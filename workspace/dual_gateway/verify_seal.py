"""独立离线核验命令。

无需启动网关、不写数据库（以只读模式打开），仅凭封存包 + 数据库文件即可
定位首个断点，并把结论分为：

  OK                包自洽且与数据库一致
  PACKAGE_CORRUPT   包内损坏（签名/清单/逐事件证明/原哈希链/锚点）
  HISTORY_MISMATCH  前序历史不匹配（封存点之前换入另一份历史）
  DB_BEHIND         数据库落后于封存（区间记录被删/回滚/改写）

用法::

    python3 -m dual_gateway.verify_seal <package.seal.json> <gateway.db> \
        [--seal-key KEY] [--json]

    # 只做包内自洽核验（无数据库，离线取证机场景）
    python3 -m dual_gateway.verify_seal <package.seal.json> --self-only

退出码：0=OK，2=PACKAGE_CORRUPT，3=HISTORY_MISMATCH，4=DB_BEHIND，1=用法/IO 错误。
"""
from __future__ import annotations

import argparse
import json
import sys

from . import sealing
from .config import load_config

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_PACKAGE_CORRUPT = 2
EXIT_HISTORY_MISMATCH = 3
EXIT_DB_BEHIND = 4

_RESULT_EXIT = {
    "OK": EXIT_OK,
    "PACKAGE_CORRUPT": EXIT_PACKAGE_CORRUPT,
    "HISTORY_MISMATCH": EXIT_HISTORY_MISMATCH,
    "DB_BEHIND": EXIT_DB_BEHIND,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m dual_gateway.verify_seal",
        description="审计封存包离线核验（只读，不写数据库）")
    parser.add_argument("package", help="封存包文件路径（*.seal.json）")
    parser.add_argument("db", nargs="?", help="网关 SQLite 数据库文件路径")
    parser.add_argument("--seal-key", default=None,
                        help="封存签名密钥（默认取 GW_SEAL_KEY 或内置演示值）")
    parser.add_argument("--self-only", action="store_true",
                        help="只做包内自洽核验，不比对数据库")
    parser.add_argument("--json", action="store_true", help="只输出 JSON 结果")
    args = parser.parse_args(argv)

    seal_key = args.seal_key or load_config().seal_key

    try:
        if args.self_only or not args.db:
            pkg = sealing.load_package(args.package)
            result = sealing.verify_package_self(pkg, seal_key)
            result = {**result, "seal_id": pkg["manifest"].get("seal_id"),
                      "package_path": args.package}
            if not args.self_only and not args.db:
                # 未给数据库且未显式 --self-only：提示仅完成了自洽核验
                result["note"] = "未提供数据库路径，仅完成包内自洽核验"
        else:
            result = sealing.verify_offline(args.package, args.db, seal_key)
    except sealing.SealError as exc:
        result = {"result": "PACKAGE_CORRUPT",
                  "break_at": {"stage": "parse", "detail": str(exc)},
                  "package_path": args.package}
    except FileNotFoundError as exc:
        print(f"错误: 文件不存在: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_human(result)
    return _RESULT_EXIT.get(result["result"], EXIT_USAGE)


def _print_human(result: dict):
    verdict = result["result"]
    seal_id = result.get("seal_id") or "—"
    print(f"封存包 : {result.get('package_path')}")
    print(f"封存ID : {seal_id}")
    if result.get("db_path"):
        print(f"数据库 : {result['db_path']}")
    if verdict == "OK":
        print("结论   : ✅ OK — 封存包自洽，与数据库完全一致")
        print(f"区间   : 事件 {result.get('from_id')}..{result.get('to_id')}"
              f"（{result.get('count')} 条）")
        print(f"链头   : {result.get('head')}")
        return
    b = result.get("break_at") or {}
    if verdict == "PACKAGE_CORRUPT":
        print("结论   : ❌ PACKAGE_CORRUPT — 包内损坏")
    elif verdict == "HISTORY_MISMATCH":
        print("结论   : ⚠ HISTORY_MISMATCH — 前序历史不匹配（疑似换入另一份历史）")
    elif verdict == "DB_BEHIND":
        print("结论   : ⤓ DB_BEHIND — 数据库落后于封存（记录缺失/被删/回滚）")
    pos = b.get("position")
    eid = b.get("event_id")
    if pos is not None or eid is not None:
        print(f"首个断点: 位置 {pos} / 事件 id {eid}")
    print(f"阶段   : {b.get('stage')}")
    print(f"详情   : {b.get('detail')}")
    for k in ("expected", "actual", "field"):
        if k in b:
            print(f"  {k}: {b[k]}")


if __name__ == "__main__":
    raise SystemExit(main())
