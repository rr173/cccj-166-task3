"""独立离线核验命令：不依赖网关进程，直接读取封存包文件与数据库文件。

用法::

    python3 -m dual_gateway.seal_verify <封存包.json> --db <gateway.db> [--json]

核验逻辑与网关在线核验共用 ``dual_gateway.seal.verify_package``，结论一致：
定位首个断点（first_break.event_id），并区分——

* ``PACKAGE_CORRUPT``        包内损坏；
* ``PRIOR_HISTORY_MISMATCH`` 前序历史不匹配（历史被改动/整库被换）；
* ``DB_LAGGING``             数据库落后于封存（区间内记录被删/库被回滚）；
* ``DB_DIVERGED``            数据库内容与封存不符（区间内记录被离线修改）。

数据库以只读模式打开，本命令不写入任何数据。
退出码：0 核验通过；1 核验失败；2 用法错误。
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys

from . import seal


def _load_db_rows(db_path: str, from_id: int, to_id: int):
    """只读取出核验所需事件行；库不可读时按空库处理（fail-closed）。"""
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            prior = [dict(r) for r in conn.execute(
                "SELECT * FROM events WHERE id<? ORDER BY id", (from_id,))]
            range_rows = {r["id"]: dict(r) for r in conn.execute(
                "SELECT * FROM events WHERE id BETWEEN ? AND ? ORDER BY id",
                (from_id, to_id))}
            max_id = conn.execute(
                "SELECT MAX(id) m FROM events").fetchone()["m"] or 0
        finally:
            conn.close()
        return prior, range_rows, max_id, None
    except sqlite3.Error as exc:
        # 数据库文件缺失/损坏/无 events 表：无法证明覆盖封存区间，
        # 按空库继续核验（结论会是 DB_LAGGING），并附上原因
        return [], {}, 0, str(exc)


def verify_file(package_path: str, db_path: str) -> dict:
    """核验一个封存包文件与一个数据库文件，返回结构化结论。"""
    try:
        pkg = seal.read_package(package_path)
    except Exception as exc:
        return {"ok": False, "verdict": seal.PACKAGE_CORRUPT,
                "verdict_label": seal.VERDICT_LABELS[seal.PACKAGE_CORRUPT],
                "first_break": {"event_id": None,
                                "reason": f"封存包不可读取/解析: {exc}"},
                "checked": {"package_events": 0, "prior_events": 0,
                            "db_events_compared": 0}}
    from_id, to_id = pkg.get("from_id"), pkg.get("to_id")
    db_err = None
    if (isinstance(from_id, int) and isinstance(to_id, int)
            and 1 <= from_id <= to_id):
        prior, range_rows, max_id, db_err = _load_db_rows(db_path, from_id, to_id)
    else:
        prior, range_rows, max_id = [], {}, 0
    result = seal.verify_package(pkg, prior_rows=prior, range_rows=range_rows,
                                 db_max_id=max_id)
    if db_err:
        result["db_error"] = db_err
    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python3 -m dual_gateway.seal_verify",
        description="审计封存包独立离线核验：定位首个断点，区分包内损坏 / "
                    "前序历史不匹配 / 数据库落后于封存 / 库内容与封存不符")
    ap.add_argument("package", help="封存包 JSON 文件路径")
    ap.add_argument("--db", required=True, help="网关 SQLite 数据库文件路径")
    ap.add_argument("--json", action="store_true", help="仅输出 JSON 结论")
    args = ap.parse_args(argv)

    result = verify_file(args.package, args.db)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not args.json:
        if result["ok"]:
            print(f"\n✅ 核验通过：封存区间 [{result['from_id']}, "
                  f"{result['to_id']}]，末尾摘要 {result['end_hash'][:16]}…，"
                  f"包摘要 {result['package_hash'][:16]}…")
        else:
            fb = result.get("first_break") or {}
            print(f"\n❌ 核验失败【{result.get('verdict_label')}】"
                  f"首个断点事件号={fb.get('event_id')}：{fb.get('reason')}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
