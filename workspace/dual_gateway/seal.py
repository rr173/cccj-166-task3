"""审计封存包：构建、原子写盘与独立核验。

本模块同时被网关服务（在线生成/核验）与离线核验命令
（``python3 -m dual_gateway.seal_verify``）使用，保证两处判定逻辑完全一致。

封存包内容（JSON 文件，落盘后不可变）：

* ``from_id`` / ``to_id``  —— 封存区间首尾事件号（含两端）；
* ``prev_hash``            —— 前序链头：区间前一条事件的哈希（起点为 1 时是创世哈希）；
* ``end_hash``             —— 末尾摘要：区间最后一条事件的哈希；
* ``events``               —— 逐事件证明：区间内每条事件的完整内容与链式哈希；
* ``package_hash``         —— 对上述全部内容的整体摘要，任何字段被改动都会失配。

核验结论（verdict）共五类，前三种为需求明确区分的类别：

* ``OK``                     核验通过；
* ``PACKAGE_CORRUPT``        包内损坏：包自身哈希链/摘要/逐事件证明不自洽；
* ``PRIOR_HISTORY_MISMATCH`` 前序历史不匹配：数据库中区间前的链被改动或整库被换；
* ``DB_LAGGING``             数据库落后于封存：区间内事件缺失（中间记录被删/库被回滚）；
* ``DB_DIVERGED``            数据库内容与封存不符：区间内同号事件被离线修改。

任何失败结论都携带 ``first_break``（首个断点的事件号与原因）。
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from .security import GENESIS_HASH, canonical_json, event_hash, sha256_hex

PACKAGE_KIND = "gw-audit-seal/v1"

# 核验结论
OK = "OK"
PACKAGE_CORRUPT = "PACKAGE_CORRUPT"
PRIOR_HISTORY_MISMATCH = "PRIOR_HISTORY_MISMATCH"
DB_LAGGING = "DB_LAGGING"
DB_DIVERGED = "DB_DIVERGED"

VERDICT_LABELS = {
    OK: "核验通过",
    PACKAGE_CORRUPT: "包内损坏",
    PRIOR_HISTORY_MISMATCH: "前序历史不匹配",
    DB_LAGGING: "数据库落后于封存",
    DB_DIVERGED: "数据库内容与封存不符",
}


# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------
def package_hash(pkg: dict) -> str:
    """封存包整体摘要：覆盖除 package_hash 自身外的全部字段。"""
    body = {k: v for k, v in pkg.items() if k != "package_hash"}
    return sha256_hex(canonical_json(body))


def build_package(seal_id: str, created_by: str, created_at: float,
                  rows: list[dict]) -> dict:
    """由有序事件行构建封存包。调用方保证 rows 连续且链式有效。"""
    if not rows:
        raise ValueError("封存区间为空")
    events = []
    for r in rows:
        payload = r["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        events.append({
            "id": r["id"], "ts": r["ts"], "actor": r["actor"],
            "channel": r["channel"], "action": r["action"],
            "command_id": r["command_id"], "device_id": r["device_id"],
            "payload": payload,
            "prev_hash": r["prev_hash"], "hash": r["hash"],
        })
    pkg = {
        "kind": PACKAGE_KIND,
        "seal_id": seal_id,
        "created_by": created_by,
        "created_at": created_at,
        "from_id": events[0]["id"],
        "to_id": events[-1]["id"],
        "event_count": len(events),
        "prev_hash": events[0]["prev_hash"],
        "end_hash": events[-1]["hash"],
        "events": events,
    }
    pkg["package_hash"] = package_hash(pkg)
    return pkg


# ---------------------------------------------------------------------------
# 落盘（写临时文件 + fsync + 原子改名；崩溃只会留下 .tmp 或完整包，无半成品）
# ---------------------------------------------------------------------------
def package_path(seal_dir: str, seal_id: str) -> str:
    return os.path.join(seal_dir, f"{seal_id}.json")


def write_package_atomic(seal_dir: str, seal_id: str, pkg: dict) -> str:
    os.makedirs(seal_dir, exist_ok=True)
    final = package_path(seal_dir, seal_id)
    tmp = final + ".tmp"
    data = json.dumps(pkg, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, final)
    try:
        dfd = os.open(seal_dir, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass
    return final


def read_package(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        pkg = json.load(f)
    if not isinstance(pkg, dict):
        raise ValueError("封存包不是 JSON 对象")
    return pkg


def remove_if_exists(path: Optional[str]) -> bool:
    if path and os.path.exists(path):
        os.remove(path)
        return True
    return False


# ---------------------------------------------------------------------------
# 独立核验（纯函数：不依赖网关进程，只依赖包内容与数据库事件行）
# ---------------------------------------------------------------------------
def _fail(verdict: str, event_id: Optional[int], reason: str,
          checked: dict, pkg: Optional[dict] = None) -> dict:
    out = {
        "ok": False,
        "verdict": verdict,
        "verdict_label": VERDICT_LABELS[verdict],
        "first_break": {"event_id": event_id, "reason": reason},
        "checked": checked,
    }
    if isinstance(pkg, dict):
        out["seal_id"] = pkg.get("seal_id")
        out["from_id"] = pkg.get("from_id")
        out["to_id"] = pkg.get("to_id")
        out["package_hash"] = pkg.get("package_hash")
    return out


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def verify_package(pkg: Any, *, prior_rows: list[dict],
                   range_rows: dict[int, dict], db_max_id: int) -> dict:
    """核验封存包与数据库当前内容。

    参数：
        pkg:        解析后的封存包（字典）；
        prior_rows: 数据库中 id < from_id 的全部事件（按 id 升序）；
        range_rows: 数据库中区间内事件，{id: row}；
        db_max_id:  数据库 events 表当前最大 id（空表为 0）。

    检查顺序即“首个断点”的定位顺序：先证包自身可信，再锚定前序历史，
    然后确认数据库覆盖封存区间，最后逐事件比对内容。
    """
    checked = {"package_events": 0, "prior_events": 0, "db_events_compared": 0}

    # ---- 1. 包内校验：结构 → 逐事件证明 → 末尾摘要 → 整体摘要 ----
    if not isinstance(pkg, dict) or pkg.get("kind") != PACKAGE_KIND:
        return _fail(PACKAGE_CORRUPT, None, "封存包格式非法（kind 不符）", checked, pkg)
    from_id, to_id = pkg.get("from_id"), pkg.get("to_id")
    events = pkg.get("events")
    prev_hash = pkg.get("prev_hash")
    end_hash = pkg.get("end_hash")
    stored_hash = pkg.get("package_hash")
    if (not _is_int(from_id) or not _is_int(to_id)
            or not isinstance(prev_hash, str) or not isinstance(end_hash, str)
            or not isinstance(stored_hash, str) or not isinstance(events, list)):
        return _fail(PACKAGE_CORRUPT, None, "封存包缺少必要字段或字段类型非法",
                     checked, pkg)
    if from_id < 1 or to_id < from_id:
        return _fail(PACKAGE_CORRUPT, None, "封存区间非法", checked, pkg)
    if len(events) != to_id - from_id + 1:
        return _fail(PACKAGE_CORRUPT, None,
                     f"逐事件证明数量({len(events)})与区间跨度"
                     f"({to_id - from_id + 1})不符", checked, pkg)
    if pkg.get("event_count") != len(events):
        return _fail(PACKAGE_CORRUPT, None, "event_count 与逐事件证明数量不符",
                     checked, pkg)
    if from_id == 1 and prev_hash != GENESIS_HASH:
        return _fail(PACKAGE_CORRUPT, None,
                     "区间自创世事件起，但前序链头不是创世哈希", checked, pkg)

    expect_prev = prev_hash
    for i, e in enumerate(events):
        eid = from_id + i
        checked["package_events"] += 1
        if not isinstance(e, dict) or e.get("id") != eid:
            return _fail(PACKAGE_CORRUPT, eid,
                         "逐事件证明序号不连续或缺失", checked, pkg)
        if e.get("prev_hash") != expect_prev:
            return _fail(PACKAGE_CORRUPT, eid,
                         "包内链式指针断裂（prev_hash 不接上一条）", checked, pkg)
        if event_hash(str(e.get("prev_hash")), str(e.get("action")),
                      e.get("payload")) != e.get("hash"):
            return _fail(PACKAGE_CORRUPT, eid,
                         "事件哈希与其内容不符（包内记录被改动）", checked, pkg)
        expect_prev = e["hash"]
    if expect_prev != end_hash:
        return _fail(PACKAGE_CORRUPT, to_id,
                     "末尾摘要与逐事件证明推算结果不符", checked, pkg)
    if package_hash(pkg) != stored_hash:
        return _fail(PACKAGE_CORRUPT, None,
                     "封存包整体摘要(package_hash)不符（包元数据被改动）", checked, pkg)

    # ---- 2. 前序历史：数据库中区间之前的链必须完好且链头与封存一致 ----
    if db_max_id < from_id - 1:
        return _fail(DB_LAGGING, db_max_id + 1,
                     "数据库事件不足，连封存区间起点之前的历史都未覆盖"
                     "（记录被删除或库被回滚）", checked, pkg)
    prev = GENESIS_HASH
    expect_id = 1
    for r in prior_rows:
        if r["id"] != expect_id:
            return _fail(PRIOR_HISTORY_MISMATCH, expect_id,
                         "前序历史事件缺失/不连续（区间前的记录被删除）",
                         checked, pkg)
        payload = r["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if r["prev_hash"] != prev or event_hash(prev, r["action"], payload) != r["hash"]:
            return _fail(PRIOR_HISTORY_MISMATCH, r["id"],
                         "前序历史哈希链在该事件处断裂（区间前的记录被改动）",
                         checked, pkg)
        prev = r["hash"]
        expect_id += 1
        checked["prior_events"] += 1
    if expect_id != from_id:
        return _fail(PRIOR_HISTORY_MISMATCH, expect_id,
                     "前序历史在封存起点前被截断", checked, pkg)
    if prev != prev_hash:
        return _fail(PRIOR_HISTORY_MISMATCH, from_id - 1,
                     "前序链头与封存记录不符（历史被改动或整库被换成另一份历史）",
                     checked, pkg)

    # ---- 3. 覆盖性：数据库必须完整覆盖封存区间，否则即落后于封存 ----
    first_missing = next((i for i in range(from_id, to_id + 1)
                          if i not in range_rows), None)
    if db_max_id < to_id or first_missing is not None:
        missing = first_missing if first_missing is not None else db_max_id + 1
        return _fail(DB_LAGGING, missing,
                     "封存区间内事件在数据库中缺失（中间记录被删除或库被回滚，"
                     "数据库落后于封存）", checked, pkg)

    # ---- 4. 逐事件比对：数据库内容必须与封存证明完全一致 ----
    for i, e in enumerate(events):
        eid = from_id + i
        row = range_rows[eid]
        checked["db_events_compared"] += 1
        if row["hash"] != e["hash"] or row["prev_hash"] != e["prev_hash"]:
            return _fail(DB_DIVERGED, eid,
                         "数据库事件哈希与封存证明不符（该记录被离线修改）",
                         checked, pkg)
        payload = row["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if (row["action"] != e["action"]
                or canonical_json(payload) != canonical_json(e["payload"])
                or row["ts"] != e["ts"] or row["actor"] != e["actor"]
                or row["channel"] != e["channel"]
                or (row["command_id"] or None) != (e.get("command_id") or None)
                or (row["device_id"] or None) != (e.get("device_id") or None)):
            return _fail(DB_DIVERGED, eid,
                         "数据库事件字段与封存证明不符（该记录被离线修改）",
                         checked, pkg)

    return {
        "ok": True,
        "verdict": OK,
        "verdict_label": VERDICT_LABELS[OK],
        "first_break": None,
        "checked": checked,
        "seal_id": pkg.get("seal_id"),
        "from_id": from_id,
        "to_id": to_id,
        "end_hash": end_hash,
        "package_hash": stored_hash,
    }
