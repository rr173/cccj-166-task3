"""审计封存包的构建与离线核验（不依赖网关在线服务）。

封存包是一个自描述、自证的 JSON 文件::

    {
      "manifest": {版本/封存 id/申请人/区间 [from_id,to_id]/前序链头 prior_head/
                   首尾事件哈希/末尾摘要/事件数/证明链头/区间锚点/封存时间},
      "events":  [区间内事件的完整全字段记录],
      "proofs":  [逐事件证明，独立于数据库的区间内证据链],
      "manifest_hash", "package_sig"
    }

核验分两级：

1. **包内自洽（PACKAGE_CORRUPT）**：签名、清单哈希、逐事件证明、区间锚点、
   首尾哈希、前序链头、事件原有哈希链——全部只依赖包本身重算，离线可判定；
2. **与数据库比对**（只读打开 DB）：
   * 前序历史不匹配（HISTORY_MISMATCH）——封存点之前的链对不上，
     典型为换入另一份历史；
   * 数据库落后于封存（DB_BEHIND）——区间记录缺失/回滚，断点在封存点之后。

任一级都报告**首个断点**的位置（位置/事件 id），顺序固定为
签名 → 清单 → 逐事件证明 → 锚点 → 前序历史 → 数据库缺失/内容。
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from typing import Any, Optional

from .security import (GENESIS_HASH, SEAL_GENESIS_PROOF, canonical_json,
                       event_full_record_hash, event_hash, event_payload_hash,
                       seal_anchor, seal_event_proof, seal_manifest_hash,
                       seal_sign, seal_signature_valid, sha256_hex)

SEAL_VERSION = "gw-seal/v1"


class SealError(Exception):
    """封存构建/解析的可预期错误。"""


# ============================ 封存包构建 ============================
def build_seal_package(*, seal_id: str, created_by: str, from_id: int, to_id: int,
                       events: list[dict], sealed_at: float,
                       seal_key: str) -> dict:
    """根据已按 id 排序的区间事件构建不可变封存包（纯函数，不落盘）。

    ``events`` 为数据库行字典（payload 为原始 JSON 文本）。
    """
    if from_id <= 0 or to_id < from_id:
        raise SealError(f"非法事件区间: [{from_id},{to_id}]")
    if not events:
        raise SealError(f"区间 [{from_id},{to_id}] 内没有事件，无法封存")
    ids = [e["id"] for e in events]
    if ids[0] != from_id or ids[-1] != to_id or ids != sorted(ids):
        raise SealError(
            f"区间事件不连续/不匹配: 期望 {from_id}..{to_id}，实际 {ids[:1]}..{ids[-1:]}")
    if len(set(ids)) != len(ids):
        raise SealError("区间内出现重复事件 id")

    prior_head = events[0]["prev_hash"]
    first_hash = events[0]["hash"]
    last_hash = events[-1]["hash"]

    proofs = []
    prev_proof = SEAL_GENESIS_PROOF
    prev_chain = prior_head
    for position, ev in enumerate(ids, start=1):
        e = events[position - 1]
        if e["id"] != ids[position - 1]:
            raise SealError("事件顺序异常")
        # 区间内原有哈希链也在构建时复核一次（数据必须是链上一致的区间）
        expect = event_hash(prev_chain, e["action"], json.loads(e["payload"]))
        if e["prev_hash"] != prev_chain or e["hash"] != expect:
            raise SealError(f"区间事件 {e['id']} 与哈希链不一致，拒绝封存")
        rec_hash = event_full_record_hash(e)
        payload = json.loads(e["payload"])
        p_hash = event_payload_hash(e["action"], payload)
        proof_val = seal_event_proof(position, e["id"], rec_hash, p_hash, prev_proof)
        proofs.append({"position": position, "event_id": e["id"],
                       "record_hash": rec_hash, "payload_hash": p_hash,
                       "prev_proof": prev_proof, "proof": proof_val})
        prev_proof = proof_val
        prev_chain = e["hash"]

    proofs_head = prev_proof
    last_summary = _event_summary(events[-1])
    anchor = seal_anchor(
        seal_id=seal_id, created_by=created_by, from_id=from_id, to_id=to_id,
        first_hash=first_hash, last_hash=last_hash, prior_head=prior_head,
        last_summary=last_summary, count=len(events), proofs_head=proofs_head,
        sealed_at=sealed_at)

    manifest = {
        "version": SEAL_VERSION,
        "seal_id": seal_id,
        "created_by": created_by,
        "from_id": from_id,
        "to_id": to_id,
        "prior_head": prior_head,
        "first_hash": first_hash,
        "last_hash": last_hash,
        "last_summary": last_summary,
        "count": len(events),
        "proofs_head": proofs_head,
        "anchor": anchor,
        "sealed_at": sealed_at,
    }
    embedded = [_embed_event(e) for e in events]
    signature = seal_sign(seal_key, manifest, proofs)
    package = {
        "manifest": manifest,
        "events": embedded,
        "proofs": proofs,
        "manifest_hash": seal_manifest_hash(manifest),
        "package_sig": signature,
    }
    package["package_hash"] = sha256_hex(_package_bytes(package))
    return package


def _event_summary(event_row: dict) -> dict:
    """末尾摘要：末事件在链上的定位信息（动作/主体/时间/链哈希）。"""
    return {"id": event_row["id"], "ts": event_row["ts"],
            "actor": event_row["actor"], "channel": event_row["channel"],
            "action": event_row["action"], "hash": event_row["hash"],
            "prev_hash": event_row["prev_hash"]}


def _embed_event(row: dict) -> dict:
    return {"id": row["id"], "ts": row["ts"], "actor": row["actor"],
            "channel": row["channel"], "action": row["action"],
            "command_id": row.get("command_id"), "device_id": row.get("device_id"),
            "payload": row["payload"], "prev_hash": row["prev_hash"],
            "hash": row["hash"]}


def _package_bytes(package: dict) -> bytes:
    """确定性序列化（写入与验签一致）。"""
    return canonical_json({
        "manifest": package["manifest"], "events": package["events"],
        "proofs": package["proofs"], "manifest_hash": package["manifest_hash"],
        "package_sig": package["package_sig"]}).encode("utf-8")


def serialize_package(package: dict) -> bytes:
    return (json.dumps(package, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def write_package_atomic(package: dict, seal_dir: str) -> str:
    """原子落盘：同目录临时文件 + os.replace，崩溃只会留下可清理的 .tmp，
    绝不会出现半个正式封存包。"""
    os.makedirs(seal_dir, exist_ok=True)
    seal_id = package["manifest"]["seal_id"]
    final = os.path.join(seal_dir, f"{seal_id}.seal.json")
    data = serialize_package(package)
    fd, tmp = tempfile.mkstemp(prefix=f".{seal_id}.", suffix=".tmp", dir=seal_dir)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return final


# ============================ 封存包解析/自洽核验 ============================
def load_package(path: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    try:
        pkg = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SealError(f"封存包不是合法 JSON: {exc}") from exc
    if not isinstance(pkg, dict) or not all(
            k in pkg for k in ("manifest", "events", "proofs",
                               "manifest_hash", "package_sig")):
        raise SealError("封存包结构不完整")
    return pkg


def verify_package_self(package: dict, seal_key: str) -> dict:
    """只依赖包本身：签名 → 清单哈希 → 逐事件证明 → 原哈希链 → 锚点。

    返回 {"result": ..., "break_at": {...}|None, "checks": [...]}。
    一旦发现损坏立即返回（首个断点）。
    """
    checks: list[str] = []
    m = package.get("manifest")
    events = package.get("events")
    proofs = package.get("proofs")

    def corrupt(stage: str, detail: str, **where):
        return {"result": "PACKAGE_CORRUPT",
                "break_at": {"stage": stage, "detail": detail, **where},
                "checks": checks}

    if not isinstance(m, dict) or not isinstance(events, list) \
            or not isinstance(proofs, list):
        return corrupt("structure", "封存包字段缺失或类型错误")

    # 1) 整包签名（防离线后整包被替换/伪造）
    if not seal_signature_valid(seal_key, m, proofs,
                                package.get("package_sig", "")):
        return corrupt("signature", "封存包 HMAC 签名无效")
    checks.append("package_sig")

    # 1b) 整包文件指纹（若包内带有则重算核对；_package_bytes 不含该字段）
    declared_ph = package.get("package_hash")
    if declared_ph is not None and declared_ph != sha256_hex(
            _package_bytes(package)):
        return corrupt("package_hash", "整包指纹重算不通过")
    checks.append("package_hash")

    # 2) 清单哈希
    if package.get("manifest_hash") != seal_manifest_hash(m):
        return corrupt("manifest_hash", "清单被改动且与 manifest_hash 不符")
    checks.append("manifest_hash")

    from_id, to_id, count = m.get("from_id"), m.get("to_id"), m.get("count")
    prior_head, first_hash, last_hash = (m.get("prior_head"),
                                         m.get("first_hash"), m.get("last_hash"))
    # 3) 结构：数量一致、id 连续覆盖区间
    if not isinstance(from_id, int) or not isinstance(to_id, int) \
            or not isinstance(count, int) or from_id <= 0 or to_id < from_id:
        return corrupt("range", "清单区间字段非法",
                       from_id=from_id, to_id=to_id)
    if count != len(events) or count != len(proofs) or count == 0:
        return corrupt("count", f"事件/证明数量与清单不符(count={count})",
                       events=len(events), proofs=len(proofs))
    checks.append("count")

    expected_ids = list(range(from_id, to_id + 1))
    actual_ids = [e.get("id") for e in events]
    if actual_ids != expected_ids:
        gap = _first_gap(expected_ids, actual_ids)
        return corrupt("event_ids", "内嵌事件 id 与区间不连续/不匹配", **gap)
    checks.append("event_ids")

    # 4) 逐事件证明 + 5) 原事件哈希链（同一遍扫描，按位置报告首个断点）
    prev_proof = SEAL_GENESIS_PROOF
    prev_chain = prior_head
    for position, (e, p) in enumerate(zip(events, proofs), start=1):
        if not isinstance(e, dict) or not isinstance(p, dict):
            return corrupt("event_record", "事件/证明记录非法",
                           position=position, event_id=expected_ids[position - 1])
        if p.get("position") != position or p.get("event_id") != e.get("id"):
            return corrupt("proof_position", "证明位置/事件 id 绑定错误",
                           position=position, event_id=e.get("id"))
        if p.get("prev_proof") != prev_proof:
            return corrupt("proof_chain", "逐事件证明链断裂(prev_proof)",
                           position=position, event_id=e["id"])
        try:
            payload = json.loads(e.get("payload"))
        except Exception:
            return corrupt("payload", "事件 payload 不是合法 JSON",
                           position=position, event_id=e["id"])
        rec_hash = event_full_record_hash(e)
        p_hash = event_payload_hash(e["action"], payload)
        if p.get("record_hash") != rec_hash:
            return corrupt("record_hash", "事件全字段记录与证明不符（事件内容被篡改）",
                           position=position, event_id=e["id"])
        if p.get("payload_hash") != p_hash:
            return corrupt("payload_hash", "事件负载摘要与证明不符",
                           position=position, event_id=e["id"])
        expect_proof = seal_event_proof(position, e["id"], rec_hash, p_hash,
                                        prev_proof)
        if p.get("proof") != expect_proof:
            return corrupt("proof", "逐事件证明重算不通过",
                           position=position, event_id=e["id"])
        expect_chain = event_hash(prev_chain, e["action"], payload)
        if e.get("prev_hash") != prev_chain:
            return corrupt("chain_prev", "区间内事件 prev_hash 断链",
                           position=position, event_id=e["id"])
        if e.get("hash") != expect_chain:
            return corrupt("chain_hash", "区间内事件哈希重算不通过",
                           position=position, event_id=e["id"])
        prev_proof = p["proof"]
        prev_chain = e["hash"]
    checks.append("proofs_and_chain")

    # 6) 首尾 / 前序链头 / 证明链尾 / 锚点
    if events[0]["hash"] != first_hash:
        return corrupt("first_hash", "清单首事件哈希与内嵌记录不符",
                       event_id=from_id)
    if events[-1]["hash"] != last_hash:
        return corrupt("last_hash", "清单尾事件哈希与内嵌记录不符",
                       event_id=to_id)
    if events[0]["prev_hash"] != prior_head:
        return corrupt("prior_head", "首事件 prev_hash 与清单 prior_head 不符",
                       event_id=from_id)
    expect_anchor = seal_anchor(
        seal_id=m["seal_id"], created_by=m["created_by"],
        from_id=from_id, to_id=to_id, first_hash=first_hash,
        last_hash=last_hash, prior_head=prior_head,
        last_summary=m.get("last_summary"), count=count,
        proofs_head=prev_proof, sealed_at=m.get("sealed_at"))
    if m.get("anchor") != expect_anchor:
        return corrupt("anchor", "区间锚点重算不通过（首尾/前序链头/末尾摘要被改）")
    checks.append("anchor")
    if m.get("last_summary", {}).get("hash") != last_hash:
        return corrupt("last_summary", "末尾摘要与尾事件哈希不符",
                       event_id=to_id)
    checks.append("self_consistent")
    return {"result": "OK", "break_at": None, "checks": checks,
            "head": prev_chain}


def _first_gap(expected: list[int], actual: list) -> dict:
    """定位首个缺失/错位的事件 id（实际集合相对期望序列）。"""
    actual_set = {a for a in actual if isinstance(a, int)}
    for want in expected:
        if want not in actual_set:
            return {"position": want - expected[0] + 1, "event_id": want,
                    "detail_missing_id": want}
    return {"position": 1, "event_id": expected[0]}


# ============================ 与数据库离线比对 ============================
def verify_offline(package_path: str, db_path: str, seal_key: str) -> dict:
    """独立离线核验：读封存包 + 只读打开数据库，定位首个断点并分类。

    结果分类：
      OK               包自洽，且数据库区间及前序历史与封存完全一致；
      PACKAGE_CORRUPT  包本身损坏（签名/证明/锚点/链），无需查库即可定罪；
      HISTORY_MISMATCH 前序历史不匹配：封存点之前的链头与包中 prior_head 不同，
                       或区间首条之前的事件被换成另一份历史；
      DB_BEHIND        数据库落后于封存：区间内事件缺失（删除中间记录/回滚），
                       或同 id 记录内容与封存不符且其前缀也已对不上。
    """
    pkg = load_package(package_path)
    self_result = verify_package_self(pkg, seal_key)
    if self_result["result"] != "OK":
        return {**self_result, "seal_id": pkg["manifest"].get("seal_id"),
                "package_path": package_path, "db_path": db_path}

    m = pkg["manifest"]
    if not os.path.exists(db_path):
        return {"result": "DB_BEHIND",
                "break_at": {"stage": "db_missing",
                             "detail": "数据库文件不存在，无法达到封存点",
                             "event_id": m["from_id"]},
                "seal_id": m["seal_id"], "checks": self_result["checks"],
                "package_path": package_path, "db_path": db_path}

    conn = sqlite3.connect(f"file:{os.path.abspath(db_path)}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return compare_package_against_connection(
            pkg, conn, self_result, package_path=package_path, db_path=db_path)
    finally:
        conn.close()


def compare_package_against_connection(pkg: dict, conn, self_result: dict, *,
                                       package_path: str = "",
                                       db_path: str = "") -> dict:
    """对已打开（只读）数据库连接做比对。包必须已通过自洽核验。

    供在线核验（内存库/同一进程）与离线 CLI（只读文件库）共用同一份判定逻辑。
    """
    m = pkg["manifest"]
    from_id, to_id = m["from_id"], m["to_id"]

    # —— 第一断点优先级：前序历史。从创世重放封存点之前的整条前缀——
    # 只比对 prior_head 无法发现“改了内容但没动 hash 列”或“换入一条内部自洽
    # 的另一份历史”，因此逐条核对 prev 指针并重算哈希，且前缀链尾必须等于
    # 清单中的 prior_head。前缀首个断点即在此报告，判为前序历史不匹配。
    head = _replay_prefix(conn, from_id - 1)
    if head["result"] != "OK":
        return _verdict("HISTORY_MISMATCH", head["stage"], head["detail"],
                        m, self_result, package_path, db_path,
                        event_id=head.get("event_id"),
                        **{k: v for k, v in head.items()
                           if k in ("expected", "actual", "field")})
    if head["hash"] != m["prior_head"]:
        return _verdict("HISTORY_MISMATCH", "prior_head",
                        f"前序链尾与封存不符：封存点之前已换入另一份历史 "
                        f"(event {from_id - 1})",
                        m, self_result, package_path, db_path,
                        event_id=from_id - 1,
                        expected=m["prior_head"], actual=head["hash"])

    # —— 区间逐条比对：缺失即 DB 落后；内容不符（含链指针/哈希）也判落后 ——
    prev_chain = m["prior_head"]
    embedded = {e["id"]: e for e in pkg["events"]}
    for eid in range(from_id, to_id + 1):
        row = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
        if row is None:
            return _verdict("DB_BEHIND", "event_missing",
                            f"数据库缺少封存区间内事件 {eid}"
                            f"（删除中间记录或回滚到封存点之前）",
                            m, self_result, package_path, db_path,
                            position=eid - from_id + 1, event_id=eid)
        d = dict(row)
        sealed = embedded[eid]
        position = eid - from_id + 1
        mismatch_field = _compare_event(d, sealed, expected_prev=prev_chain)
        if mismatch_field:
            # 前缀（含 prior_head）已全部吻合，区间内同 id 记录被离线删改/换链：
            # 数据库未能保持封存点之后的状态，判为落后于封存。
            return _verdict("DB_BEHIND", "event_content",
                            f"事件 {eid} 字段 {mismatch_field} 与封存不符",
                            m, self_result, package_path, db_path,
                            position=position, event_id=eid,
                            field=mismatch_field)
        prev_chain = d["hash"]

    return {"result": "OK", "break_at": None, "seal_id": m["seal_id"],
            "from_id": from_id, "to_id": to_id, "count": m["count"],
            "head": prev_chain, "checks": self_result["checks"] + ["db_match"],
            "package_path": package_path, "db_path": db_path,
            "sealed_at": m["sealed_at"]}


def _replay_prefix(conn, upto_id: int) -> dict:
    """从创世重放事件 1..upto_id 的前缀，逐条核对链指针并重算哈希。

    返回 {"result":"OK","hash":链尾}，或首个断点
    {"result":"BAD","stage","detail","event_id",...}。upto_id<=0 表示空前缀，
    链尾为创世哈希。
    """
    import json as _json
    prev = GENESIS_HASH
    if upto_id <= 0:
        return {"result": "OK", "hash": prev}
    rows = conn.execute(
        "SELECT * FROM events WHERE id<=? ORDER BY id", (upto_id,)).fetchall()
    expected_id = 1
    for r in rows:
        d = dict(r)
        if d["id"] != expected_id:
            return {"result": "BAD", "stage": "prior_event_missing",
                    "detail": f"前序历史在事件 {expected_id} 处缺失（记录被删除）",
                    "event_id": expected_id}
        if d["prev_hash"] != prev:
            return {"result": "BAD", "stage": "prior_chain_prev",
                    "detail": f"前序历史在事件 {d['id']} 处 prev_hash 不接",
                    "event_id": d["id"], "expected": prev,
                    "actual": d["prev_hash"]}
        try:
            payload = _json.loads(d["payload"])
        except Exception:
            return {"result": "BAD", "stage": "prior_payload",
                    "detail": f"前序事件 {d['id']} payload 非法",
                    "event_id": d["id"], "field": "payload"}
        expect_hash = event_hash(prev, d["action"], payload)
        if d["hash"] != expect_hash:
            return {"result": "BAD", "stage": "prior_hash",
                    "detail": f"前序事件 {d['id']} 内容与哈希不符（历史被改写）",
                    "event_id": d["id"], "expected": expect_hash,
                    "actual": d["hash"], "field": "hash"}
        # 全字段自洽：actor/ts/channel 等列若被离线改动而未重算链哈希，
        # 用全字段记录摘要即可发现（封存逐事件证明绑定同一摘要）。
        if d.get("full_record_hash"):
            if d["full_record_hash"] != event_full_record_hash(d):
                return {"result": "BAD", "stage": "prior_record",
                        "detail": f"前序事件 {d['id']} 全字段记录被改写",
                        "event_id": d["id"], "field": "full_record_hash"}
        prev = d["hash"]
        expected_id += 1
    if expected_id <= upto_id:
        return {"result": "BAD", "stage": "prior_event_missing",
                "detail": f"前序历史在事件 {expected_id} 处缺失（记录被删除）",
                "event_id": expected_id}
    return {"result": "OK", "hash": prev}


def _compare_event(db_row: dict, sealed: dict,
                   expected_prev: Optional[str] = None) -> Optional[str]:
    """返回首个不一致字段名；一致返回 None。payload 按 canonical 比较。

    expected_prev 非空时还校验该事件的 prev_hash 必须接上封存链。
    """
    if expected_prev is not None and db_row.get("prev_hash") != expected_prev:
        return "prev_hash"
    for key in ("ts", "actor", "channel", "action", "command_id", "device_id",
                "prev_hash", "hash"):
        if db_row.get(key) != sealed.get(key):
            return key
    try:
        if canonical_json(json.loads(db_row["payload"])) != \
                canonical_json(json.loads(sealed["payload"])):
            return "payload"
    except Exception:
        return "payload"
    return None


def _verdict(result: str, stage: str, detail: str, manifest: dict,
             self_result: dict, package_path: str, db_path: str,
             **where) -> dict:
    return {"result": result,
            "break_at": {"stage": stage, "detail": detail, **where},
            "seal_id": manifest["seal_id"], "from_id": manifest["from_id"],
            "to_id": manifest["to_id"], "checks": self_result["checks"],
            "package_path": package_path, "db_path": db_path}
