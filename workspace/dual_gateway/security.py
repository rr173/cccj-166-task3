"""密码学与摘要工具（全部使用标准库）。

* 指令参数采用确定性规范化 JSON 计算 SHA-256 摘要：创建时冻结，
  确认时第二角色必须复核摘要，防止"创建的指令"与"看到的指令"被调包；
* 设备通道使用 HMAC-SHA256 对请求体做签名（共享密钥预置）；
* 带外确认码仅在创建响应中返回一次明文，库存的是其哈希值；
* 审计事件链：event_hash_n = SHA256(prev_hash || canonical(payload))。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(obj: Any) -> str:
    """键排序、无多余空白、不转义非 ASCII 的确定性 JSON。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_payload(payload: dict) -> str:
    """计算冻结负载摘要（设备集合 + 参数 + 时间窗口）。"""
    frozen = {
        "devices": sorted(payload.get("devices", [])),
        "params": payload.get("params", {}),
        "valid_from": payload.get("valid_from"),
        "valid_to": payload.get("valid_to"),
        "action": payload.get("action", ""),
    }
    return sha256_hex(canonical_json(frozen))


def new_confirm_code() -> str:
    """6 位带外确认码（安全通道在创建指令后通过独立手段告知第二角色）。"""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_confirm_code(code: str) -> str:
    # 加服务侧盐，避免码空间小被反查
    return sha256_hex("gw-confirm-code/v1:" + code)


def new_session_id() -> str:
    return secrets.token_urlsafe(24)


def new_boot_code() -> str:
    """设备启动代号：设备每次冷启动生成的随机高熵代号。"""
    return "BOOT-" + secrets.token_hex(10).upper()


def hmac_sign(key: str, message: bytes) -> str:
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_hmac(key: str, message: bytes, signature: str) -> bool:
    return hmac.compare_digest(hmac_sign(key, message), signature or "")


# ---------------------------------------------------------------------------
# 现场执行账簿（device ledger）密码学
#
# 账簿是设备侧“执行事实”的权威来源，必须自带独立于传输层的签名与链式结构：
#
#   anchor = SHA256(canonical{device, boot_code, first_seq})   每个代次一条链
#   entry_hash_n = SHA256(canonical{条目内容, prev})
#   prev_1 = anchor, prev_n = entry_hash_{n-1}                账簿连续性
#   ledger_sig = HMAC_SHA256(device_key, "gw-ledger/v1"‖canonical(entries))
#
# 网关重连收到账簿后独立重算：签名不符 → 整册隔离，不得补记任何事实；
# 序号不严格 +1（编号缺口/复用）、prev 断链（连续性破坏）→ 隔离该条目及其后
# 同代次条目；指令指纹（创建时冻结的 SHA-256 摘要）不符 → 隔离矛盾记录。
# ---------------------------------------------------------------------------
LEDGER_DOMAIN = "gw-ledger/v1"


def ledger_anchor(device_id: str, boot_code: str, first_seq: int) -> str:
    return sha256_hex(canonical_json({
        "kind": "ledger-anchor/v1", "device_id": device_id,
        "boot_code": boot_code, "first_seq": first_seq}))


def ledger_entry_hash(device_id: str, entry: dict) -> str:
    """对账簿条目内容（含 prev 指针）取摘要；下一序条目的 prev 必须等于它。"""
    return sha256_hex(canonical_json({
        "kind": "ledger-entry/v1", "device_id": device_id,
        "boot_code": entry.get("boot_code", ""), "seq": entry.get("seq"),
        "command_id": entry.get("command_id", ""),
        "result": entry.get("result", ""),
        "digest": entry.get("digest", ""),
        "message": entry.get("message", ""),
        "prev": entry.get("prev", "")}))


def ledger_book_hash(entries: list[dict]) -> str:
    """整册内容指纹：重复上送同一册内容据此识别（幂等）。"""
    return sha256_hex(canonical_json(entries))


def ledger_sign(key: str, entries: list[dict]) -> str:
    msg = (LEDGER_DOMAIN + canonical_json(entries)).encode("utf-8")
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def ledger_signature_valid(key: str, entries: list[dict], signature: str) -> bool:
    return hmac.compare_digest(ledger_sign(key, entries), signature or "")


def event_hash(prev_hash: str, event_type: str, payload: dict) -> str:
    body = canonical_json({"prev": prev_hash, "type": event_type, "payload": payload})
    return sha256_hex(body)


def event_full_record_hash(event: dict) -> str:
    """事件**全字段**记录摘要：把 ts/actor/channel/action/command_id/device_id/
    payload/prev_hash/hash 全部绑定。

    运行时哈希链 event_hash 只覆盖 (prev,action,payload)；封存用本摘要补齐对
    actor/时间/通道等列的覆盖，使离线改任何一列都能被封存核验发现。封存构建、
    包内自洽与前序历史重放三处共用同一规范化结构。
    """
    return sha256_hex(canonical_json({
        "kind": "seal-event-record/v1",
        "id": event["id"], "ts": event["ts"], "actor": event["actor"],
        "channel": event["channel"], "action": event["action"],
        "command_id": event.get("command_id"), "device_id": event.get("device_id"),
        "payload": event["payload"], "prev_hash": event["prev_hash"],
        "hash": event["hash"]}))


# ---------------------------------------------------------------------------
# 审计封存包（seal package）密码学
#
# 封存包由安全角色按事件区间（事件 id 区间）申请，内容自证且可离线核验：
#
#   proof_n = SHA256(canonical{event_id, prev_hash, action, payload_hash,
#                              position, prev_proof})
#
# 每个事件的证明同时绑定事件自身字段、在区间内的位置与上一条证明，形成独立于
# 数据库的“区间内证据链”；区间锚点绑定首尾事件 id/哈希、前序链头与末尾摘要，
# 整包再用封存密钥 HMAC 签名。核验时无需任何在线服务与数据库写权限：
# 仅读包 + 只读打开数据库即可定位首个断点并区分三类结果。
# ---------------------------------------------------------------------------
SEAL_DOMAIN = "gw-audit-seal/v1"

SEAL_GENESIS_PROOF = "0" * 64


def event_payload_hash(action: str, payload: Any) -> str:
    """单条事件负载（动作 + canonical 负载）的摘要，用于逐事件证明。"""
    return sha256_hex(canonical_json({"action": action, "payload": payload}))


def seal_event_proof(position: int, event_id: int, record_hash: str,
                     payload_hash: str, prev_proof: str) -> str:
    return sha256_hex(canonical_json({
        "kind": "seal-event-proof/v1", "position": position,
        "event_id": event_id, "record_hash": record_hash,
        "payload_hash": payload_hash, "prev_proof": prev_proof}))


def seal_anchor(*, seal_id: str, created_by: str, from_id: int, to_id: int,
                first_hash: str, last_hash: str, prior_head: str,
                last_summary: str, count: int, proofs_head: str,
                sealed_at: float) -> str:
    """区间锚点：绑定区间首尾、前序链头、末尾摘要、事件数与逐事件证明链尾。"""
    return sha256_hex(canonical_json({
        "kind": "seal-anchor/v1", "seal_id": seal_id, "created_by": created_by,
        "from_id": from_id, "to_id": to_id, "first_hash": first_hash,
        "last_hash": last_hash, "prior_head": prior_head,
        "last_summary": last_summary, "count": count,
        "proofs_head": proofs_head, "sealed_at": sealed_at}))


def seal_manifest_hash(manifest: dict) -> str:
    """清单（不含 proofs/package_sig）指纹。"""
    return sha256_hex(canonical_json(manifest))


def seal_sign(seal_key: str, manifest: dict, proofs: list[dict]) -> str:
    msg = (SEAL_DOMAIN + canonical_json({"manifest": manifest,
                                         "proofs": proofs})).encode("utf-8")
    return hmac.new(seal_key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def seal_signature_valid(seal_key: str, manifest: dict, proofs: list[dict],
                         signature: str) -> bool:
    return hmac.compare_digest(seal_sign(seal_key, manifest, proofs),
                               signature or "")
