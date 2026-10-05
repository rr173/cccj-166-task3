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
