"""设备通道 HTTP API（8082，下现场控制网）。

认证：每台设备预置共享密钥，请求头带：

* X-Device-Id
* X-Signature: hex(HMAC_SHA256(key, raw_body))

所有现场状态只能通过这条通道上送；回执必须携带 boot_code + 严格递增 seq，
旧启动代号 / 乱序 / 跳号 / 重复伪造一律拒绝并进入 rejected_receipts 审计。
"""
from __future__ import annotations

from .errors import Forbidden, Unauthorized
from .http_common import make_handler
from .security import verify_hmac

ROUTES: list = []


def route(path: str, method: str = "POST"):
    def deco(fn):
        ROUTES.append((path, method, fn))
        return fn
    return deco


def _authenticate(h) -> str:
    device_id = h.headers.get("X-Device-Id", "")
    sig = h.headers.get("X-Signature", "")
    dev = h.ctx.svc.db.get_device(device_id)
    if not dev:
        raise Unauthorized("设备未注册")
    # 必须对原始字节验签，防止 JSON 重排/注入
    raw = h._body()
    h._cached_body = raw
    if not verify_hmac(dev["preshared_key"], raw, sig):
        raise Forbidden("设备签名无效")
    return device_id


def _json(h) -> dict:
    import json
    raw = getattr(h, "_cached_body", None)
    if raw is None:
        raw = h._body()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


@route("/api/device/hello", "POST")
def hello(h):
    device_id = _authenticate(h)
    body = _json(h)
    out = h.ctx.svc.hello(
        device_id=device_id,
        boot_code=body.get("boot_code", ""),
        first_seq=int(body.get("first_seq", 1)),
        ledger=body.get("ledger") or [],
        ledger_sig=body.get("ledger_sig"))
    h.send_json(out)


@route("/api/device/heartbeat", "POST")
def heartbeat(h):
    device_id = _authenticate(h)
    body = _json(h)
    h.send_json(h.ctx.svc.heartbeat(device_id, body.get("boot_code", "")))


@route("/api/device/pull", "POST")
def pull(h):
    device_id = _authenticate(h)
    body = _json(h)
    h.send_json(h.ctx.svc.pull(device_id, body.get("boot_code", "")))


@route("/api/device/receipt", "POST")
def receipt(h):
    device_id = _authenticate(h)
    body = _json(h)
    out = h.ctx.svc.receipt(
        device_id=device_id,
        boot_code=body.get("boot_code", ""),
        seq=body.get("seq"),
        command_id=body.get("command_id", ""),
        result=body.get("result", ""),
        message=body.get("message", ""))
    h.send_json(out)


@route("/healthz", "GET")
def health(h):
    h.send_json({"channel": "device", "ok": True})


def build_handler(ctx):
    return make_handler(ctx, ROUTES)
