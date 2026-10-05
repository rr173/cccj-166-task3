"""业务通道 HTTP API（8080）。

仅接受持独立业务令牌的请求，提供指令创建、查询、列表、撤销。
业务通道不提供任何“确认”能力——创建与确认在凭据与网络上彻底分离。
"""
from __future__ import annotations

from .errors import Forbidden, Unauthorized
from .http_common import make_handler

ROUTES: list = []


def route(path: str, method: str = "POST"):
    def deco(fn):
        ROUTES.append((path, method, fn))
        return fn
    return deco


def _token(h) -> str:
    expect = h.ctx.cfg.biz_token
    got = h.headers.get("X-Biz-Token") or ""
    if not got:
        raise Unauthorized("缺少 X-Biz-Token")
    import hmac
    if not hmac.compare_digest(got, expect):
        raise Forbidden("业务令牌无效")
    return got


@route("/api/commands", "POST")
def create(h):
    _token(h)
    body = h.read_json()
    out = h.ctx.svc.create_command(
        actor=body.get("created_by", "biz-system"),
        action=body.get("action", ""),
        devices=body.get("devices", []),
        params=body.get("params", {}),
        valid_seconds=body.get("valid_seconds"))
    # confirm_code 仅此一次返回，之后任何接口都无法再读到
    h.send_json(out, 201)


@route("/api/commands", "GET")
def list_cmds(h):
    _token(h)
    q = h.query()
    h.send_json({"commands": h.ctx.svc.list_commands(
        status=q.get("status"), limit=int(q.get("limit", 100)))})


@route("/api/commands/*", "GET")
def detail(h):
    _token(h)
    cid = h.raw_path.rsplit("/", 1)[-1]
    h.send_json(h.ctx.svc.get_command(cid))


@route("/api/commands/*/revoke", "POST")
def revoke(h):
    _token(h)
    cid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.revoke_command(
        actor=body.get("actor", "biz-system"),
        command_id=cid, reason=body.get("reason", "")))


@route("/healthz", "GET")
def health(h):
    h.send_json({"channel": "business", "ok": True})


def build_handler(ctx):
    return make_handler(ctx, ROUTES)
