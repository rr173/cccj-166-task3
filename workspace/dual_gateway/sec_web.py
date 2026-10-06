"""安全通道：第二角色确认工作台 + 设备回执审计（8081）。

与业务通道完全隔离：独立端口、独立用户库（supervisor 可批准/拒绝，
safety 只读审计）、浏览器会话 Cookie（HttpOnly）。

确认动作强制"双证据"：
  1) 通过带外手段（电话/短信/硬令牌）收到的 6 位确认码；
  2) 页面展示创建时冻结的 SHA-256 摘要，第二角色核对后勾选/回填摘要。
"""
from __future__ import annotations

import html
import time

from .errors import Forbidden, Unauthorized
from .http_common import make_handler

ROUTES: list = []
COOKIE = "GWSEC_SESSION"


def route(path: str, method: str = "GET"):
    def deco(fn):
        ROUTES.append((path, method, fn))
        return fn
    return deco


def _check_login(h) -> dict:
    return h.require_session()


def _require_role(h, role: str) -> dict:
    s = _check_login(h)
    if role == "supervisor" and s["user"] != "supervisor":
        raise Forbidden("仅 supervisor 可执行确认/拒绝（职责分离）")
    return s


def _set_cookie(h, sid: str):
    h.send_header_add = None
    return f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/"


_PAGE = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{title} - 安全确认工作台</title><style>
body{{font-family:-apple-system,Segoe UI,Roboto,'Helvetica Neue',sans-serif;margin:0;background:#0f1420;color:#e6e9ef}}
header{{background:#172033;padding:12px 24px;border-bottom:1px solid #24304a;display:flex;gap:18px;align-items:center}}
header a{{color:#9db4d8;text-decoration:none;font-size:14px}} header b{{color:#fff}}
main{{padding:24px;max-width:1080px;margin:0 auto}}
.card{{background:#161d2e;border:1px solid #25314c;border-radius:10px;padding:18px;margin-bottom:16px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border-bottom:1px solid #25314c;padding:7px 9px;text-align:left;vertical-align:top}}
th{{color:#8fa3c6;font-weight:600}} code,.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
.digest{{word-break:break-all;color:#7fd1b9;background:#10231f;padding:6px 8px;border-radius:6px;display:inline-block}}
.tag{{padding:1px 8px;border-radius:10px;font-size:12px}}
.PENDING{{background:#3a3210;color:#ffd76b}} .CONFIRMED{{background:#10304a;color:#7fc4ff}}
.EXECUTED{{background:#103a20;color:#7ff0ac}} .FAILED,.PARTIAL_FAILED{{background:#3d1620;color:#ff8ea3}}
.EXPIRED,.REVOKED,.REJECTED,.CLOSED{{background:#333845;color:#aab2c5}}
.DISPATCHED{{background:#10304a;color:#7fc4ff}} .DOUBT{{background:#4a2c10;color:#ffbd7f}}
.MISSED,.SKIPPED{{background:#2a2f3c;color:#9aa3b5}}
.OPEN{{background:#4a2c10;color:#ffbd7f}} .RECOVERED{{background:#103a20;color:#7ff0ac}}
.REDELIVERED{{background:#10304a;color:#7fc4ff}} .EXPIRED{{background:#333845;color:#aab2c5}}
.SEALING{{background:#10304a;color:#7fc4ff}} .SEALED{{background:#103a20;color:#7ff0ac}}
.VERIFY_FAILED{{background:#3d1620;color:#ff8ea3}} .CANCELLED{{background:#2a2f3c;color:#9aa3b5}}
.qreason{{background:#3d1620;color:#ff8ea3;padding:1px 8px;border-radius:10px;font-size:12px}}
input,textarea,select{{background:#0f1626;border:1px solid #31405f;color:#e6e9ef;border-radius:6px;padding:8px;margin:4px 0;width:320px}}
button{{background:#2f6df6;color:#fff;border:0;border-radius:6px;padding:9px 18px;cursor:pointer;margin-right:8px}}
button.danger{{background:#c0394f}} button.gray{{background:#3a4358}}
.flash{{background:#3d1620;color:#ffb3c0;padding:9px 14px;border-radius:8px;margin-bottom:14px}}
.ok{{background:#103a20;color:#7ff0ac}} .muted{{color:#8593ad;font-size:12px}}
</style></head><body><header>
<b>🛡 安全确认工作台</b>
<a href="/workbench">待确认/在途指令</a><a href="/incidents">事故对账工单</a>
<a href="/quarantine">账簿隔离区</a>
<a href="/audit">审计事件链</a>
<a href="/seals">审计封存</a>
<a href="/receipts">回执审计</a><a href="/devices">设备状态</a>
<span style="flex:1"></span><span class="muted">{user}</span>
<a href="/logout">登出</a></header><main>{flash}{body}</main></body></html>"""


def _page(h, title: str, body: str, flash: str = "", status: int = 200):
    s = h.ctx.sessions.get(h._session_cookie())
    user = s["user"] if s else "未登录"
    flash_html = f'<div class="flash {flash[1]}">{flash[0]}</div>' if flash else ""
    h.send_html(_PAGE.format(title=html.escape(title), body=body,
                             user=html.escape(user), flash=flash_html), status)


# ---------------- 登录 ----------------
@route("/login", "GET")
def login_form(h):
    if h.ctx.sessions.get(h._session_cookie()):
        return h.redirect("/workbench")
    body = """<div class="card"><h3>第二角色登录（独立安全通道）</h3>
    <form method="post" action="/login">
      <p><input name="username" placeholder="用户名 (supervisor / safety)" autocomplete="username"></p>
      <p><input name="password" type="password" placeholder="口令" autocomplete="current-password"></p>
      <button type="submit">登录</button>
    </form><p class="muted">supervisor=确认/拒绝；safety=只读审计</p></div>"""
    h.send_html(_PAGE.format(title="登录", body=body, user="未登录", flash=""))


@route("/login", "POST")
def login(h):
    from urllib.parse import parse_qs
    form = parse_qs(h._body().decode("utf-8"))
    u = (form.get("username") or [""])[0].strip()
    pw = (form.get("password") or [""])[0]
    import hmac as _hmac
    expect = h.ctx.cfg.sec_users.get(u)
    if expect is None or not _hmac.compare_digest(pw, expect):
        body = '<div class="flash">用户名或口令错误</div>' + \
            '<p><a href="/login">返回</a></p>'
        return h.send_html(_PAGE.format(title="登录失败", body=body, user="未登录", flash=""), 401)
    sid = h.ctx.sessions.create(u)
    h.send_response(302)
    h.send_header("Location", "/workbench")
    h.send_header("Set-Cookie", f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/")
    h.send_header("Content-Length", "0")
    h.end_headers()


@route("/logout", "GET")
def logout(h):
    sid = h._session_cookie()
    if sid:
        h.ctx.sessions.drop(sid)
    h.send_response(302)
    h.send_header("Location", "/login")
    h.send_header("Set-Cookie", f"{COOKIE}=; Max-Age=0; Path=/")
    h.send_header("Content-Length", "0")
    h.end_headers()


@route("/", "GET")
def root(h):
    h.redirect("/workbench" if h.ctx.sessions.get(h._session_cookie()) else "/login")


# ---------------- 工作台 ----------------
@route("/workbench", "GET")
def workbench(h):
    _check_login(h)
    cmds = h.ctx.svc.list_commands(limit=100)
    rows = []
    for c in cmds:
        tag = f'<span class="tag {c["status"]}">{c["status"]}</span>'
        rows.append(
            f'<tr><td class="mono"><a href="/commands/{c["command_id"]}" style="color:#9db4d8">'
            f'{c["command_id"]}</a></td><td>{html.escape(c["action"])}</td>'
            f'<td>{len(c["devices"])} 台</td><td>{tag}</td>'
            f'<td class="mono">{c["digest"][:16]}…</td>'
            f'<td class="muted">{_ts(c["created_at"])}</td></tr>')
    body = f"""<div class="card"><h3>指令列表</h3>
    <table><tr><th>指令</th><th>动作</th><th>设备</th><th>状态</th><th>冻结摘要</th><th>创建时间</th></tr>
    {''.join(rows) or '<tr><td colspan=6 class=muted>暂无指令</td></tr>'}</table></div>"""
    _page(h, "工作台", body)


@route("/commands/*", "GET")
def cmd_detail(h):
    s = _check_login(h)
    cid = h.raw_path.rsplit("/", 1)[-1]
    c = h.ctx.svc.get_command(cid)
    tgt_rows = []
    for t in c["targets"]:
        rec = ""
        if t["receipt"]:
            r = t["receipt"]
            rec = (f'回执: <b>{r["result"]}</b> <span class="muted">代号 {r["boot_code"]} '
                   f'#{r["seq"]} / 来源 {r["source"]}</span>')
        tgt_rows.append(
            f'<tr><td class="mono">{t["device_id"]}</td>'
            f'<td><span class="tag {t["status"]}">{t["status"]}</span></td>'
            f'<td>{rec}</td></tr>')

    action_box = ""
    if c["status"] == "PENDING":
        if s["user"] == "supervisor":
            action_box = f"""
            <div class="card"><h3>⚠ 高风险指令确认</h3>
            <p class="muted">请通过独立带外通道获取 6 位确认码，并与送审来源核对以下冻结摘要：</p>
            <form method="post" action="/commands/{cid}/confirm">
              <p>带外确认码 <input name="confirm_code" inputmode="numeric" maxlength="6" required></p>
              <p>冻结摘要复核（完整复制后提交）<br>
              <span class="digest mono">{c["digest"]}</span><br>
              <input name="digest_ack" value="{c["digest"]}" class="mono" style="width:640px"></p>
              <button type="submit">✅ 确认下发</button>
            </form>
            <form method="post" action="/commands/{cid}/reject" style="margin-top:10px">
              <input name="reason" placeholder="拒绝原因" style="width:420px">
              <button class="danger" type="submit">⛔ 拒绝</button>
            </form></div>"""
        else:
            action_box = '<div class="card muted">只读账号：仅 supervisor 可确认/拒绝</div>'

    body = f"""<div class="card">
      <h3>{html.escape(c["action"])} <span class="tag {c["status"]}">{c["status"]}</span></h3>
      <table>
      <tr><th>指令 ID</th><td class="mono">{c["command_id"]}</td></tr>
      <tr><th>冻结设备集合</th><td class="mono">{html.escape(", ".join(c["devices"]))}</td></tr>
      <tr><th>冻结参数</th><td class="mono">{html.escape(str(c["params"]))}</td></tr>
      <tr><th>冻结摘要 SHA-256</th><td><span class="digest mono">{c["digest"]}</span></td></tr>
      <tr><th>有效窗口</th><td class="mono">{_ts(c["valid_from"])} → {_ts(c["valid_to"])}</td></tr>
      <tr><th>确认截止</th><td class="mono">{_ts(c["confirm_deadline"])}</td></tr>
      <tr><th>创建人 / 确认人</th><td>{html.escape(c["created_by"])} / {html.escape(str(c["confirmed_by"]))}</td></tr>
      </table></div>
      {action_box}
      <div class="card"><h3>设备执行情况</h3>
      <table><tr><th>设备</th><th>目标状态</th><th>执行事实</th></tr>{''.join(tgt_rows)}</table></div>"""
    _page(h, cid, body)


@route("/commands/*/confirm", "POST")
def web_confirm(h):
    from urllib.parse import parse_qs
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[2]
    form = parse_qs(h._body().decode("utf-8"))
    try:
        h.ctx.svc.confirm_command(
            actor=s["user"], command_id=cid,
            code=(form.get("confirm_code") or [""])[0],
            digest_ack=(form.get("digest_ack") or [""])[0])
        h.redirect(f"/commands/{cid}")
    except Exception as exc:
        _page(h, cid, f'<div class="flash">{html.escape(str(exc))}</div>'
                      f'<p><a href="/commands/{cid}">返回指令</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/commands/*/reject", "POST")
def web_reject(h):
    from urllib.parse import parse_qs
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[2]
    form = parse_qs(h._body().decode("utf-8"))
    h.ctx.svc.reject_command(
        actor=s["user"], command_id=cid,
        reason=(form.get("reason") or [""])[0])
    h.redirect(f"/commands/{cid}")


# ---------------- 事故恢复对账工单 ----------------
@route("/incidents", "GET")
def incidents_page(h):
    _check_login(h)
    q = h.query()
    status = q.get("status") or "OPEN"
    incs = h.ctx.svc.list_incidents(status=None if status == "ALL" else status)
    n_open = len(h.ctx.svc.list_incidents(status="OPEN"))
    rows = []
    for i in incs:
        rows.append(
            f'<tr><td class="mono"><a href="/incidents/{i["incident_id"]}" '
            f'style="color:#9db4d8">{i["incident_id"]}</a></td>'
            f'<td class="mono">{i["command_id"]}</td><td>{i["device_id"]}</td>'
            f'<td>{html.escape(i.get("action") or "—")}</td>'
            f'<td><span class="tag {i["status"]}">{i["status"]}</span></td>'
            f'<td><span class="tag {i.get("target_status") or ""}">'
            f'{i.get("target_status") or "—"}</span></td>'
            f'<td>{i["open_reason"]}</td>'
            f'<td class="muted">{_ts(i["opened_at"])}</td></tr>')
    tabs = "".join(
        f'<a href="/incidents?status={s}" style="margin-right:12px">'
        f'<b>{s}</b></a>' for s in ("OPEN", "RECOVERED", "REDELIVERED",
                                    "EXPIRED", "ALL"))
    body = f"""<div class="card"><h3>事故恢复对账工单（仅安全通道可见）
    <span class="tag OPEN">未结 {n_open}</span></h3>
    <p class="muted">{tabs}</p>
    <table><tr><th>工单</th><th>指令</th><th>设备</th><th>动作</th>
    <th>工单状态</th><th>目标状态</th><th>打开原因</th><th>打开时间</th></tr>
    {''.join(rows) or '<tr><td colspan=8 class=muted>暂无工单</td></tr>'}
    </table></div>"""
    _page(h, "事故对账工单", body)


@route("/incidents/*", "GET")
def incident_detail_page(h):
    s = _check_login(h)
    iid = h.raw_path.rsplit("/", 1)[-1]
    i = h.ctx.svc.incident_detail(iid)
    c = i["command"]
    t = i["target"]
    rec = ""
    if t.get("receipt"):
        r = t["receipt"]
        rec = (f'<b>{r["result"]}</b> <span class="muted">代号 {r["boot_code"]} '
               f'#{r["seq"]} / 来源 {r["source"]}</span>')

    hist_rows = []
    for ev in i["history"]:
        hist_rows.append(
            f'<tr><td class="mono">{_ts(ev["ts"])}</td><td>{html.escape(ev["actor"])}'
            f'</td><td><b>{ev["kind"]}</b></td>'
            f'<td class="mono">{html.escape(str(ev["detail"]))[:400]}</td></tr>')

    q_rows = []
    for q in i["quarantine"]:
        q_rows.append(
            f'<tr><td><span class="qreason">{q["reason"]}</span></td>'
            f'<td>{q.get("boot_code") or "—"}</td><td>{q.get("seq") if q.get("seq") is not None else "—"}</td>'
            f'<td class="mono">{html.escape(str(q["entry"]))[:300]}</td></tr>')

    action_box = ""
    if i["status"] == "OPEN" and s["user"] == "supervisor":
        if t["status"] == "DOUBT" and i["window_open"]:
            action_box = f"""
            <div class="card"><h3>人工处置（不会覆盖任何执行事实）</h3>
            <form method="post" action="/incidents/{iid}/redeliver"
                  onsubmit="return confirm('确认设备确定未执行且已更换启动代号？重投可能双触发。')">
              <input name="reason" placeholder="重新派发依据（带外核实说明）" style="width:420px">
              <button type="submit">↻ 确认未执行且时限有效，重新派发</button>
            </form>
            <p class="muted">仅当设备已换代号（确定重启过）、窗口仍有效且无执行证据时允许。</p>
            </div>"""
        elif t["status"] == "DOUBT" and not i["window_open"]:
            action_box = f"""
            <div class="card"><h3>人工处置（不会覆盖任何执行事实）</h3>
            <form method="post" action="/incidents/{iid}/close"
                  onsubmit="return confirm('窗口已关闭，按未达 MISSED 关闭工单？不产生执行事实。')">
              <input name="reason" placeholder="关闭依据（始终无法取得账簿证据）" style="width:420px">
              <button class="gray" type="submit">🔒 窗口已过且无证据，按未达关闭</button>
            </form></div>"""
        else:
            action_box = '<div class="card muted">目标当前不处于 DOUBT，暂无可处置动作</div>'
        action_box += f"""
        <div class="card"><h3>添加处置备注</h3>
        <form method="post" action="/incidents/{iid}/note">
          <input name="note" placeholder="备注（留痕，不改状态）" style="width:520px">
          <button class="gray" type="submit">追加备注</button>
        </form></div>"""
    elif i["status"] == "OPEN":
        action_box = '<div class="card muted">只读账号：仅 supervisor 可处置</div>'

    body = f"""<div class="card">
      <h3>对账工单 {i["incident_id"]}
      <span class="tag {i["status"]}">{i["status"]}</span></h3>
      <table>
      <tr><th>指令 / 动作</th><td class="mono">{i["command_id"]} / {html.escape(c["action"] if c else "—")}</td></tr>
      <tr><th>现场设备</th><td>{i["device_id"]}（投递代次 <span class="mono">{i["dispatched_boot"]}</span>）</td></tr>
      <tr><th>打开原因 / 时间</th><td>{i["open_reason"]} / {_ts(i["opened_at"])}</td></tr>
      <tr><th>冻结指令指纹</th><td><span class="digest mono">{c["digest"] if c else "—"}</span></td></tr>
      <tr><th>目标状态</th><td><span class="tag {t["status"]}">{t["status"]}</span> {rec}</td></tr>
      <tr><th>有效窗口</th><td class="mono">{_ts(c["valid_from"] if c else None)} → {_ts(c["valid_to"] if c else None)}
      （{'仍有效' if i["window_open"] else '已过期'}）</td></tr>
      <tr><th>结论</th><td>{html.escape(str(i.get("resolution")))} / {_ts(i.get("resolved_at"))}</td></tr>
      </table></div>
      {action_box}
      <div class="card"><h3>证据 / 冲突 / 处置历史（只追加）</h3>
      <table><tr><th>时间</th><th>主体</th><th>事件</th><th>内容</th></tr>
      {''.join(hist_rows) or '<tr><td colspan=4 class=muted>暂无</td></tr>'}</table></div>
      <div class="card"><h3>隔离留痕（编号缺口/矛盾/过期/旧代次/坏签名）</h3>
      <table><tr><th>原因</th><th>代次</th><th>序号</th><th>原始材料</th></tr>
      {''.join(q_rows) or '<tr><td colspan=4 class=muted>无隔离材料</td></tr>'}</table></div>"""
    _page(h, iid, body)


def _incident_form(h):
    from urllib.parse import parse_qs
    form = parse_qs(h._body().decode("utf-8"))
    return (form.get("reason") or [""])[0], (form.get("note") or [""])[0]


@route("/incidents/*/redeliver", "POST")
def web_incident_redeliver(h):
    s = _require_role(h, "supervisor")
    iid = h.raw_path.split("/")[2]
    reason, _ = _incident_form(h)
    try:
        h.ctx.svc.incident_redeliver(s["user"], iid, reason)
        h.redirect(f"/incidents/{iid}")
    except Exception as exc:
        _page(h, iid, f'<div class="flash">{html.escape(str(exc))}</div>'
                      f'<p><a href="/incidents/{iid}">返回工单</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/incidents/*/close", "POST")
def web_incident_close(h):
    s = _require_role(h, "supervisor")
    iid = h.raw_path.split("/")[2]
    reason, _ = _incident_form(h)
    try:
        h.ctx.svc.incident_close_unverified(s["user"], iid, reason)
        h.redirect(f"/incidents/{iid}")
    except Exception as exc:
        _page(h, iid, f'<div class="flash">{html.escape(str(exc))}</div>'
                      f'<p><a href="/incidents/{iid}">返回工单</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/incidents/*/note", "POST")
def web_incident_note(h):
    s = _require_role(h, "supervisor")
    iid = h.raw_path.split("/")[2]
    _, note = _incident_form(h)
    try:
        h.ctx.svc.incident_note(s["user"], iid, note)
        h.redirect(f"/incidents/{iid}")
    except Exception as exc:
        _page(h, iid, f'<div class="flash">{html.escape(str(exc))}</div>'
                      f'<p><a href="/incidents/{iid}">返回工单</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/quarantine", "GET")
def quarantine_page(h):
    _check_login(h)
    rows = []
    for q in h.ctx.svc.list_quarantine():
        rows.append(
            f'<tr><td>{q["id"]}</td><td>{q["device_id"]}</td>'
            f'<td><span class="qreason">{q["reason"]}</span></td>'
            f'<td class="mono">{q.get("boot_code") or "—"}</td>'
            f'<td>{q.get("seq") if q.get("seq") is not None else "—"}</td>'
            f'<td class="mono">{q.get("command_id") or "—"}</td>'
            f'<td class="mono">{html.escape(str(q["entry"]))[:260]}</td>'
            f'<td class="muted">{_ts(q["received_at"])}</td></tr>')
    body = """<div class="card"><h3>账簿隔离区（只留痕，绝不据此改状态/造事实）</h3>
    <table><tr><th>#</th><th>设备</th><th>原因</th><th>代次</th><th>序号</th>
    <th>指令</th><th>原始材料</th><th>时间</th></tr>
    """ + "".join(rows) + "</table></div>"
    _page(h, "账簿隔离区", body)


# ---------------- 审计 ----------------
@route("/audit", "GET")
def audit_page(h):
    _check_login(h)
    events = h.ctx.svc.audit_events(limit=100)
    chain = h.ctx.svc.verify_audit_chain()
    rows = []
    for e in reversed(events):
        rows.append(
            f'<tr><td>{e["id"]}</td><td class="mono">{_ts(e["ts"])}</td>'
            f'<td>{e["channel"]}</td><td>{html.escape(e["actor"])}</td>'
            f'<td><b>{e["action"]}</b></td>'
            f'<td class="mono" style="max-width:420px;overflow:hidden;text-overflow:ellipsis">'
            f'{html.escape(e["payload"][:200] if isinstance(e["payload"], str) else str(e["payload"])[:200])}</td>'
            f'<td class="mono" title="{e["hash"]}">{e["hash"][:10]}…</td></tr>')
    chain_badge = ('<span class="flash ok">✅ 哈希链校验通过：'
                   f'{chain["events"]} 个事件，链尾 {chain["head"][:16]}…</span>'
                   if chain["ok"] else
                   f'<span class="flash">❌ 哈希链断裂于事件 {chain["broken_at"]}：'
                   f'{chain["reason"]}</span>')
    body = f"""{chain_badge}<div class="card"><h3>审计事件（append-only 哈希链）</h3>
    <table><tr><th>#</th><th>时间</th><th>通道</th><th>主体</th><th>动作</th><th>内容</th><th>哈希</th></tr>
    {''.join(rows)}</table></div>
    <form method="post" action="/audit/verify"><button class="gray">重新校验哈希链</button></form>"""
    _page(h, "审计", body)


@route("/audit/verify", "POST")
def audit_verify(h):
    _check_login(h)
    h.redirect("/audit")


# ---------------- 审计封存（不可变封存包 + 离线核验） ----------------
_SEAL_STATUS_LABEL = {
    "PENDING": "待处理", "SEALING": "生成中", "SEALED": "已封存",
    "VERIFY_FAILED": "核验失败", "CANCELLED": "已撤销",
}


def _seal_tag(status: str) -> str:
    return (f'<span class="tag {status}">'
            f'{_SEAL_STATUS_LABEL.get(status, status)}</span>')


@route("/seals", "GET")
def seals_page(h):
    s = _check_login(h)
    q = h.query()
    status = q.get("status") or "ALL"
    seals = h.ctx.svc.list_seals(status=None if status == "ALL" else status)
    max_id = h.ctx.svc.db.max_event_id() or 0
    rows = []
    for r in seals:
        verify = "—"
        if r["last_verify_at"]:
            verify = (f'<span class="tag {"SEALED" if r["last_verify_ok"] else "VERIFY_FAILED"}">'
                      f'{"通过" if r["last_verify_ok"] else "失败"}</span> '
                      f'<span class="muted">{_ts(r["last_verify_at"])}</span>')
        rows.append(
            f'<tr><td class="mono"><a href="/seals/{r["seal_id"]}" '
            f'style="color:#9db4d8">{r["seal_id"]}</a></td>'
            f'<td class="mono">#{r["from_id"]} → #{r["to_id"]}</td>'
            f'<td>{_seal_tag(r["status"])}</td>'
            f'<td>{r["event_count"] if r["event_count"] is not None else "—"}</td>'
            f'<td class="mono" title="{r.get("end_hash") or ""}">'
            f'{(r.get("end_hash") or "—")[:12]}{"…" if r.get("end_hash") else ""}</td>'
            f'<td>{html.escape(r["requested_by"])}</td>'
            f'<td class="muted">{_ts(r["requested_at"])}</td>'
            f'<td>{verify}</td></tr>')
    tabs = " ".join(
        f'<a href="/seals?status={k}" style="margin-right:12px">'
        f'{"<b>" if status == k else ""}{v}{"</b>" if status == k else ""}</a>'
        for k, v in [("PENDING", "待处理"), ("SEALING", "生成中"),
                     ("SEALED", "已封存"), ("VERIFY_FAILED", "核验失败"),
                     ("CANCELLED", "已撤销"), ("ALL", "全部")])
    new_form = ""
    if s["user"] == "supervisor":
        new_form = f"""<div class="card"><h3>新封存申请</h3>
        <p class="muted">对审计事件链的区间 [from, to] 生成不可变封存包
        （当前已固化事件：1 … {max_id}）。同一区间只产生一份封存结果，重复申请返回原结果。</p>
        <form method="post" action="/seals">
          起始事件号 <input name="from_id" inputmode="numeric" style="width:120px" required>
          末尾事件号 <input name="to_id" inputmode="numeric" style="width:120px" required>
          <button type="submit">登记封存申请</button>
        </form></div>"""
    body = f"""{new_form}
    <div class="card"><h3>审计封存记录</h3>
    <p class="muted">{tabs}</p>
    <table><tr><th>封存号</th><th>区间</th><th>状态</th><th>事件数</th>
    <th>末尾摘要</th><th>申请人</th><th>申请时间</th><th>最近核验</th></tr>
    {''.join(rows) or '<tr><td colspan=8 class=muted>暂无封存记录</td></tr>'}
    </table></div>"""
    _page(h, "审计封存", body)


@route("/seals", "POST")
def seal_create(h):
    from urllib.parse import parse_qs
    s = _require_role(h, "supervisor")
    form = parse_qs(h._body().decode("utf-8"))
    try:
        out = h.ctx.svc.request_seal(
            actor=s["user"],
            from_id=(form.get("from_id") or [""])[0],
            to_id=(form.get("to_id") or [""])[0])
        h.redirect(f"/seals/{out['seal']['seal_id']}")
    except Exception as exc:
        _page(h, "审计封存", f'<div class="flash">{html.escape(str(exc))}</div>'
                             f'<p><a href="/seals">返回封存列表</a></p>',
              status=getattr(exc, "http_status", 400))


@route("/seals/*/package.json", "GET")
def seal_package_download(h):
    _check_login(h)
    seal_id = h.raw_path.split("/")[2]
    pkg = h.ctx.svc.read_seal_package(seal_id)
    h.send_json(pkg, extra_headers={
        "Content-Disposition": f'attachment; filename="{seal_id}.json"'})


@route("/seals/*", "GET")
def seal_detail_page(h):
    s = _check_login(h)
    seal_id = h.raw_path.rsplit("/", 1)[-1]
    r = h.ctx.svc.seal_detail(seal_id)

    hist_rows = []
    for ev in r["history"]:
        hist_rows.append(
            f'<tr><td class="mono">{_ts(ev["ts"])}</td>'
            f'<td>{html.escape(ev["actor"])}</td><td><b>{ev["kind"]}</b></td>'
            f'<td class="mono">{html.escape(str(ev["detail"]))[:400]}</td></tr>')

    pkg_rows = []
    pkg = r.get("package")
    if pkg:
        for e in pkg.get("events", [])[:200]:
            pkg_rows.append(
                f'<tr><td>{e["id"]}</td><td>{html.escape(str(e["action"]))}</td>'
                f'<td>{html.escape(str(e["actor"]))}</td>'
                f'<td class="mono" title="{e["hash"]}">{e["hash"][:12]}…</td></tr>')

    action_box = ""
    if s["user"] == "supervisor":
        if r["status"] == "PENDING":
            action_box = f"""
            <div class="card"><h3>处置</h3>
            <form method="post" action="/seals/{seal_id}/generate" style="display:inline">
              <button type="submit">📦 生成封存包</button>
            </form>
            <form method="post" action="/seals/{seal_id}/cancel" style="display:inline"
                  onsubmit="return confirm('撤销该封存申请？仅未开始写包的申请可撤销。')">
              <input name="reason" placeholder="撤销原因" style="width:240px">
              <button class="danger" type="submit">撤销申请</button>
            </form>
            {f'<p class="muted">上次错误：{html.escape(r["last_error"] or "")}</p>' if r.get("last_error") else ""}
            </div>"""
        elif r["status"] in ("SEALED", "VERIFY_FAILED"):
            action_box = f"""
            <div class="card"><h3>处置</h3>
            <form method="post" action="/seals/{seal_id}/verify" style="display:inline">
              <button type="submit">🔍 立即核验（与离线命令同一逻辑）</button>
            </form>
            <a href="/seals/{seal_id}/package.json"><button class="gray" type="button">⬇ 下载封存包</button></a>
            <p class="muted">已封存内容不得覆盖；离线核验：
            <code>python3 -m dual_gateway.seal_verify {seal_id}.json --db &lt;gateway.db&gt;</code></p>
            </div>"""
        elif r["status"] == "SEALING":
            action_box = ('<div class="card muted">生成中：若服务重启，将自动续完同一份包'
                          '或回滚为可重试，不留半成品。</div>')
    elif r["status"] in ("PENDING", "SEALED", "VERIFY_FAILED"):
        action_box = '<div class="card muted">只读账号：仅 supervisor 可处置</div>'

    verify_info = "—"
    if r["last_verify_at"]:
        verify_info = (f'{"✅ 通过" if r["last_verify_ok"] else "❌ 失败"} '
                       f'({_ts(r["last_verify_at"])})')
    body = f"""<div class="card">
      <h3>封存申请 {r["seal_id"]} {_seal_tag(r["status"])}</h3>
      <table>
      <tr><th>封存区间</th><td class="mono">#{r["from_id"]} → #{r["to_id"]}
        （{r["event_count"] if r["event_count"] is not None else "—"} 个事件）</td></tr>
      <tr><th>前序链头 prev_hash</th><td class="mono digest">{(r.get("prev_hash") or "—")}</td></tr>
      <tr><th>末尾摘要 end_hash</th><td class="mono digest">{(r.get("end_hash") or "—")}</td></tr>
      <tr><th>包整体摘要 package_hash</th><td class="mono digest">{(r.get("package_hash") or "—")}</td></tr>
      <tr><th>申请 / 生成</th><td>{html.escape(r["requested_by"])} @ {_ts(r["requested_at"])}
        / 第 {r["attempt"]} 次尝试，{_ts(r.get("sealed_at"))} 完成</td></tr>
      <tr><th>包文件</th><td class="mono">{html.escape(r.get("package_path") or "—")}</td></tr>
      <tr><th>最近核验</th><td>{verify_info}</td></tr>
      {f'<tr><th>最近错误</th><td class="mono">{html.escape(r["last_error"])}</td></tr>' if r.get("last_error") else ""}
      </table></div>
      {action_box}
      <div class="card"><h3>处置历史（只追加）</h3>
      <table><tr><th>时间</th><th>主体</th><th>事件</th><th>内容</th></tr>
      {''.join(hist_rows) or '<tr><td colspan=4 class=muted>暂无</td></tr>'}</table></div>
      {f'''<div class="card"><h3>逐事件证明（包内 {len(pkg.get("events", []))} 条）</h3>
      <table><tr><th>#</th><th>动作</th><th>主体</th><th>哈希</th></tr>
      {''.join(pkg_rows)}</table></div>''' if pkg else ""}"""
    _page(h, seal_id, body)


def _seal_action(h, fn):
    s = _require_role(h, "supervisor")
    seal_id = h.raw_path.split("/")[2]
    from urllib.parse import parse_qs
    form = parse_qs(h._body().decode("utf-8"))
    try:
        return fn(s["user"], seal_id, form)
    except Exception as exc:
        _page(h, seal_id, f'<div class="flash">{html.escape(str(exc))}</div>'
                          f'<p><a href="/seals/{seal_id}">返回封存记录</a></p>',
              status=getattr(exc, "http_status", 400))
        return None


@route("/seals/*/generate", "POST")
def seal_generate(h):
    def _do(actor, seal_id, form):
        h.ctx.svc.generate_seal(actor, seal_id)
        h.redirect(f"/seals/{seal_id}")
    _seal_action(h, _do)


@route("/seals/*/cancel", "POST")
def seal_cancel(h):
    def _do(actor, seal_id, form):
        h.ctx.svc.cancel_seal(actor, seal_id, (form.get("reason") or [""])[0])
        h.redirect(f"/seals/{seal_id}")
    _seal_action(h, _do)


@route("/seals/*/verify", "POST")
def seal_verify(h):
    def _do(actor, seal_id, form):
        result = h.ctx.svc.verify_seal(actor, seal_id)
        if result["ok"]:
            h.redirect(f"/seals/{seal_id}")
        else:
            fb = result.get("first_break") or {}
            _page(h, seal_id,
                  f'<div class="flash">核验失败【{html.escape(result["verdict_label"])}】'
                  f'首个断点事件号={fb.get("event_id")}：'
                  f'{html.escape(str(fb.get("reason")))}</div>'
                  f'<p><a href="/seals/{seal_id}">返回封存记录</a></p>')
    _seal_action(h, _do)


@route("/receipts", "GET")
def receipts_page(h):
    _check_login(h)
    accepted = h.ctx.svc.db.list_receipts()
    rejected = h.ctx.svc.rejected_receipts()
    a_rows = [
        f'<tr><td class="mono">{r["command_id"]}</td><td>{r["device_id"]}</td>'
        f'<td>{r["boot_code"]}</td><td>{r["seq"]}</td>'
        f'<td><span class="tag {r["result"]}">{r["result"]}</span></td>'
        f'<td>{r["source"]}</td><td class="muted">{html.escape(r["message"] or "")}</td></tr>'
        for r in accepted]
    r_rows = [
        f'<tr><td>{r["device_id"]}</td><td>{r.get("boot_code") or ""}</td>'
        f'<td>{r.get("seq")}</td><td><b>{r["reason"]}</b></td>'
        f'<td class="mono">{html.escape(str(r["raw"]))[:180]}</td></tr>'
        for r in rejected]
    body = f"""<div class="card"><h3>已接受回执（执行事实，不可变）</h3>
    <table><tr><th>指令</th><th>设备</th><th>启动代号</th><th>序号</th><th>结果</th><th>来源</th><th>说明</th></tr>
    {''.join(a_rows) or '<tr><td colspan=7 class=muted>暂无</td></tr>'}</table></div>
    <div class="card"><h3>被拒绝回执（旧代号 / 乱序 / 伪造，全部留痕）</h3>
    <table><tr><th>设备</th><th>启动代号</th><th>序号</th><th>拒绝原因</th><th>原始报文</th></tr>
    {''.join(r_rows) or '<tr><td colspan=5 class=muted>暂无</td></tr>'}</table></div>"""
    _page(h, "回执审计", body)


@route("/devices", "GET")
def devices_page(h):
    _check_login(h)
    rows = []
    for d in h.ctx.svc.list_devices():
        rows.append(
            f'<tr><td class="mono">{d["device_id"]}</td>'
            f'<td><span class="tag {"CONFIRMED" if d["online"] else "MISSED"}">'
            f'{"在线" if d["online"] else "离线"}</span></td>'
            f'<td class="mono">{d.get("current_boot") or "—"}</td>'
            f'<td>{d.get("ledger_head_seq")}</td>'
            f'<td class="muted">{_ts(d["last_seen"]) if d["last_seen"] else "—"}</td></tr>')
    body = """<div class="card"><h3>现场设备</h3>
    <table><tr><th>设备</th><th>状态</th><th>当前启动代号</th><th>已连续确认序号</th><th>最近心跳</th></tr>
    """ + "".join(rows) + "</table></div>"
    _page(h, "设备", body)


# ---------------- 供自动化/审计脚本调用的 JSON 接口（同样需要会话） ----------------
@route("/api/session", "POST")
def api_login(h):
    body = h.read_json()
    import hmac as _hmac
    u = body.get("username", "")
    pw = body.get("password", "")
    expect = h.ctx.cfg.sec_users.get(u)
    if expect is None or not _hmac.compare_digest(pw, expect):
        raise Unauthorized("安全通道凭据错误")
    sid = h.ctx.sessions.create(u)
    h.send_json({"ok": True, "user": u},
                extra_headers={"Set-Cookie":
                               f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/"})


@route("/api/commands", "GET")
def api_list(h):
    _check_login(h)
    q = h.query()
    h.send_json({"commands": h.ctx.svc.list_commands(status=q.get("status"))})


@route("/api/commands/*", "GET")
def api_detail(h):
    _check_login(h)
    cid = h.raw_path.rsplit("/", 1)[-1]
    h.send_json(h.ctx.svc.get_command(cid))


@route("/api/commands/*/confirm", "POST")
def api_confirm(h):
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.confirm_command(
        actor=s["user"], command_id=cid,
        code=body.get("confirm_code", ""), digest_ack=body.get("digest_ack", "")))


@route("/api/commands/*/reject", "POST")
def api_reject(h):
    s = _require_role(h, "supervisor")
    cid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.reject_command(
        actor=s["user"], command_id=cid, reason=body.get("reason", "")))


@route("/api/audit", "GET")
def api_audit(h):
    _check_login(h)
    q = h.query()
    h.send_json({"events": h.ctx.svc.audit_events(
        limit=int(q.get("limit", 200)),
        command_id=q.get("command_id"), device_id=q.get("device_id")),
        "chain": h.ctx.svc.verify_audit_chain()})


@route("/api/rejected", "GET")
def api_rejected(h):
    _check_login(h)
    h.send_json({"rejected": h.ctx.svc.rejected_receipts()})


@route("/api/incidents", "GET")
def api_incidents(h):
    _check_login(h)
    q = h.query()
    status = q.get("status")
    h.send_json({"incidents": h.ctx.svc.list_incidents(
        status=None if status in (None, "ALL") else status)})


@route("/api/incidents/*", "GET")
def api_incident_detail(h):
    _check_login(h)
    iid = h.raw_path.rsplit("/", 1)[-1]
    h.send_json(h.ctx.svc.incident_detail(iid))


@route("/api/incidents/*/redeliver", "POST")
def api_incident_redeliver(h):
    s = _require_role(h, "supervisor")
    iid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.incident_redeliver(
        s["user"], iid, body.get("reason", "")))


@route("/api/incidents/*/close", "POST")
def api_incident_close(h):
    s = _require_role(h, "supervisor")
    iid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.incident_close_unverified(
        s["user"], iid, body.get("reason", "")))


@route("/api/incidents/*/note", "POST")
def api_incident_note(h):
    s = _require_role(h, "supervisor")
    iid = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.incident_note(s["user"], iid, body.get("note", "")))


@route("/api/quarantine", "GET")
def api_quarantine(h):
    _check_login(h)
    h.send_json({"quarantined": h.ctx.svc.list_quarantine()})


# ---------------- 审计封存 JSON 接口 ----------------
@route("/api/seals", "POST")
def api_seal_request(h):
    s = _require_role(h, "supervisor")
    body = h.read_json()
    out = h.ctx.svc.request_seal(actor=s["user"], from_id=body.get("from_id"),
                                 to_id=body.get("to_id"))
    h.send_json(out, 200 if out["duplicate"] else 201)


@route("/api/seals", "GET")
def api_seal_list(h):
    _check_login(h)
    q = h.query()
    status = q.get("status")
    h.send_json({"seals": h.ctx.svc.list_seals(
        status=None if status in (None, "ALL") else status)})


@route("/api/seals/*/package", "GET")
def api_seal_package(h):
    _check_login(h)
    seal_id = h.raw_path.split("/")[3]
    h.send_json(h.ctx.svc.read_seal_package(seal_id))


@route("/api/seals/*", "GET")
def api_seal_detail(h):
    _check_login(h)
    seal_id = h.raw_path.rsplit("/", 1)[-1]
    h.send_json(h.ctx.svc.seal_detail(seal_id))


@route("/api/seals/*/generate", "POST")
def api_seal_generate(h):
    s = _require_role(h, "supervisor")
    seal_id = h.raw_path.split("/")[3]
    h.send_json(h.ctx.svc.generate_seal(s["user"], seal_id))


@route("/api/seals/*/cancel", "POST")
def api_seal_cancel(h):
    s = _require_role(h, "supervisor")
    seal_id = h.raw_path.split("/")[3]
    body = h.read_json()
    h.send_json(h.ctx.svc.cancel_seal(s["user"], seal_id, body.get("reason", "")))


@route("/api/seals/*/verify", "POST")
def api_seal_verify(h):
    s = _require_role(h, "supervisor")
    seal_id = h.raw_path.split("/")[3]
    h.send_json(h.ctx.svc.verify_seal(s["user"], seal_id))


@route("/healthz", "GET")
def health(h):
    h.send_json({"channel": "security", "ok": True})


def _ts(v) -> str:
    import datetime
    if not v:
        return "—"
    return datetime.datetime.fromtimestamp(v).strftime("%m-%d %H:%M:%S")


def build_handler(ctx):
    return make_handler(ctx, ROUTES)
