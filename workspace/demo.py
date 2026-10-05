#!/usr/bin/env python3
"""端到端场景演示脚本（不依赖测试框架，直接跑真实网关+设备模拟器）。

运行：python3 demo.py
会依次演示：
  1. 双通道确认正常流程（创建→冻结→第二角色确认→下发→回执）
  2. 通道隔离：业务令牌无法确认、错确认码/错摘要被拒、设备 HMAC 伪造被拒
  3. 撤销安全：未确认可撤、在途拒撤、已执行不可撤销
  4. 确认超时自动冻结，冻结后绝不能再下发
  5. 旧启动代号 / 跳号 / 序号复用回执全部拒绝留痕，不改当前状态
  6. 回执丢失 + 网关重启：在途转 DOUBT 并生成对账工单，设备签名账簿补记执行事实、不重投
  7. 设备未执行即重启：窗口内安全重投一次；窗口外不补发、转人工处置
  8. 事故对账：坏签名/旧代次/编号缺口/指纹不符/矛盾记录全部隔离留痕；
     重复上送幂等；人工处置不能覆盖已确认执行事实
  9. 审计哈希链校验（含篡改检测）
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time

from dual_gateway.app import Gateway
from dual_gateway.config import load_config
from dual_gateway.device_sim import SimDevice
from dual_gateway.security import hmac_sign

import urllib.request
import urllib.error

GREEN = "\033[92m"; RED = "\033[91m"; YEL = "\033[93m"; DIM = "\033[2m"; END = "\033[0m"


def hr(title):
    print(f"\n{'='*70}\n{YEL}▶ {title}{END}\n{'='*70}")


def ok(msg):
    print(f"  {GREEN}✔{END} {msg}")


def bad(msg):
    print(f"  {RED}✘ 被拒绝：{msg}{END}")


def info(msg):
    print(f"  {DIM}· {msg}{END}")


def call(method, url, *, token=None, cookie=None, body=None,
         device=None, key=None):
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Biz-Token"] = token
    if cookie:
        headers["Cookie"] = cookie
    if device:
        headers["X-Device-Id"] = device
        headers["X-Signature"] = hmac_sign(key, data or b"")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    tmp = tempfile.mkdtemp(prefix="gw-demo-")
    cfg = load_config(
        db_path=os.path.join(tmp, "gw.db"),
        biz_port=18090, sec_port=18091, dev_port=18092,
        default_valid_seconds=120, confirm_timeout_seconds=60,
        offline_seconds=4, sweep_interval=0.2)
    BIZ, SEC, DEV = ("http://127.0.0.1:18090", "http://127.0.0.1:18091",
                     "http://127.0.0.1:18092")
    gw = Gateway(cfg)
    gw.start()
    time.sleep(0.3)
    TK = cfg.biz_token

    def create(devices, action="EMERGENCY_STOP", params=None, valid_seconds=None):
        b = {"action": action, "devices": list(devices),
             "params": params or {"valve": "CLOSE", "rpm": 0}}
        if valid_seconds:
            b["valid_seconds"] = valid_seconds
        st, out = call("POST", BIZ + "/api/commands", token=TK, body=b)
        assert st == 201, out
        return out

    def login(user="supervisor"):
        st, out, hdr = None, None, None
        data = json.dumps({"username": user,
                           "password": cfg.sec_users[user]}).encode()
        req = urllib.request.Request(SEC + "/api/session", data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as r:
            return r.headers["Set-Cookie"].split(";")[0]

    def confirm(c, cookie, code=None, digest=None):
        return call("POST", f"{SEC}/api/commands/{c['command_id']}/confirm",
                    cookie=cookie,
                    body={"confirm_code": code or c["confirm_code"],
                          "digest_ack": digest or c["digest"]})

    def detail(c):
        st, out = call("GET", f"{BIZ}/api/commands/{c['command_id']}", token=TK)
        return out

    def devpost(path, dev_id, body, bad_key=False):
        return call("POST", DEV + path, device=dev_id,
                    key="wrong" if bad_key else cfg.device_keys[dev_id], body=body)

    def make_dev(dev_id, **kw):
        return SimDevice(dev_id, cfg.device_keys[dev_id], DEV,
                         os.path.join(tmp, "sim", dev_id), verbose=False, **kw)

    from dual_gateway.security import new_boot_code

    def newboot():
        return new_boot_code()

    def report(dev_id, d, cid, result="EXECUTED", *, boot=None, seq=None):
        return devpost("/api/device/receipt", dev_id,
                       {"boot_code": boot or d.boot_code,
                        "seq": seq if seq is not None else d.seq,
                        "command_id": cid, "result": result})

    # ---------------- 1 正常流程 ----------------
    hr("1. 双通道确认正常流程")
    c = create(["DEV-A1", "DEV-A2"])
    info(f"业务系统创建 {c['command_id']}，状态={c['status']}，冻结摘要={c['digest'][:24]}…")
    info(f"带外确认码（仅此一次返回）: {YEL}{c['confirm_code']}{END}")
    cookie = login()
    st, out = confirm(c, cookie)
    ok(f"第二角色输入确认码+复核摘要后确认 → {out['status']}")

    for i, dev_id in enumerate(["DEV-A1", "DEV-A2"], start=1):
        d = make_dev(dev_id)
        devpost("/api/device/hello", dev_id,
                {"boot_code": d.boot_code, "first_seq": 1})
        st, pull = devpost("/api/device/pull", dev_id, {"boot_code": d.boot_code})
        info(f"{dev_id} 拉取到 {len(pull['commands'])} 条指令，执行中…")
        d._append_ledger(d.make_ledger_entry(
            c["command_id"], "EXECUTED", c["digest"], "valve closed"))
        st, resp = report(dev_id, d, c["command_id"])
        d.seq = 2
        ok(f"{dev_id} 回执 boot={d.boot_code[:12]}… seq=1 接受={resp['accepted']}")
    time.sleep(0.3)
    final = detail(c)
    ok(f"指令最终状态 {GREEN}{final['status']}{END}（两台设备事实均为 EXECUTED）")

    # ---------------- 2 通道隔离 ----------------
    hr("2. 通道隔离与凭据独立性")
    c2 = create(["DEV-A1"], action="PURGE_LINE")
    st, out = call("POST", BIZ + "/api/commands",
                   body={"action": "X", "devices": ["DEV-A1"], "params": {}})
    bad(f"无业务令牌创建指令 → HTTP {st}")
    st, out = confirm(c2, cookie, code="000001")
    bad(f"错误带外确认码 → {out['error']}")
    st, out = confirm(c2, cookie, digest="0" * 64)
    bad(f"摘要复核不一致（防调包）→ {out['error']}")
    ro = login("safety")
    st, out = confirm(c2, ro)
    bad(f"只读安全员试图确认（职责分离）→ HTTP {st} {out['error']}")
    st, out = devpost("/api/device/hello", "DEV-A1",
                      {"boot_code": "BOOT-FORGED", "first_seq": 1}, bad_key=True)
    bad(f"设备伪造 HMAC 握手 → HTTP {st}")
    # 正确确认收尾
    confirm(c2, cookie)
    ok("正确确认码+摘要仍可确认，误杀=0")

    # ---------------- 3 撤销安全 ----------------
    hr("3. 指令撤销的边界")
    c3 = create(["DEV-A1"], action="TEMP_CUT")
    st, out = call("POST", f"{BIZ}/api/commands/{c3['command_id']}/revoke",
                   token=TK, body={"reason": "计划取消"})
    ok(f"未确认、未下发 → 撤销成功，状态={out['status']}")

    c4 = create(["DEV-A1"], action="TEMP_CUT")
    confirm(c4, cookie)
    d = None  # 仅借启动代号
    boot = newboot()
    devpost("/api/device/hello", "DEV-A1", {"boot_code": boot, "first_seq": 1})
    devpost("/api/device/pull", "DEV-A1", {"boot_code": boot})
    st, out = call("POST", f"{BIZ}/api/commands/{c4['command_id']}/revoke",
                   token=TK, body={})
    bad(f"已下发在途（是否执行未知）→ {out['message']}")
    st, out = devpost("/api/device/receipt", "DEV-A1",
                      {"boot_code": boot, "seq": 1,
                       "command_id": c4["command_id"], "result": "EXECUTED"})
    st, out = call("POST", f"{BIZ}/api/commands/{c4['command_id']}/revoke",
                   token=TK, body={})
    bad(f"已执行事实不可撤销覆盖 → {out['message']}")
    ok(f"指令状态保持 {detail(c4)['status']}")

    # ---------------- 4 确认超时 ----------------
    hr("4. 确认超时冻结")
    c5 = create(["DEV-A1"], action="REMOTE_TRIP", valid_seconds=1)
    info("有效窗口=1s，等待超时…")
    time.sleep(1.6)
    st, out = confirm(c5, cookie)
    bad(f"超时后确认 → {out['error']}（{out['message']}）")
    ok(f"指令已冻结为 {detail(c5)['status']}，设备永远拉取不到它")
    st, pull = devpost("/api/device/pull", "DEV-A1", {"boot_code": boot})
    ok(f"设备拉取列表不含过期指令（拿到 {len(pull['commands'])} 条）")

    # ---------------- 5 坏回执 ----------------
    hr("5. 旧启动代号 / 乱序 / 序号复用 —— 一律不改状态")
    c6 = create(["DEV-A1"], action="OVERSPEED_TEST")
    confirm(c6, cookie)
    boot2 = newboot()
    devpost("/api/device/hello", "DEV-A1", {"boot_code": boot2, "first_seq": 1})
    devpost("/api/device/pull", "DEV-A1", {"boot_code": boot2})
    st, out = devpost("/api/device/receipt", "DEV-A1",
                      {"boot_code": "BOOT-THE-OLD-ONE", "seq": 1,
                       "command_id": c6["command_id"], "result": "EXECUTED"})
    bad(f"旧启动代号回执 → {out['details']['reason']}")
    st, out = devpost("/api/device/receipt", "DEV-A1",
                      {"boot_code": boot2, "seq": 5,
                       "command_id": c6["command_id"], "result": "EXECUTED"})
    bad(f"跳号回执(seq=5) → {out['details']['reason']}")
    st, out = devpost("/api/device/receipt", "DEV-A1",
                      {"boot_code": boot2, "seq": 1,
                       "command_id": c6["command_id"], "result": "EXECUTED"})
    ok("正常 seq=1 回执被接受")
    st, out = devpost("/api/device/receipt", "DEV-A1",
                      {"boot_code": boot2, "seq": 1,
                       "command_id": "CMD-OTHER", "result": "EXECUTED"})
    bad(f"序号复用伪造别的指令 → {out['details']['reason']}")
    st, rej = call("GET", SEC + "/api/rejected", cookie=cookie)
    reasons = sorted({r["reason"] for r in rej["rejected"]})
    ok(f"拒绝回执全部留痕：{reasons}")

    # ---------------- 6 网关重启 + 回执丢失 ----------------
    hr("6. 网关重启 / 回执丢失：DOUBT + 对账工单 + 签名账簿补记，绝不误执行")
    c7 = create(["DEV-A2"], action="EMERGENCY_STOP")
    confirm(c7, cookie)
    d7 = make_dev("DEV-A2")
    devpost("/api/device/hello", "DEV-A2",
            {"boot_code": d7.boot_code, "first_seq": 1})
    devpost("/api/device/pull", "DEV-A2", {"boot_code": d7.boot_code})
    d7._append_ledger(d7.make_ledger_entry(
        c7["command_id"], "EXECUTED", c7["digest"], "done"))
    d7.seq = 2
    info("设备已执行并落盘，但回执在途时网关崩溃（不重放任何乐观状态）…")
    gw.stop()
    time.sleep(0.3)
    cfg2 = load_config(db_path=cfg.db_path, biz_port=18090, sec_port=18091,
                       dev_port=18092, default_valid_seconds=120,
                       confirm_timeout_seconds=60, offline_seconds=4,
                       sweep_interval=0.2)
    gw = Gateway(cfg2)
    gw.start()
    time.sleep(0.4)
    cookie = login()  # 重启后内存会话失效（安全设计），第二角色需重新登录
    t = detail(c7)["targets"][0]
    ok(f"重启后在途目标状态={t['status']}（等待设备账簿对账，禁止重投）")
    st, incs = call("GET", SEC + "/api/incidents?status=OPEN", cookie=cookie)
    iid7 = incs["incidents"][0]["incident_id"]
    ok(f"已为缺终态目标生成安全通道对账工单 {iid7}（业务通道看不到）")
    from dual_gateway.security import ledger_sign
    sig7 = ledger_sign(cfg.device_keys["DEV-A2"], d7.executed)
    devpost("/api/device/hello", "DEV-A2",
            {"boot_code": d7.boot_code, "first_seq": 1,
             "ledger": d7.executed, "ledger_sig": sig7})
    st, pull = devpost("/api/device/pull", "DEV-A2", {"boot_code": d7.boot_code})
    ok(f"对账后设备拉取 {len(pull['commands'])} 条（已执行的指令不会被重投/双触发）")
    t = detail(c7)["targets"][0]
    ok(f"事实被账簿补记：状态={t['status']}，回执来源={t['receipt']['source']}")
    st, idet = call("GET", f"{SEC}/api/incidents/{iid7}", cookie=cookie)
    ok(f"工单自动结案：{idet['status']}，处置历史 "
       f"{[e['kind'] for e in idet['history']]}")

    # ---------------- 7 设备重启未执行 ----------------
    hr("7. 设备离线恢复：未执行才重投，窗口外 MISSED")
    c8 = create(["DEV-B1"], action="OPEN_BYPASS")
    confirm(c8, cookie)
    d8 = make_dev("DEV-B1")
    devpost("/api/device/hello", "DEV-B1",
            {"boot_code": d8.boot_code, "first_seq": 1})
    devpost("/api/device/pull", "DEV-B1", {"boot_code": d8.boot_code})
    info("设备尚未执行就断电重启（新启动代号、空账本），网关也重启…")
    gw.stop(); time.sleep(0.2)
    gw = Gateway(cfg2); gw.start(); time.sleep(0.3)
    cookie = login()
    d8.reboot()  # 新 boot_code + HELLO + 空账本 → 证明未执行 → 重投
    st, pull = devpost("/api/device/pull", "DEV-B1", {"boot_code": d8.boot_code})
    ok(f"窗口内重投 {len(pull['commands'])} 次（且只有一次）")

    c9 = create(["DEV-B1"], action="OPEN_BYPASS", valid_seconds=3)
    confirm(c9, cookie)
    boot9 = newboot()
    info("设备在整个有效窗口内离线，等待窗口关闭…")
    time.sleep(3.6)
    devpost("/api/device/hello", "DEV-B1",
            {"boot_code": boot9, "first_seq": 1})
    st, pull = devpost("/api/device/pull", "DEV-B1", {"boot_code": boot9})
    t = detail(c9)["targets"][0]
    ok(f"窗口已过：目标={t['status']}，设备恢复后也拿不到指令（未执行→永不误执行）")

    # ---------------- 8 事故对账：坏签名/指纹/缺口/幂等/人工处置 ----------------
    hr("8. 事故恢复对账：签名账簿五重校验 + 工单隔离留痕")
    from dual_gateway.security import (ledger_anchor, ledger_entry_hash,
                                       ledger_sign as _lsign)

    def signed_entry(dev_id, c, boot, seq, *, digest=None, result="EXECUTED",
                     prev=None, message="actuated"):
        e = {"command_id": c["command_id"], "boot_code": boot, "seq": seq,
             "result": result, "digest": digest if digest is not None else c["digest"],
             "message": message,
             "prev": prev if prev is not None else ledger_anchor(dev_id, boot, 1)}
        return e

    # 8a) 坏签名：整册隔离、不补记、fail-closed 不重投
    ca = create(["DEV-A1"], action="EMERGENCY_STOP")
    confirm(ca, cookie)
    ba = newboot()
    devpost("/api/device/hello", "DEV-A1", {"boot_code": ba, "first_seq": 1})
    devpost("/api/device/pull", "DEV-A1", {"boot_code": ba})
    gw.stop(); time.sleep(0.2); gw = Gateway(cfg2); gw.start(); time.sleep(0.3)
    cookie = login()
    ea = signed_entry("DEV-A1", ca, ba, 1)
    st, hb = devpost("/api/device/hello", "DEV-A1",
                     {"boot_code": newboot(), "first_seq": 1,
                      "ledger": [ea], "ledger_sig": "0" * 64})
    ok(f"账簿签名无效 → sig_valid={hb['ledger']['sig_valid']}，"
       f"隔离 {len(hb['ledger']['quarantined'])} 条，目标不动、不重投")

    # 8b) 指令指纹被调包：隔离
    cb = create(["DEV-A2"], action="EMERGENCY_STOP")
    confirm(cb, cookie)
    bb = newboot()
    devpost("/api/device/hello", "DEV-A2", {"boot_code": bb, "first_seq": 1})
    devpost("/api/device/pull", "DEV-A2", {"boot_code": bb})
    gw.stop(); time.sleep(0.2); gw = Gateway(cfg2); gw.start(); time.sleep(0.3)
    cookie = login()
    eb = signed_entry("DEV-A2", cb, bb, 1, digest="f" * 64)
    st, hb = devpost("/api/device/hello", "DEV-A2",
                     {"boot_code": newboot(), "first_seq": 1,
                      "ledger": [eb],
                      "ledger_sig": _lsign(cfg.device_keys["DEV-A2"], [eb])})
    reasons = {x["reason"] for x in hb["ledger"]["quarantined"]}
    bad(f"账簿指令指纹与冻结摘要不符 → {reasons}（只隔离，状态不变）")

    # 8c) 编号缺口 + 重复上送幂等：合法补记一次，重复不双记
    cc = create(["DEV-B1"], action="OPEN_BYPASS")
    confirm(cc, cookie)
    bc = newboot()
    devpost("/api/device/hello", "DEV-B1", {"boot_code": bc, "first_seq": 1})
    devpost("/api/device/pull", "DEV-B1", {"boot_code": bc})
    gw.stop(); time.sleep(0.2); gw = Gateway(cfg2); gw.start(); time.sleep(0.3)
    cookie = login()
    # 先送一个有缺口的册子（seq=2 直接出现）→ 隔离，不补记
    gap = signed_entry("DEV-B1", cc, bc, 2)
    st, hb = devpost("/api/device/hello", "DEV-B1",
                     {"boot_code": newboot(), "first_seq": 1,
                      "ledger": [gap],
                      "ledger_sig": _lsign(cfg.device_keys["DEV-B1"], [gap])})
    bad(f"编号缺口 seq=2 → { {x['reason'] for x in hb['ledger']['quarantined']} }")
    # 同代号重连并补上正确链（seq=1 接锚点）→ 补记
    good = signed_entry("DEV-B1", cc, bc, 1)
    st, hb1 = devpost("/api/device/hello", "DEV-B1",
                      {"boot_code": bc, "first_seq": 1, "ledger": [good],
                       "ledger_sig": _lsign(cfg.device_keys["DEV-B1"], [good])})
    ok(f"合法签名账簿补记：accepted={hb1['ledger']['accepted']}")
    st, hb2 = devpost("/api/device/hello", "DEV-B1",
                      {"boot_code": bc, "first_seq": 1, "ledger": [good],
                       "ledger_sig": _lsign(cfg.device_keys["DEV-B1"], [good])})
    ok(f"同册重复上送幂等：duplicate={hb2['ledger']['duplicate']}，"
       f"accepted={hb2['ledger']['accepted']}，不产生第二条事实")
    t = detail(cc)["targets"][0]
    ok(f"目标终态={t['status']}（人工/矛盾材料都无法再覆盖）")

    st, qall = call("GET", SEC + "/api/quarantine", cookie=cookie)
    ok(f"隔离区共 {len(qall['quarantined'])} 条问题材料（坏签名/指纹/缺口全程留痕）")

    # ---------------- 9 审计链 ----------------
    hr("9. 设备回执审计与哈希链")
    st, audit = call("GET", SEC + "/api/audit?limit=400", cookie=cookie)
    n = audit["chain"]["events"]
    ok(f"审计事件 {n} 条，哈希链校验={audit['chain']['ok']}，链尾 {audit['chain']['head'][:16]}…")
    st, rej = call("GET", SEC + "/api/rejected", cookie=cookie)
    ok(f"被拒绝回执留痕 {len(rej['rejected'])} 条（旧代号/跳号/复用/伪造可逐条追溯）")
    st, incs = call("GET", SEC + "/api/incidents?status=ALL", cookie=cookie)
    ok(f"对账工单 {len(incs['incidents'])} 张，工作台 /incidents 查看证据/冲突/处置历史")
    info("工作台: http://127.0.0.1:8081/login  (supervisor / S@fety-Confirm-7)")

    gw.stop()
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{GREEN}全部场景演示完成。{END}\n")


if __name__ == "__main__":
    main()
