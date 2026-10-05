"""核心领域规则单元测试（无 HTTP，直接驱动服务层）。"""
from __future__ import annotations

import os
import tempfile
import unittest

from dual_gateway.config import load_config
from dual_gateway.errors import (Conflict, DeviceRejected, FrozenMismatch,
                                 InvalidReceipt, InvalidState, NotFound)
from dual_gateway.security import ledger_anchor, ledger_entry_hash, ledger_sign
from dual_gateway.service import CommandService
from dual_gateway.storage import Storage


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.clock = Clock()
        cfg = load_config(db_path=os.path.join(self.tmp, "g.db"),
                          default_valid_seconds=100,
                          confirm_timeout_seconds=50,
                          offline_seconds=5)
        self.cfg = cfg
        self.db = Storage(cfg.db_path)
        for d, k in cfg.device_keys.items():
            self.db.seed_device(d, k, self.clock())
        self.db.commit()
        self.svc = CommandService(self.db, cfg, clock=self.clock)

    def tearDown(self):
        self.db.close()

    def _create(self, devices=("DEV-A1", "DEV-A2"), code_out=True, **kw):
        out = self.svc.create_command(
            actor="ops", action="EMERGENCY_STOP", devices=list(devices),
            params={"rpm": 0, "valve": "close"}, **kw)
        return out

    def _confirm(self, c):
        return self.svc.confirm_command("supervisor", c["command_id"],
                                        c["confirm_code"], c["digest"])

    def _hello(self, dev="DEV-A1", boot="BOOT-1", ledger=None):
        return self.svc.hello(dev, boot, 1, ledger or [])

    def _receipt(self, dev, boot, seq, cid, result="EXECUTED"):
        return self.svc.receipt(dev, boot, seq, cid, result, "ok")

    # ---- 构造带指令指纹 + prev 哈希链的账簿条目 ----
    def _lentry(self, dev, c, boot="B1", seq=1, result="EXECUTED",
                *, digest=None, prev=None, command_id=None, message="done"):
        cid = command_id or c["command_id"]
        dig = digest if digest is not None else c["digest"]
        p = prev if prev is not None else ledger_anchor(dev, boot, 1)
        e = {"command_id": cid, "boot_code": boot, "seq": seq,
             "result": result, "digest": dig, "message": message, "prev": p}
        return e

    def _lhash(self, dev, e):
        return ledger_entry_hash(dev, e)

    def _lsig(self, dev, entries):
        return ledger_sign(self.cfg.device_keys[dev], entries)

    def _hello_ledger(self, dev, boot, entries, first_seq=1, sig=None):
        return self.svc.hello(
            dev, boot, first_seq, entries,
            ledger_sig=sig if sig is not None else self._lsig(dev, entries))


class TestCreateConfirm(ServiceTestBase):
    def test_frozen_create_and_code_once(self):
        c = self._create()
        self.assertEqual(c["status"], "PENDING")
        got = self.svc.get_command(c["command_id"])
        self.assertNotIn("confirm_code", got)  # 明文码只能出现一次
        self.assertEqual(len(c["digest"]), 64)

    def test_confirm_requires_code_and_digest(self):
        c = self._create()
        with self.assertRaises(FrozenMismatch):
            self.svc.confirm_command("supervisor", c["command_id"], "000000", c["digest"])
        with self.assertRaises(FrozenMismatch):
            self.svc.confirm_command("supervisor", c["command_id"],
                                     c["confirm_code"], "deadbeef")
        ok = self._confirm(c)
        self.assertEqual(ok["status"], "CONFIRMED")
        with self.assertRaises(InvalidState):
            self._confirm(c)  # 重复确认

    def test_unknown_device_rejected(self):
        with self.assertRaises(NotFound):
            self._create(devices=("DEV-A1", "GHOST"))

    def test_reject_closes(self):
        c = self._create()
        out = self.svc.reject_command("supervisor", c["command_id"], "看着不对")
        self.assertEqual(out["status"], "REJECTED")
        self.assertTrue(all(t["status"] == "SKIPPED" for t in out["targets"]))


class TestReceiptOrdering(ServiceTestBase):
    def _ready_one(self, dev="DEV-A1"):
        c = self._create(devices=(dev,))
        self._confirm(c)
        self._hello(dev, "B1")
        self.svc.pull(dev, "B1")
        return c

    def test_happy_path_seq_and_terminal(self):
        c = self._ready_one()
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXECUTED")
        self.assertEqual(got["targets"][0]["receipt"]["boot_code"], "B1")

    def test_stale_boot_rejected(self):
        c = self._ready_one()
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "BOOT-OLD", 1, c["command_id"])
        self.assertEqual(cm.exception.details["reason"], "STALE_BOOT")
        # 状态未变
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DISPATCHED")

    def test_gap_rejected(self):
        c = self._ready_one()
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 2, c["command_id"])
        self.assertEqual(cm.exception.details["reason"], "OUT_OF_ORDER_GAP")

    def test_seq_reuse_rejected(self):
        c = self._ready_one()
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        # 同序号但换一条指令：拒绝，序号不能复用
        c2 = self._create(devices=("DEV-A1",))
        self._confirm(c2)
        self.svc.pull("DEV-A1", "B1")
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 1, c2["command_id"])
        self.assertEqual(cm.exception.details["reason"], "REUSED_OR_OLD_SEQ")

    def test_duplicate_is_idempotent_not_state_change(self):
        c = self._ready_one()
        self._receipt("DEV-A1", "B1", 1, c["command_id"], "EXECUTED")
        # 设备重发同一回执：返回 duplicate，且不能把 EXECUTED 改成 FAILED
        out = self._receipt("DEV-A1", "B1", 1, c["command_id"], "EXECUTED")
        self.assertTrue(out["duplicate"])
        with self.assertRaises(InvalidReceipt):
            self._receipt("DEV-A1", "B1", 1, c["command_id"], "FAILED")
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")

    def test_receipt_for_unknown_or_undispatched(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 1, "CMD-NOPE")
        self.assertEqual(cm.exception.details["reason"], "UNKNOWN_TARGET")
        # 未 PULL 就回执
        with self.assertRaises(InvalidReceipt) as cm:
            self._receipt("DEV-A1", "B1", 1, c["command_id"])
        self.assertEqual(cm.exception.details["reason"], "NOT_DISPATCHED")


class TestRevoke(ServiceTestBase):
    def test_revoke_before_confirm(self):
        c = self._create()
        out = self.svc.revoke_command("ops", c["command_id"], "取消")
        self.assertEqual(out["status"], "REVOKED")

    def test_revoke_after_dispatch_blocked(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        with self.assertRaises(Conflict) as cm:
            self.svc.revoke_command("ops", c["command_id"])
        self.assertIn("在途", cm.exception.message)

    def test_revoke_after_executed_impossible(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        with self.assertRaises(Conflict):
            self.svc.revoke_command("ops", c["command_id"])

    def test_revoke_multi_device_with_one_executed_blocked(self):
        c = self._create(devices=("DEV-A1", "DEV-A2"))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self._hello("DEV-A2", "B2")
        self.svc.pull("DEV-A1", "B1")
        self._receipt("DEV-A1", "B1", 1, c["command_id"])
        # A2 尚未投递，但 A1 已执行：整单不可撤销，事实不能被覆盖
        with self.assertRaises(Conflict):
            self.svc.revoke_command("ops", c["command_id"])


class TestTimeout(ServiceTestBase):
    def test_confirm_timeout_expires(self):
        c = self._create()
        self.clock.advance(60)
        self.svc.sweep()
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXPIRED")
        with self.assertRaises(InvalidState):
            self._confirm(c)

    def test_window_close_pending_missed(self):
        c = self._create(devices=("DEV-A1", "DEV-A2"), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        # DEV-A2 一直离线；窗口关闭
        self.clock.advance(11)
        self.svc.sweep()
        got = self.svc.get_command(c["command_id"])
        statuses = {t["device_id"]: t["status"] for t in got["targets"]}
        self.assertEqual(statuses["DEV-A1"], "DOUBT")   # 在途等对账
        self.assertEqual(statuses["DEV-A2"], "MISSED")  # 未投递不补发
        self.assertEqual(got["status"], "CLOSED")


class TestOffline(ServiceTestBase):
    def test_offline_detection_and_old_boot_heartbeat(self):
        self._hello("DEV-A1", "B1")
        self.clock.advance(10)
        self.svc.sweep()
        dev = next(d for d in self.svc.list_devices() if d["device_id"] == "DEV-A1")
        self.assertFalse(dev["online"])
        # 设备重连用新代号；旧代号心跳必须被拒
        self.svc.hello("DEV-A1", "B2", 1)
        with self.assertRaises(DeviceRejected):
            self.svc.heartbeat("DEV-A1", "B1")
        self.svc.heartbeat("DEV-A1", "B2")  # 新代号正常

    def test_offline_device_gets_no_commands(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        # 从未 HELLO
        with self.assertRaises(DeviceRejected):
            self.svc.pull("DEV-A1", "B1")


class TestRestartRecovery(ServiceTestBase):
    def test_doubt_after_gateway_restart(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        # 网关重启：startup_recovery 把 DISPATCHED -> DOUBT
        self.svc.startup_recovery()
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")

    def test_ledger_recovers_executed_fact(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备也重启了（新代号），但账簿证明旧代号下已执行
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._hello_ledger("DEV-A1", "B2", [e])
        got = self.svc.get_command(c["command_id"])
        self.assertEqual(got["status"], "EXECUTED")
        self.assertEqual(got["targets"][0]["receipt"]["source"], "LEDGER_RECOVERY")

    def test_ledger_absent_after_reboot_redelivers_within_window(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备重启、账簿为空 → 未执行确定 → 窗口内重新投递
        self._hello_ledger("DEV-A1", "B2", [])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "PENDING")
        cmds = self.svc.pull("DEV-A1", "B2")["commands"]
        self.assertEqual(len(cmds), 1)

    def test_ledger_absent_after_window_missed_not_executed(self):
        c = self._create(devices=("DEV-A1",), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        self.clock.advance(20)
        # 设备重启账簿为空、窗口已过：保持 DOUBT（不臆断未执行而补发），
        # 工单仍 OPEN，等待安全角色在核实无执行证据后按 MISSED 人工关闭
        self._hello_ledger("DEV-A1", "B2", [])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")
        inc = self.svc.list_incidents(status="OPEN")
        self.assertEqual(len(inc), 1)
        self.svc.incident_close_unverified("supervisor", inc[0]["incident_id"],
                                           "窗口已过，电话核实现场无动作")
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "MISSED")
        self.assertEqual(self.svc.list_incidents(status="OPEN"), [])

    def test_same_boot_doubt_waits_no_redeliver(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        # 设备未重启（同一代号重连）：是否执行未知，不重投，继续等回执
        self._hello_ledger("DEV-A1", "B1", [])
        cmds = self.svc.pull("DEV-A1", "B1")["commands"]
        self.assertEqual(cmds, [])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "DOUBT")

    def test_fabricated_ledger_ignored(self):
        # 对从未投递的指令伪造账簿：不改任何状态
        c_fake = {"command_id": "CMD-FAKE", "digest": "0" * 64}
        self._hello("DEV-A1", "B1")
        e = self._lentry("DEV-A1", c_fake, "B1", 1)
        self._hello_ledger("DEV-A1", "B2", [e])
        rejected = self.svc.rejected_receipts()
        self.assertTrue(any(r["reason"] == "LEDGER_NEVER_DISPATCHED"
                            for r in rejected))
        self.assertTrue(any(x["reason"] == "NEVER_DISPATCHED"
                            for x in self.svc.list_quarantine()))

    def test_ledger_for_revoked_command_rejected(self):
        c = self._create(devices=("DEV-A1",))
        self.svc.revoke_command("ops", c["command_id"])
        self._hello("DEV-A1", "B1")
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._hello_ledger("DEV-A1", "B2", [e])
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "SKIPPED")  # 已撤销事实不被账簿翻案
        self.assertTrue(any(x["reason"] == "TARGET_SKIPPED"
                            for x in self.svc.list_quarantine()))


class TestIncidentOrders(ServiceTestBase):
    """事故恢复对账工单 + 签名账簿五重校验。"""

    def _dispatch_and_doubt(self, dev="DEV-A1", valid_seconds=None):
        c = self._create(devices=(dev,), valid_seconds=valid_seconds)
        self._confirm(c)
        self._hello(dev, "B1")
        self.svc.pull(dev, "B1")
        info = self.svc.startup_recovery()
        return c, info

    def test_restart_opens_one_open_incident_per_target(self):
        c, info = self._dispatch_and_doubt()
        self.assertEqual(info["incidents"], 1)
        incs = self.svc.list_incidents(status="OPEN")
        self.assertEqual(len(incs), 1)
        self.assertEqual(incs[0]["command_id"], c["command_id"])
        self.assertEqual(incs[0]["device_id"], "DEV-A1")
        # 再次“重启恢复”幂等：不重复开工单
        self.svc.startup_recovery()
        self.assertEqual(len(self.svc.list_incidents(status="OPEN")), 1)

    def test_incident_detail_has_evidence_history(self):
        c, _ = self._dispatch_and_doubt()
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        d = self.svc.incident_detail(iid)
        self.assertEqual(d["command"]["digest"], c["digest"])
        self.assertEqual(d["target"]["status"], "DOUBT")
        kinds = [e["kind"] for e in d["history"]]
        self.assertIn("INCIDENT_OPENED", kinds)

    def test_recovered_incident_resolved_with_evidence(self):
        c, _ = self._dispatch_and_doubt()
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._hello_ledger("DEV-A1", "B2", [e])
        d = self.svc.incident_detail(iid)
        self.assertEqual(d["status"], "RECOVERED")
        self.assertEqual(d["resolution"], "LEDGER:EXECUTED")
        kinds = [x["kind"] for x in d["history"]]
        self.assertIn("LEDGER_EVIDENCE_ACCEPTED", kinds)

    def test_auto_redelivery_resolves_incident(self):
        c, _ = self._dispatch_and_doubt()
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        self._hello_ledger("DEV-A1", "B2", [])
        d = self.svc.incident_detail(iid)
        self.assertEqual(d["status"], "REDELIVERED")
        self.assertEqual(d["target"]["status"], "PENDING")

    def test_manual_cannot_override_executed_fact(self):
        c, _ = self._dispatch_and_doubt()
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._hello_ledger("DEV-A1", "B2", [e])
        # 已 RECOVERED：不能再处置；即便强行调用，事实也不可覆盖
        with self.assertRaises(InvalidState):
            self.svc.incident_redeliver("supervisor", iid)
        with self.assertRaises(InvalidState):
            self.svc.incident_close_unverified("supervisor", iid)
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")

    def test_manual_close_only_after_window(self):
        c, _ = self._dispatch_and_doubt(valid_seconds=10)
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        # 窗口内不允许人工关闭
        with self.assertRaises(Conflict):
            self.svc.incident_close_unverified("supervisor", iid)
        self.clock.advance(20)
        # 设备换代次但无账簿：保持 DOUBT；人工核实后关闭为 MISSED
        self._hello_ledger("DEV-A1", "B2", [])
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "DOUBT")
        out = self.svc.incident_close_unverified("supervisor", iid, "现场确认无动作")
        self.assertEqual(out["status"], "EXPIRED")
        self.assertEqual(out["target"]["status"], "MISSED")
        self.assertIsNone(out["target"]["receipt"])  # 不产生执行事实

    def test_manual_redeliver_requires_reboot_and_window(self):
        c, _ = self._dispatch_and_doubt()
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        # 设备离线：禁止人工重投
        with self.assertRaises(Conflict):
            self.svc.incident_redeliver("supervisor", iid)
        # 同代号在线（是否执行未知）：禁止重投
        self._hello_ledger("DEV-A1", "B1", [])
        with self.assertRaises(Conflict):
            self.svc.incident_redeliver("supervisor", iid)

    def test_note_appends_history_without_state_change(self):
        c, _ = self._dispatch_and_doubt()
        iid = self.svc.list_incidents(status="OPEN")[0]["incident_id"]
        self.svc.incident_note("supervisor", iid, "已电话联系现场，待回复")
        d = self.svc.incident_detail(iid)
        self.assertEqual(d["status"], "OPEN")
        self.assertIn("MANUAL_NOTE", [x["kind"] for x in d["history"]])


class TestLedgerValidation(ServiceTestBase):
    """签名 / 代次 / 单调编号 / 指纹 / 连续性——失败一律隔离留痕。"""

    def _doubt(self):
        c = self._create(devices=("DEV-A1",))
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.svc.startup_recovery()
        return c

    def _reconnect_b2(self, entries, *, sig=None):
        return self._hello_ledger("DEV-A1", "B2", entries, sig=sig)

    def test_bad_signature_quarantines_all_and_no_recovery(self):
        c = self._doubt()
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._reconnect_b2([e], sig="deadbeef")
        q = self.svc.list_quarantine()
        self.assertTrue(all(x["reason"] == "LEDGER_BAD_SIGNATURE" for x in q))
        self.assertEqual(len(q), 1)
        # 事实未补记，目标仍 DOUBT；坏签名不得触发重投
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "DOUBT")
        cmds = self.svc.pull("DEV-A1", "B2")["commands"]
        self.assertEqual(cmds, [])

    def test_duplicate_upload_is_idempotent(self):
        c = self._doubt()
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._reconnect_b2([e])
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "EXECUTED")
        # 整册重复上送：不产生重复事实/重复对账事件（仅 DEVICE_HELLO 心跳性事件）
        def reconcile_events():
            return [e for e in self.svc.audit_events(limit=500)
                    if e["action"] in ("LEDGER_RECONCILED", "LEDGER_RECOVERY")]
        ev_before = len(reconcile_events())
        r = self._reconnect_b2([e])
        self.assertTrue(r["ledger"]["duplicate"])
        q = self.svc.list_quarantine()
        self.assertEqual(q, [])
        receipts = self.db.conn.execute(
            "SELECT COUNT(*) n FROM receipts").fetchone()["n"]
        self.assertEqual(receipts, 1)
        self.assertEqual(len(reconcile_events()), ev_before)

    def test_seq_gap_quarantines_entry_and_rest_of_boot(self):
        c = self._doubt()
        # 缺 seq=1，直接给 seq=2（编号缺口）
        e2 = self._lentry("DEV-A1", c, "B1", 2,
                          prev=ledger_anchor("DEV-A1", "B1", 1))
        self._reconnect_b2([e2])
        reasons = {x["reason"] for x in self.svc.list_quarantine()}
        self.assertIn("SEQ_GAP", reasons)
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "DOUBT")

    def test_seq_reuse_quarantined(self):
        c = self._doubt()
        e1 = self._lentry("DEV-A1", c, "B1", 1)
        e1b = self._lentry("DEV-A1", c, "B1", 1, result="FAILED")
        self._reconnect_b2([e1, e1b])
        reasons = {x["reason"] for x in self.svc.list_quarantine()}
        self.assertIn("SEQ_REUSED", reasons)

    def test_broken_prev_chain_quarantined(self):
        c = self._doubt()
        e = self._lentry("DEV-A1", c, "B1", 1, prev="0" * 64)
        self._reconnect_b2([e])
        self.assertTrue(any(x["reason"] == "CHAIN_DISCONTINUITY"
                            for x in self.svc.list_quarantine()))

    def test_fingerprint_mismatch_quarantined(self):
        c = self._doubt()
        e = self._lentry("DEV-A1", c, "B1", 1, digest="f" * 64)
        self._reconnect_b2([e])
        self.assertTrue(any(x["reason"] == "FINGERPRINT_MISMATCH"
                            for x in self.svc.list_quarantine()))
        self.assertEqual(
            self.svc.get_command(c["command_id"])["targets"][0]["status"], "DOUBT")

    def test_fact_conflict_quarantined_and_fact_stands(self):
        c = self._doubt()
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._reconnect_b2([e])  # 补记 EXECUTED
        # 同册重放被幂等跳过；构造不同内容（message 变）使 book_hash 不同，
        # 条目仍 seq=1 且 result=FAILED → 与事实矛盾
        e_conflict = self._lentry("DEV-A1", c, "B1", 1, result="FAILED",
                                  message="conflict")
        self.svc.hello("DEV-A1", "B3", 1, [e_conflict],
                       ledger_sig=self._lsig("DEV-A1", [e_conflict]))
        self.assertTrue(any(x["reason"] == "FACT_CONFLICT"
                            for x in self.svc.list_quarantine()))
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertEqual(t["status"], "EXECUTED")  # 矛盾记录不能翻案

    def test_unknown_boot_generation_quarantined(self):
        c = self._doubt()
        # boot 从未在网关节过（设备伪造旧代次）
        e = {"command_id": c["command_id"], "boot_code": "BOOT-GHOST", "seq": 1,
             "result": "EXECUTED", "digest": c["digest"], "message": "",
             "prev": ledger_anchor("DEV-A1", "BOOT-GHOST", 1)}
        self._reconnect_b2([e])
        self.assertTrue(any(x["reason"] == "UNKNOWN_BOOT_GENERATION"
                            for x in self.svc.list_quarantine()))

    def test_expired_evidence_only_quarantined(self):
        c = self._create(devices=("DEV-A1",), valid_seconds=10)
        self._confirm(c)
        self._hello("DEV-A1", "B1")
        self.svc.pull("DEV-A1", "B1")
        self.clock.advance(12)
        self.svc.sweep()  # 窗口关闭：DISPATCHED→DOUBT + 工单
        # 设备事后带账簿声称当时已执行：只能隔离，不能补成 EXECUTED
        e = self._lentry("DEV-A1", c, "B1", 1)
        self._reconnect_b2([e])
        self.assertTrue(any(x["reason"] == "WINDOW_EXPIRED"
                            for x in self.svc.list_quarantine()))
        t = self.svc.get_command(c["command_id"])["targets"][0]
        self.assertIn(t["status"], ("DOUBT", "MISSED"))
        self.assertIsNone(t["receipt"])


class TestAuditChain(ServiceTestBase):
    def test_chain_verifies(self):
        for i in range(3):
            c = self._create(devices=("DEV-A1",))
            self._confirm(c)
        r = self.svc.verify_audit_chain()
        self.assertTrue(r["ok"])
        self.assertGreater(r["events"], 5)

    def test_chain_detects_tampering(self):
        c = self._create()
        self._confirm(c)
        # 直接篡改审计负载
        self.db.conn.execute("UPDATE events SET payload=? WHERE id=1",
                             ('{"hacked":true}',))
        self.db.commit()
        r = self.svc.verify_audit_chain()
        self.assertFalse(r["ok"])
        self.assertEqual(r["broken_at"], 1)  # 首条负载即被篡改，哈希立即对不上


if __name__ == "__main__":
    unittest.main()
