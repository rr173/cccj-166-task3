"""审计封存 + 离线核验单元测试。

覆盖：
1. 封存包生成（区间首尾/前序链头/末尾摘要/逐事件证明/锚点/签名）；
2. 同一区间并发/重复申请只产生一份结果，重复申请返回原结果；
3. 撤销边界：仅 PENDING 可撤，SEALING/SEALED 不可撤，已封存不可覆盖；
4. 服务重启恢复：SEALING 续写完成；生成中崩溃回滚为 FAILED 可重试，不留永久锁；
5. 离线核验三分类 + 首个断点：包内损坏 / 前序历史不匹配 / 数据库落后；
6. 在线核验留痕（核验失败不改变封存结果）。
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest

from dual_gateway import sealing
from dual_gateway.config import load_config
from dual_gateway.errors import Conflict, InvalidState, NotFound
from dual_gateway.security import (GENESIS_HASH, canonical_json, event_hash,
                                   event_full_record_hash)
from dual_gateway.service import CommandService
from dual_gateway.storage import Storage


class SealTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = load_config(db_path=os.path.join(self.tmp, "g.db"),
                          seal_dir=os.path.join(self.tmp, "seals"))
        self.cfg = cfg
        self.db = Storage(cfg.db_path)
        for d, k in cfg.device_keys.items():
            self.db.seed_device(d, k, 1000.0)
        self.db.commit()
        self.svc = CommandService(self.db, cfg)
        # 制造若干事件
        c = self.svc.create_command("ops", "EMERGENCY_STOP", ["DEV-A1"], {"rpm": 0})
        self.svc.confirm_command("supervisor", c["command_id"],
                                 c["confirm_code"], c["digest"])
        c2 = self.svc.create_command("ops", "POWER_CUT", ["DEV-A2"], {"v": 1})
        self.max_id = self.db.events_max_id()
        self.assertGreaterEqual(self.max_id, 3)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seal_path(self, s):
        return s["package_path"]


class TestSealBuild(SealTestBase):
    def test_package_contains_required_parts(self):
        s = self.svc.request_seal("supervisor", 1, self.max_id)
        self.assertEqual(s["status"], "SEALED")
        pkg = sealing.load_package(s["package_path"])
        m = pkg["manifest"]
        self.assertEqual(m["from_id"], 1)
        self.assertEqual(m["to_id"], self.max_id)
        self.assertEqual(m["count"], self.max_id)
        self.assertEqual(m["prior_head"], GENESIS_HASH)
        self.assertEqual(m["first_hash"], pkg["events"][0]["hash"])
        self.assertEqual(m["last_hash"], pkg["events"][-1]["hash"])
        # 末尾摘要
        self.assertEqual(m["last_summary"]["id"], self.max_id)
        self.assertEqual(m["last_summary"]["hash"], m["last_hash"])
        # 逐事件证明
        self.assertEqual(len(pkg["proofs"]), self.max_id)
        self.assertEqual(pkg["proofs"][0]["position"], 1)
        # 签名 + 包指纹 + 锚点
        self.assertEqual(len(pkg["package_sig"]), 64)
        self.assertEqual(len(pkg["package_hash"]), 64)
        self.assertEqual(len(m["anchor"]), 64)

    def test_subrange_keeps_prior_head(self):
        s = self.svc.request_seal("supervisor", 2, self.max_id)
        pkg = sealing.load_package(s["package_path"])
        first = self.db.get_event_row(1)
        self.assertEqual(pkg["manifest"]["prior_head"], first["hash"])

    def test_default_range_is_full_chain(self):
        s = self.svc.request_seal("supervisor")
        self.assertEqual((s["from_id"], s["to_id"]), (1, self.max_id))

    def test_bad_range_rejected(self):
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", 1, self.max_id + 5)
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", 5, 2)
        # 不超尾但端点事件不存在（空洞）也拒绝
        with self.assertRaises((NotFound, InvalidState)):
            self.svc.request_seal("supervisor", self.max_id + 10,
                                  self.max_id + 11)

    def test_history_recorded(self):
        s = self.svc.request_seal("supervisor", 1, 2)
        detail = self.svc.seal_detail(s["seal_id"])
        kinds = [e["kind"] for e in detail["history"]]
        self.assertEqual(kinds, ["SEAL_REQUESTED", "SEAL_STARTED",
                                 "SEAL_COMPLETED"])


class TestSealDedup(SealTestBase):
    def test_duplicate_returns_same_result(self):
        a = self.svc.request_seal("supervisor", 1, 2)
        b = self.svc.request_seal("supervisor", 1, 2)
        self.assertEqual(a["seal_id"], b["seal_id"])
        self.assertEqual(b["status"], "SEALED")

    def test_concurrent_requests_single_result(self):
        import threading
        results = []

        def worker():
            results.append(self.svc.request_seal("safety-admin", 1, 2))
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ids = {r["seal_id"] for r in results}
        self.assertEqual(len(ids), 1, "同区间并发必须只产生一份封存")
        rows = self.db.list_seals()
        same_range = [r for r in rows if r["from_id"] == 1 and r["to_id"] == 2]
        self.assertEqual(len(same_range), 1)

    def test_different_ranges_allowed(self):
        a = self.svc.request_seal("supervisor", 1, 2)
        b = self.svc.request_seal("supervisor", 2, 3)
        self.assertNotEqual(a["seal_id"], b["seal_id"])


class TestSealCancelAndImmutability(SealTestBase):
    def _pending_seal(self):
        # 直接构造一份 PENDING 申请（不触发生成）
        row = self.db.insert_seal_request(
            {"seal_id": "SEAL-PEND1", "from_id": 1, "to_id": 1,
             "created_by": "supervisor"}, self.svc.now())
        self.db.commit()
        return row["seal_id"]

    def test_cancel_pending_ok(self):
        sid = self._pending_seal()
        out = self.svc.cancel_seal("supervisor", sid, "误申请")
        self.assertEqual(out["status"], "CANCELED")
        # 撤销后同区间可重新申请
        new = self.svc.request_seal("supervisor", 1, 1)
        self.assertEqual(new["status"], "SEALED")

    def test_cancel_sealed_rejected(self):
        s = self.svc.request_seal("supervisor", 1, 1)
        with self.assertRaises(Conflict):
            self.svc.cancel_seal("supervisor", s["seal_id"])

    def test_sealed_not_overwritten_by_new_request(self):
        a = self.svc.request_seal("supervisor", 1, 1)
        b = self.svc.request_seal("supervisor", 1, 1)
        self.assertEqual(a["seal_id"], b["seal_id"])
        self.assertEqual(a["package_hash"], b["package_hash"])
        # 数据库记录唯一
        rows = [r for r in self.db.list_seals()
                if r["from_id"] == 1 and r["to_id"] == 1]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "SEALED")

    def test_package_file_immutable_content(self):
        s = self.svc.request_seal("supervisor", 1, 2)
        with open(s["package_path"], "rb") as f:
            p1 = f.read()
        # 再次申请不重写
        self.svc.request_seal("supervisor", 1, 2)
        with open(s["package_path"], "rb") as f:
            p2 = f.read()
        self.assertEqual(p1, p2)


class TestSealRestartRecovery(SealTestBase):
    def _fresh_service(self):
        return CommandService(self.db, self.cfg)

    def test_stuck_sealing_resumed_and_completed(self):
        # 手工制造一份 SEALING（模拟生成中进程被杀死，未落盘）
        row = self.db.insert_seal_request(
            {"seal_id": "SEAL-HALF1", "from_id": 1, "to_id": 2,
             "created_by": "supervisor"}, self.svc.now())
        self.db.mark_seal_sealing("SEAL-HALF1", GENESIS_HASH, self.svc.now())
        self.db.commit()
        self.assertFalse(os.path.exists(
            os.path.join(self.cfg.seal_dir, "SEAL-HALF1.seal.json")))

        svc2 = self._fresh_service()
        info = svc2.recover_seals_on_startup()
        self.assertEqual(info["resumed"], 1)
        row2 = self.db.get_seal_row("SEAL-HALF1")
        self.assertEqual(row2["status"], "SEALED")
        self.assertTrue(os.path.exists(row2["package_path"]))
        kinds = [e["kind"] for e in self.db.list_seal_events("SEAL-HALF1")]
        self.assertIn("SEAL_RESUMED_ON_RESTART", kinds)
        self.assertIn("SEAL_COMPLETED", kinds)

    def test_crash_before_package_marks_failed_and_retryable(self):
        # 崩溃注入：PENDING→SEALING 成功后、写包前抛错
        def hook(stage, seal_id):
            raise RuntimeError("simulated crash during sealing")
        self.svc.seal_crash_hook = hook
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", 1, 2)
        # 找到那份记录：必须已回滚为 FAILED，而非卡 SEALING
        rows = [r for r in self.db.list_seals(status=None)
                if r["from_id"] == 1 and r["to_id"] == 2]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "FAILED")
        # 没有半成品文件
        self.assertFalse(os.path.exists(rows[0]["package_path"] or "/nonexistent"))

        # 重新申请同区间：成功生成（FAILED 不占用唯一索引）
        self.svc.seal_crash_hook = None
        again = self.svc.request_seal("supervisor", 1, 2)
        self.assertEqual(again["status"], "SEALED")
        self.assertTrue(os.path.exists(again["package_path"]))

    def test_temp_files_cleaned_on_restart(self):
        os.makedirs(self.cfg.seal_dir, exist_ok=True)
        tmpf = os.path.join(self.cfg.seal_dir, ".SEAL-X.abc.tmp")
        with open(tmpf, "w") as f:
            f.write("half")
        self._fresh_service().recover_seals_on_startup()
        self.assertFalse(os.path.exists(tmpf))

    def test_full_process_restart_completes(self):
        """用文件库模拟真实进程重启：SEALING → 关闭 → 新服务续写完成。"""
        sid = "SEAL-RESTART1"
        self.db.insert_seal_request(
            {"seal_id": sid, "from_id": 1, "to_id": self.max_id,
             "created_by": "supervisor"}, self.svc.now())
        self.db.mark_seal_sealing(sid, GENESIS_HASH, self.svc.now())
        self.db.commit()
        db_path, seal_dir, key = self.cfg.db_path, self.cfg.seal_dir, self.cfg.seal_key
        self.db.close()

        cfg2 = load_config(db_path=db_path, seal_dir=seal_dir, seal_key=key)
        db2 = Storage(db_path)
        svc2 = CommandService(db2, cfg2)
        svc2.recover_seals_on_startup()
        row = db2.get_seal_row(sid)
        self.assertEqual(row["status"], "SEALED")
        # 续写产出的包可独立核验
        r = sealing.verify_offline(row["package_path"], db_path, key)
        self.assertEqual(r["result"], "OK")
        db2.close()
        # 重新打开 base 使用的连接，避免 tearDown 关闭已关闭连接
        self.db = Storage(db_path)


class TestOfflineVerify(SealTestBase):
    def setUp(self):
        super().setUp()
        # 区间从 2 开始：事件 1 是“前序历史”，事件 2..max 在封存区间内，
        # 这样能分别制造前序不匹配与区间内落后两类断点。
        self.s = self.svc.request_seal("supervisor", 2, self.max_id)
        self.pkg_path = self.s["package_path"]
        self.bak = self.cfg.db_path + ".bak"
        self.db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.commit()
        shutil.copy(self.cfg.db_path, self.bak)

    def _verify(self, mutate=lambda c: None, pkg_path=None):
        shutil.copy(self.bak, self.cfg.db_path)
        conn = sqlite3.connect(self.cfg.db_path)
        mutate(conn)
        conn.commit()
        conn.close()
        return sealing.verify_offline(pkg_path or self.pkg_path,
                                      self.cfg.db_path, self.cfg.seal_key)

    def test_clean_ok(self):
        r = self._verify()
        self.assertEqual(r["result"], "OK")
        self.assertIn("db_match", r["checks"])

    def test_db_extra_events_ahead_still_ok(self):
        # 数据库在封存点之后继续增长是正常的
        self.svc.create_command("ops", "LATER", ["DEV-A1"], {"x": 1})
        self.db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.commit()
        shutil.copy(self.cfg.db_path, self.bak)
        r = self._verify()
        self.assertEqual(r["result"], "OK")

    def test_delete_middle_record_db_behind(self):
        mid = 2
        r = self._verify(lambda c: c.execute("DELETE FROM events WHERE id=?",
                                             (mid,)))
        self.assertEqual(r["result"], "DB_BEHIND")
        self.assertEqual(r["break_at"]["event_id"], mid)
        self.assertEqual(r["break_at"]["stage"], "event_missing")

    def test_modify_record_db_behind(self):
        r = self._verify(lambda c: c.execute(
            "UPDATE events SET actor='OFFLINE-EDIT' WHERE id=2"))
        self.assertEqual(r["result"], "DB_BEHIND")
        self.assertEqual(r["break_at"]["event_id"], 2)
        self.assertEqual(r["break_at"]["field"], "actor")

    def test_prior_history_content_mismatch(self):
        r = self._verify(lambda c: c.execute(
            "UPDATE events SET actor='ANOTHER-HISTORY' WHERE id=1"))
        self.assertEqual(r["result"], "HISTORY_MISMATCH")
        self.assertEqual(r["break_at"]["event_id"], 1)

    def test_prior_record_deleted_mismatch(self):
        r = self._verify(lambda c: c.execute("DELETE FROM events WHERE id=1"))
        self.assertEqual(r["result"], "HISTORY_MISMATCH")

    def test_alternative_consistent_prefix_mismatch(self):
        """换入一份内部自洽但内容不同的历史：重算链尾 != prior_head。"""
        def mutate(conn):
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM events WHERE id=1").fetchone()
            d = dict(row)
            payload = json.loads(d["payload"])
            payload["injected"] = "other-history"
            payload_txt = canonical_json(payload)
            new_h = event_hash(GENESIS_HASH, d["action"], payload)
            d["payload"] = payload_txt
            d["hash"] = new_h
            d["prev_hash"] = GENESIS_HASH
            # 同时伪造全字段摘要，使该条自身“自洽”，但链尾已经不同
            new_rec = event_full_record_hash(d)
            conn.execute("UPDATE events SET payload=?, hash=?, full_record_hash=? "
                         "WHERE id=1", (payload_txt, new_h, new_rec))
        r = self._verify(mutate)
        self.assertEqual(r["result"], "HISTORY_MISMATCH")
        self.assertEqual(r["break_at"]["stage"], "prior_head")

    def test_db_rolled_back_behind(self):
        """数据库回滚到封存点之前：区间首条缺失 → 但前序历史也已被清空，
        首个断点落在前序历史（封存点之前即不匹配）。"""
        r = self._verify(lambda c: c.execute(
            "DELETE FROM events WHERE id>=?", (1,)))
        self.assertEqual(r["result"], "HISTORY_MISMATCH")

    def test_db_rolled_back_partial_behind(self):
        """删掉封存点之后的首条（区间首事件），保留前序历史 → DB_BEHIND。"""
        r = self._verify(lambda c: c.execute(
            "DELETE FROM events WHERE id>=?", (2,)))
        self.assertEqual(r["result"], "DB_BEHIND")
        self.assertEqual(r["break_at"]["stage"], "event_missing")
        self.assertEqual(r["break_at"]["event_id"], 2)

    # ---- 包内损坏 ----
    def _write_pkg(self, pkg, name="mod.seal.json"):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(pkg, f)
        return p

    def test_bad_signature_package_corrupt(self):
        pkg = sealing.load_package(self.pkg_path)
        pkg["package_sig"] = "0" * 64
        p = self._write_pkg(pkg)
        r = self._verify(pkg_path=p)
        self.assertEqual(r["result"], "PACKAGE_CORRUPT")
        self.assertEqual(r["break_at"]["stage"], "signature")

    def test_tampered_event_record_package_corrupt(self):
        pkg = sealing.load_package(self.pkg_path)
        pkg["events"][0]["actor"] = "TAMPER"
        # 刷新文件指纹（仅为越过文件层校验），签名仍覆盖 events 故签名先失败；
        # 去掉签名校验干扰需重签——这里直接断言包级损坏，并在重签后定位到 record_hash
        p = self._write_pkg(pkg)
        r = self._verify(pkg_path=p)
        self.assertEqual(r["result"], "PACKAGE_CORRUPT")
        # 重签使签名/文件层通过，暴露出逐事件记录校验
        pkg["package_sig"] = sealing.seal_sign(
            self.cfg.seal_key, pkg["manifest"], pkg["proofs"])
        pkg["package_hash"] = sealing.sha256_hex(sealing._package_bytes(pkg))
        p = self._write_pkg(pkg, "mod_rec2.seal.json")
        r = self._verify(pkg_path=p)
        self.assertEqual(r["result"], "PACKAGE_CORRUPT")
        self.assertEqual(r["break_at"]["stage"], "record_hash")
        self.assertEqual(r["break_at"]["event_id"],
                         pkg["events"][0]["id"])

    def test_tampered_proof_package_corrupt(self):
        pkg = sealing.load_package(self.pkg_path)
        pkg["proofs"][-1]["proof"] = "f" * 64
        p = self._write_pkg(pkg)
        r = self._verify(pkg_path=p)
        self.assertEqual(r["result"], "PACKAGE_CORRUPT")

    def test_anchor_tamper_package_corrupt(self):
        pkg = sealing.load_package(self.pkg_path)
        pkg["manifest"]["last_summary"]["note"] = "x"
        pkg["manifest_hash"] = sealing.seal_manifest_hash(pkg["manifest"])
        # 重签 + 刷新文件指纹让签名/文件层通过，暴露出锚点校验
        pkg["package_sig"] = sealing.seal_sign(
            self.cfg.seal_key, pkg["manifest"], pkg["proofs"])
        pkg["package_hash"] = sealing.sha256_hex(sealing._package_bytes(pkg))
        p = self._write_pkg(pkg)
        r = self._verify(pkg_path=p)
        self.assertEqual(r["result"], "PACKAGE_CORRUPT")
        self.assertEqual(r["break_at"]["stage"], "anchor")

    def test_wrong_key_signature_corrupt(self):
        r = sealing.verify_offline(self.pkg_path, self.cfg.db_path,
                                   "a-different-key")
        self.assertEqual(r["result"], "PACKAGE_CORRUPT")
        self.assertEqual(r["break_at"]["stage"], "signature")

    def test_self_only_mode(self):
        pkg = sealing.load_package(self.pkg_path)
        r = sealing.verify_package_self(pkg, self.cfg.seal_key)
        self.assertEqual(r["result"], "OK")


class TestOnlineVerifyRecords(SealTestBase):
    def test_verify_online_ok_records_history(self):
        s = self.svc.request_seal("supervisor", 1, 2)
        r = self.svc.verify_seal_online("safety", s["seal_id"])
        self.assertEqual(r["result"], "OK")
        detail = self.svc.seal_detail(s["seal_id"])
        last = detail["history"][-1]
        self.assertEqual(last["kind"], "SEAL_VERIFICATION_RECORDED")
        self.assertEqual(last["detail"]["result"], "OK")

    def test_verify_failure_keeps_seal_immutable(self):
        s = self.svc.request_seal("supervisor", 1, self.max_id)
        sid = s["seal_id"]
        # 离线删除一条中间记录
        self.db.close()
        conn = sqlite3.connect(self.cfg.db_path)
        conn.execute("DELETE FROM events WHERE id=2")
        conn.commit()
        conn.close()
        # 重开服务（同库）后在线核验
        self.db = Storage(self.cfg.db_path)
        self.svc = CommandService(self.db, self.cfg)
        r = self.svc.verify_seal_online("safety", sid)
        self.assertIn(r["result"], ("DB_BEHIND", "HISTORY_MISMATCH"))
        row = self.db.get_seal_row(sid)
        self.assertEqual(row["status"], "SEALED")  # 核验失败不改封存
        self.assertTrue(os.path.exists(row["package_path"]))

    def test_verify_unsealed_rejected(self):
        row = self.db.insert_seal_request(
            {"seal_id": "SEAL-NOTYET", "from_id": 1, "to_id": 1,
             "created_by": "supervisor"}, self.svc.now())
        self.db.commit()
        with self.assertRaises(InvalidState):
            self.svc.verify_seal_online("safety", row["seal_id"])


class TestVerifyCli(SealTestBase):
    def test_cli_exit_codes(self):
        from dual_gateway.verify_seal import main
        s = self.svc.request_seal("supervisor", 1, self.max_id)
        self.db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.commit()
        # 干净：exit 0
        code = main([s["package_path"], self.cfg.db_path,
                     "--seal-key", self.cfg.seal_key, "--json"])
        self.assertEqual(code, 0)
        # 错密钥：exit 2
        code = main([s["package_path"], self.cfg.db_path,
                     "--seal-key", "wrong", "--json"])
        self.assertEqual(code, 2)
        # 自洽模式
        code = main([s["package_path"], "--self-only",
                     "--seal-key", self.cfg.seal_key, "--json"])
        self.assertEqual(code, 0)

    def test_cli_db_behind_exit_4(self):
        from dual_gateway.verify_seal import main
        s = self.svc.request_seal("supervisor", 1, self.max_id)
        self.db.close()
        conn = sqlite3.connect(self.cfg.db_path)
        conn.execute("DELETE FROM events WHERE id=%d" % self.max_id)
        conn.commit()
        conn.close()
        code = main([s["package_path"], self.cfg.db_path,
                     "--seal-key", self.cfg.seal_key, "--json"])
        self.assertEqual(code, 4)
        self.db = Storage(self.cfg.db_path)


if __name__ == "__main__":
    unittest.main()
