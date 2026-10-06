"""审计封存与离线核验单元测试（无 HTTP，直接驱动服务层与核验核心）。

覆盖：
  * 申请幂等：同一区间并发/重复申请只产生一份结果；
  * 生成：包内容（区间首尾/前序链头/末尾摘要/逐事件证明/整体摘要）；
  * 撤销边界：仅 PENDING 可撤销，已封存内容不得覆盖；
  * 崩溃恢复：SEALING 中断后续完同一份包或明确回滚为可重试，不留半成品；
  * 核验：包内损坏 / 前序历史不匹配 / 数据库落后于封存 / 库内容被改，
    全部定位首个断点；在线与离线命令结论一致。
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from io import StringIO

from dual_gateway import seal as seal_mod
from dual_gateway.config import load_config
from dual_gateway.errors import Conflict, InvalidState, NotFound
from dual_gateway.seal_verify import main as cli_main, verify_file
from dual_gateway.security import GENESIS_HASH, event_hash
from dual_gateway.service import CommandService
from dual_gateway.storage import Storage


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class SealTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.clock = Clock()
        self.cfg = load_config(
            db_path=os.path.join(self.tmp, "g.db"),
            seal_dir=os.path.join(self.tmp, "seals"),
            default_valid_seconds=100, confirm_timeout_seconds=50,
            offline_seconds=5)
        self.db = Storage(self.cfg.db_path)
        for d, k in self.cfg.device_keys.items():
            self.db.seed_device(d, k, self.clock())
        self.db.commit()
        self.svc = CommandService(self.db, self.cfg, clock=self.clock)

    def tearDown(self):
        self.db.close()

    def _make_events(self, n_commands=3):
        """产生一批审计事件，返回当前最大事件号。"""
        for _ in range(n_commands):
            c = self.svc.create_command(
                actor="ops", action="EMERGENCY_STOP", devices=["DEV-A1"],
                params={"rpm": 0})
            self.svc.confirm_command("supervisor", c["command_id"],
                                     c["confirm_code"], c["digest"])
        return self.db.max_event_id()

    def _sealed(self, from_id=1, to_id=None):
        to_id = to_id or self.db.max_event_id()
        out = self.svc.request_seal("supervisor", from_id, to_id)
        sid = out["seal"]["seal_id"]
        det = self.svc.generate_seal("supervisor", sid)
        return sid, det

    def _tamper(self, sql, args=()):
        self.db.conn.execute(sql, args)
        self.db.commit()


class TestSealRequest(SealTestBase):
    def test_request_creates_pending_and_validates_interval(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        self.assertFalse(out["duplicate"])
        self.assertEqual(out["seal"]["status"], "PENDING")
        self.assertEqual(out["seal"]["from_id"], 1)
        self.assertEqual(out["seal"]["to_id"], max_id)
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", 0, max_id)
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", max_id, 1)
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", 1, max_id + 100)
        with self.assertRaises(InvalidState):
            self.svc.request_seal("supervisor", "abc", max_id)

    def test_duplicate_request_returns_original(self):
        max_id = self._make_events(2)
        first = self.svc.request_seal("supervisor", 1, max_id)
        again = self.svc.request_seal("supervisor", 1, max_id)
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["seal"]["seal_id"], first["seal"]["seal_id"])
        # 已封存后重复申请仍返回原结果
        self.svc.generate_seal("supervisor", first["seal"]["seal_id"])
        third = self.svc.request_seal("supervisor", 1, max_id)
        self.assertTrue(third["duplicate"])
        self.assertEqual(third["seal"]["status"], "SEALED")
        # 不同区间是新的申请
        other = self.svc.request_seal("supervisor", 2, max_id)
        self.assertFalse(other["duplicate"])
        self.assertNotEqual(other["seal"]["seal_id"], first["seal"]["seal_id"])

    def test_concurrent_requests_single_result(self):
        max_id = self._make_events(2)
        results, errors = [], []

        def worker():
            try:
                results.append(self.svc.request_seal("supervisor", 1, max_id))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        seal_ids = {r["seal"]["seal_id"] for r in results}
        self.assertEqual(len(seal_ids), 1)          # 只产生一份封存结果
        self.assertEqual(sum(1 for r in results if not r["duplicate"]), 1)
        active = [s for s in self.svc.list_seals() if s["status"] != "CANCELLED"]
        self.assertEqual(len(active), 1)


class TestSealGenerate(SealTestBase):
    def test_package_contents(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(1, max_id)
        self.assertEqual(det["status"], "SEALED")
        pkg = det["package"]
        self.assertEqual(pkg["from_id"], 1)
        self.assertEqual(pkg["to_id"], max_id)
        self.assertEqual(pkg["event_count"], max_id)
        self.assertEqual(len(pkg["events"]), max_id)
        self.assertEqual(pkg["prev_hash"], GENESIS_HASH)       # 前序链头（创世）
        last = self.db.get_event(max_id)
        self.assertEqual(pkg["end_hash"], last["hash"])        # 末尾摘要
        self.assertEqual(pkg["events"][0]["prev_hash"], GENESIS_HASH)
        self.assertEqual(pkg["package_hash"], seal_mod.package_hash(pkg))
        # 落盘文件与登记一致
        on_disk = seal_mod.read_package(det["package_path"])
        self.assertEqual(on_disk["package_hash"], det["package_hash"])
        self.assertEqual(det["sealed_at"], det["sealed_at"])  # 字段存在

    def test_package_anchors_prior_chain_head(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(3, max_id)
        pkg = det["package"]
        prior = self.db.get_event(2)
        self.assertEqual(pkg["prev_hash"], prior["hash"])      # 前序链头
        self.assertEqual(pkg["events"][0]["id"], 3)

    def test_sealed_content_cannot_be_overwritten(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(1, max_id)
        with open(det["package_path"], encoding="utf-8") as f:
            content_before = f.read()
        # 已封存后再次生成/撤销都被拒，包文件与登记摘要不变
        with self.assertRaises(Conflict):
            self.svc.generate_seal("supervisor", sid)
        with self.assertRaises(Conflict):
            self.svc.cancel_seal("supervisor", sid)
        with open(det["package_path"], encoding="utf-8") as f:
            self.assertEqual(f.read(), content_before)
        row = self.svc.seal_detail(sid)
        self.assertEqual(row["package_hash"], det["package_hash"])

    def test_generate_missing_events_rolls_back_retryable(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        # 申请后数据库被离线删除一条事件：生成必须失败并回滚为可重试
        self._tamper("DELETE FROM events WHERE id=?", (max_id,))
        with self.assertRaises(InvalidState):
            self.svc.generate_seal("supervisor", sid)
        row = self.svc.seal_detail(sid)
        self.assertEqual(row["status"], "PENDING")   # 明确回滚，可重试
        self.assertTrue(row["last_error"])
        self.assertIn("SEAL_FAILED", [e["kind"] for e in row["history"]])
        self.assertFalse(os.path.exists(row["package_path"] or ""))  # 不留半成品


class TestSealCancel(SealTestBase):
    def test_cancel_only_pending(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        det = self.svc.cancel_seal("supervisor", sid, "区间选错了")
        self.assertEqual(det["status"], "CANCELLED")
        self.assertIn("SEAL_CANCELLED", [e["kind"] for e in det["history"]])
        with self.assertRaises(Conflict):
            self.svc.cancel_seal("supervisor", sid)  # 已撤销不能重复撤销
        # 撤销后同区间可重新申请（未产生过封存结果）
        again = self.svc.request_seal("supervisor", 1, max_id)
        self.assertFalse(again["duplicate"])
        self.assertNotEqual(again["seal"]["seal_id"], sid)

    def test_cancel_sealing_rejected(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        self.svc._seal_begin("supervisor", sid)      # 模拟已开始写包
        with self.assertRaises(Conflict):
            self.svc.cancel_seal("supervisor", sid)


class TestSealCrashRecovery(SealTestBase):
    def _restart(self):
        """模拟进程重启：在同一数据库上构造新的服务实例并跑恢复。"""
        self.clock.advance(1)
        svc = CommandService(self.db, self.cfg, clock=self.clock)
        return svc, svc.seal_startup_recovery()

    def test_crash_while_sealing_rolls_back_retryable(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        self.svc._seal_begin("supervisor", sid)      # 崩溃于 SEALING，无包文件
        svc, info = self._restart()
        self.assertEqual(info["rolled_back"], [sid])
        self.assertEqual(info["adopted"], [])
        row = svc.seal_detail(sid)
        self.assertEqual(row["status"], "PENDING")   # 可重试，不占永久锁
        self.assertIn("SEAL_ROLLBACK", [e["kind"] for e in row["history"]])
        det = svc.generate_seal("supervisor", sid)   # 重试成功
        self.assertEqual(det["status"], "SEALED")

    def test_crash_after_package_written_adopts_same_package(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        row = self.svc._seal_begin("supervisor", sid)
        pkg, path = self.svc._seal_build_and_write(row)  # 崩溃于登记之前
        self.assertTrue(os.path.exists(path))
        svc, info = self._restart()
        self.assertEqual(info["adopted"], [sid])         # 续完同一份包
        det = svc.seal_detail(sid)
        self.assertEqual(det["status"], "SEALED")
        self.assertEqual(det["package_hash"], pkg["package_hash"])
        self.assertIn("SEAL_ADOPTED", [e["kind"] for e in det["history"]])
        # 采纳的包与在线核验一致
        self.assertTrue(svc.verify_seal("supervisor", sid)["ok"])

    def test_crash_with_garbage_package_rolls_back(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        row = self.svc._seal_begin("supervisor", sid)
        # 崩溃留下一个内容不符的包文件（半成品/损坏）
        os.makedirs(self.cfg.seal_dir, exist_ok=True)
        with open(row["package_path"], "w", encoding="utf-8") as f:
            json.dump({"kind": "gw-audit-seal/v1", "garbage": True}, f)
        svc, info = self._restart()
        self.assertEqual(info["rolled_back"], [sid])
        self.assertFalse(os.path.exists(row["package_path"]))  # 半成品已清除
        self.assertEqual(svc.seal_detail(sid)["status"], "PENDING")

    def test_stray_tmp_file_cleaned(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        sid = out["seal"]["seal_id"]
        row = self.svc._seal_begin("supervisor", sid)
        tmp_file = row["package_path"] + ".tmp"
        os.makedirs(self.cfg.seal_dir, exist_ok=True)
        with open(tmp_file, "w") as f:
            f.write('{"partial":')                        # 写了一半的临时文件
        svc, info = self._restart()
        self.assertIn(sid, info["cleaned"])
        self.assertFalse(os.path.exists(tmp_file))
        self.assertEqual(svc.seal_detail(sid)["status"], "PENDING")


class TestSealVerify(SealTestBase):
    def test_verify_ok_and_history(self):
        max_id = self._make_events(2)
        sid, _ = self._sealed(1, max_id)
        res = self.svc.verify_seal("supervisor", sid)
        self.assertTrue(res["ok"])
        self.assertEqual(res["verdict"], "OK")
        self.assertEqual(res["checked"]["db_events_compared"], max_id)
        det = self.svc.seal_detail(sid)
        self.assertEqual(det["status"], "SEALED")
        self.assertIn("SEAL_VERIFY_OK", [e["kind"] for e in det["history"]])
        self.assertEqual(det["last_verify_ok"], 1)

    def test_db_diverged_locates_first_break(self):
        max_id = self._make_events(3)
        sid, _ = self._sealed(1, max_id)
        # 离线修改区间内两条记录：首个断点必须是较小的那个
        self._tamper("UPDATE events SET payload=? WHERE id IN (3, 5)",
                     ('{"hacked":true}',))
        res = self.svc.verify_seal("supervisor", sid)
        self.assertFalse(res["ok"])
        self.assertEqual(res["verdict"], "DB_DIVERGED")
        self.assertEqual(res["verdict_label"], "数据库内容与封存不符")
        self.assertEqual(res["first_break"]["event_id"], 3)
        det = self.svc.seal_detail(sid)
        self.assertEqual(det["status"], "VERIFY_FAILED")
        self.assertIn("SEAL_VERIFY_FAILED", [e["kind"] for e in det["history"]])
        # 修复后复核通过，状态回到 SEALED
        pkg = seal_mod.read_package(det["package_path"])
        orig = next(e for e in pkg["events"] if e["id"] == 3)
        self._tamper("UPDATE events SET payload=? WHERE id=3",
                     (json.dumps(orig["payload"], ensure_ascii=False,
                                 sort_keys=True),))
        self._tamper("UPDATE events SET payload=? WHERE id=5",
                     (json.dumps(next(e for e in pkg["events"] if e["id"] == 5)
                                 ["payload"], ensure_ascii=False, sort_keys=True),))
        res2 = self.svc.verify_seal("supervisor", sid)
        self.assertTrue(res2["ok"])
        self.assertEqual(self.svc.seal_detail(sid)["status"], "SEALED")

    def test_db_lagging_when_middle_record_deleted(self):
        max_id = self._make_events(3)
        sid, _ = self._sealed(1, max_id)
        self._tamper("DELETE FROM events WHERE id=4")     # 删除中间记录
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "DB_LAGGING")
        self.assertEqual(res["verdict_label"], "数据库落后于封存")
        self.assertEqual(res["first_break"]["event_id"], 4)

    def test_db_lagging_when_truncated(self):
        max_id = self._make_events(3)
        sid, _ = self._sealed(1, max_id)
        self._tamper("DELETE FROM events WHERE id>=?", (max_id - 1,))  # 库被回滚
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "DB_LAGGING")
        self.assertEqual(res["first_break"]["event_id"], max_id - 1)

    def test_prior_history_mismatch_on_tamper(self):
        max_id = self._make_events(3)
        sid, _ = self._sealed(3, max_id)                  # 前序为事件 1..2
        self._tamper("UPDATE events SET payload=? WHERE id=1", ('{"x":1}',))
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "PRIOR_HISTORY_MISMATCH")
        self.assertEqual(res["verdict_label"], "前序历史不匹配")
        self.assertEqual(res["first_break"]["event_id"], 1)

    def test_prior_history_mismatch_on_swapped_history(self):
        max_id = self._make_events(3)
        sid, _ = self._sealed(3, max_id)
        # 整库被换成另一份自洽的历史
        self._tamper("DELETE FROM events")
        prev = GENESIS_HASH
        for i in range(1, max_id + 1):
            payload = {"forged": i}
            h = event_hash(prev, "FORGED", payload)
            self._tamper(
                "INSERT INTO events(id,ts,actor,channel,action,command_id,"
                "device_id,payload,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (i, 1000.0, "mallory", "SYSTEM", "FORGED", None, None,
                 json.dumps(payload), prev, h))
            prev = h
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "PRIOR_HISTORY_MISMATCH")
        self.assertEqual(res["first_break"]["event_id"], 2)  # 链头锚点

    def test_package_corrupt_locates_first_break(self):
        max_id = self._make_events(3)
        sid, det = self._sealed(1, max_id)
        pkg = seal_mod.read_package(det["package_path"])
        pkg["events"][2]["payload"] = {"tampered": True}   # 改包内第三条
        with open(det["package_path"], "w", encoding="utf-8") as f:
            json.dump(pkg, f, ensure_ascii=False, indent=2, sort_keys=True)
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "PACKAGE_CORRUPT")
        self.assertEqual(res["verdict_label"], "包内损坏")
        self.assertEqual(res["first_break"]["event_id"], 3)

    def test_package_end_summary_tampered(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(1, max_id)
        pkg = seal_mod.read_package(det["package_path"])
        pkg["end_hash"] = "0" * 64
        with open(det["package_path"], "w", encoding="utf-8") as f:
            json.dump(pkg, f, ensure_ascii=False, indent=2, sort_keys=True)
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "PACKAGE_CORRUPT")
        self.assertEqual(res["first_break"]["event_id"], max_id)

    def test_package_missing_file(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(1, max_id)
        os.remove(det["package_path"])
        res = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(res["verdict"], "PACKAGE_CORRUPT")
        self.assertIn("缺失", res["first_break"]["reason"])

    def test_verify_requires_sealed(self):
        max_id = self._make_events(2)
        out = self.svc.request_seal("supervisor", 1, max_id)
        with self.assertRaises(InvalidState):
            self.svc.verify_seal("supervisor", out["seal"]["seal_id"])
        with self.assertRaises(NotFound):
            self.svc.verify_seal("supervisor", "SEAL-NOPE")


class TestOfflineCommand(SealTestBase):
    """独立核验命令：与在线核验同一逻辑，直接读包文件与库文件。"""

    def _cli(self, *args) -> int:
        with redirect_stdout(StringIO()):
            return cli_main(list(args))

    def test_offline_ok_and_exit_code(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(1, max_id)
        res = verify_file(det["package_path"], self.cfg.db_path)
        self.assertTrue(res["ok"])
        self.assertEqual(self._cli(det["package_path"], "--db",
                                   self.cfg.db_path, "--json"), 0)

    def test_offline_matches_online_verdicts(self):
        max_id = self._make_events(3)
        sid, det = self._sealed(1, max_id)
        path = det["package_path"]
        # 1) 库内篡改
        self._tamper("UPDATE events SET payload=? WHERE id=2", ('{"h":1}',))
        off = verify_file(path, self.cfg.db_path)
        onl = self.svc.verify_seal("supervisor", sid)
        self.assertEqual(off["verdict"], "DB_DIVERGED")
        self.assertEqual(onl["verdict"], "DB_DIVERGED")
        self.assertEqual(off["first_break"], onl["first_break"])
        self.assertEqual(self._cli(path, "--db", self.cfg.db_path, "--json"), 1)
        # 2) 删除中间记录
        self._tamper("DELETE FROM events WHERE id=4")
        off = verify_file(path, self.cfg.db_path)
        self.assertEqual(off["verdict"], "DB_LAGGING")
        self.assertEqual(off["first_break"]["event_id"], 4)
        # 3) 包损坏
        pkg = seal_mod.read_package(path)
        pkg["prev_hash"] = "f" * 64
        with open(path, "w", encoding="utf-8") as f:
            json.dump(pkg, f, ensure_ascii=False, indent=2, sort_keys=True)
        off = verify_file(path, self.cfg.db_path)
        self.assertEqual(off["verdict"], "PACKAGE_CORRUPT")

    def test_offline_missing_db_is_lagging(self):
        max_id = self._make_events(2)
        sid, det = self._sealed(1, max_id)
        res = verify_file(det["package_path"],
                          os.path.join(self.tmp, "no-such.db"))
        self.assertFalse(res["ok"])
        self.assertEqual(res["verdict"], "DB_LAGGING")
        self.assertIn("db_error", res)


if __name__ == "__main__":
    unittest.main()
