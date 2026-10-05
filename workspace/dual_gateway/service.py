"""核心领域服务：全部安全不变量在这里收口。

线程模型：HTTP 三通道 + 后台清扫线程并发访问，所有公共方法在同一把
可重入锁内执行；每个“事件 + 状态变更”在一个 SQLite 事务内提交，
保证审计与状态要么同时生效、要么都不生效。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any, Callable, Optional

from . import models as M
from .errors import (Conflict, DeviceRejected, FrozenMismatch, InvalidReceipt,
                     InvalidState, NotFound)
from .security import (canonical_json, digest_payload, hash_confirm_code,
                       ledger_anchor, ledger_book_hash, ledger_entry_hash,
                       ledger_signature_valid, new_confirm_code)
from .storage import Storage


def _new_incident_id() -> str:
    return "INC-" + uuid.uuid4().hex[:12].upper()


def _cmd_dict(row: dict) -> dict:
    return {
        "command_id": row["command_id"],
        "action": row["action"],
        "devices": json.loads(row["device_set"]),
        "params": json.loads(row["params"]),
        "digest": row["digest"],
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "confirm_deadline": row["confirm_deadline"],
        "status": row["status"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "confirmed_by": row["confirmed_by"],
        "confirmed_at": row["confirmed_at"],
        "revoked_by": row["revoked_by"],
        "revoked_at": row["revoked_at"],
        "reject_reason": row["reject_reason"],
    }


class CommandService:
    def __init__(self, storage: Storage, config, clock: Callable[[], float] = time.time):
        self.db = storage
        self.cfg = config
        self.now = clock
        self._lock = threading.RLock()

    # ================= 业务通道：创建 / 查询 / 撤销 =================
    def create_command(self, actor: str, action: str, devices: list[str],
                       params: dict[str, Any],
                       valid_seconds: Optional[int] = None) -> dict:
        """高风险指令创建：冻结设备集合、参数摘要与有效窗口。

        返回体里的 confirm_code 只出现这一次明文——业务系统应把它交给
        独立带外通道（语音/短信/硬令牌）送达第二角色，服务端只存哈希。
        """
        with self._lock:
            now = self.now()
            if not action or not isinstance(action, str):
                raise InvalidState("action 不能为空")
            if not devices:
                raise InvalidState("devices 不能为空")
            devices = sorted(set(devices))
            unknown = [d for d in devices if not self.db.get_device(d)]
            if unknown:
                raise NotFound(f"未注册设备: {unknown}", details={"unknown": unknown})
            if not isinstance(params, dict):
                raise InvalidState("params 必须是对象")

            valid_seconds = valid_seconds or self.cfg.default_valid_seconds
            if valid_seconds <= 0:
                raise InvalidState("有效窗口必须为正")
            valid_from = now
            valid_to = now + valid_seconds
            confirm_deadline = min(valid_to, now + self.cfg.confirm_timeout_seconds)
            command_id = "CMD-" + uuid.uuid4().hex[:12].upper()
            code = new_confirm_code()

            frozen = {
                "action": action,
                "devices": devices,
                "params": params,
                "valid_from": valid_from,
                "valid_to": valid_to,
            }
            row = {
                "command_id": command_id,
                "action": action,
                "params": params,
                "digest": digest_payload(frozen),
                "valid_from": valid_from,
                "valid_to": valid_to,
                "confirm_deadline": confirm_deadline,
                "status": M.CMD_PENDING,
                "confirm_code_hash": hash_confirm_code(code),
                "created_by": actor,
            }
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_BIZ, "CMD_CREATED",
                    {"command_id": command_id, "frozen": {
                        **frozen, "params": json.loads(canonical_json(params))},
                     "digest": row["digest"], "confirm_deadline": confirm_deadline},
                    command_id=command_id)
                self.db.insert_command(row, devices, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {**_cmd_dict(self.db.get_command_row(command_id)),
                    "confirm_code": code}

    def get_command(self, command_id: str) -> dict:
        with self._lock:
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            out = _cmd_dict(row)
            out["targets"] = [self._target_view(t) for t in self.db.list_targets(command_id)]
            return out

    def list_commands(self, status: Optional[str] = None, limit: int = 100) -> list[dict]:
        with self._lock:
            return [_cmd_dict(r) for r in self.db.list_commands(limit, status)]

    def revoke_command(self, actor: str, command_id: str, reason: str = "") -> dict:
        """撤销。硬约束：任何设备一旦形成执行事实（或指令已在途不可证明未执行），
        撤销一律拒绝——已执行事实不能被撤销覆盖；在途目标必须先对账。"""
        with self._lock:
            now = self.now()
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            status = row["status"]
            targets = self.db.list_targets(command_id)
            executed = [t["device_id"] for t in targets if t["status"] in (M.TGT_EXECUTED, M.TGT_FAILED)]
            inflight = [t["device_id"] for t in targets if t["status"] in (M.TGT_DISPATCHED, M.TGT_DOUBT)]

            if executed:
                raise Conflict(
                    "存在已执行回执，已执行事实不可撤销",
                    details={"executed": executed})
            if status in (M.CMD_EXECUTED, M.CMD_PARTIAL_FAILED, M.CMD_CLOSED):
                raise Conflict("指令已终结，不可撤销", details={"status": status})
            if status in (M.CMD_REVOKED, M.CMD_REJECTED, M.CMD_EXPIRED):
                raise Conflict("指令已终结，不可重复撤销", details={"status": status})
            if inflight:
                # 已投递给现场设备：无法保证设备没有执行，必须等设备账本对账，
                # 绝不能用“撤销”把在途指令一笔勾销后又重投。
                raise Conflict(
                    "指令已下发在途，需设备重连对账后处理，禁止直接撤销",
                    details={"inflight": inflight})

            # PENDING 或 CONFIRMED 且所有目标仍 PENDING：指令从未到达任何设备
            assert all(t["status"] == M.TGT_PENDING for t in targets)
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_BIZ, "CMD_REVOKED",
                    {"command_id": command_id, "reason": reason},
                    command_id=command_id)
                self.db.mark_revoked(command_id, actor, now)
                self.db.conn.execute(
                    "UPDATE targets SET status='SKIPPED',updated_at=? "
                    "WHERE command_id=? AND status='PENDING'", (now, command_id))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_command(command_id)

    # ================= 安全通道：第二角色确认 / 拒绝 =================
    def confirm_command(self, actor: str, command_id: str, code: str,
                        digest_ack: str) -> dict:
        """第二角色确认。三重独立证据缺一不可：

        1. 已登录的安全通道会话（独立口令，见 web 层）；
        2. 带外送达的 6 位确认码（不经过业务通道）；
        3. 第二角色亲眼复核冻结摘要并回传（防创建页/工作台内容被调包）。
        """
        with self._lock:
            now = self.now()
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            if row["status"] != M.CMD_PENDING:
                raise InvalidState("仅待确认指令可确认", details={"status": row["status"]})
            if now > row["confirm_deadline"]:
                # 懒清扫：即使后台线程没跑到，也绝不放行超时确认
                self._expire_one(row, now)
                raise InvalidState("确认超时，指令已冻结为 EXPIRED")
            import hmac as _hmac
            if not _hmac.compare_digest(hash_confirm_code(code or ""), row["confirm_code_hash"]):
                self._sec_event("CONFIRM_DENIED", actor, command_id,
                                {"reason": "BAD_CODE"})
                raise FrozenMismatch("确认码错误")
            if not digest_ack or not _hmac.compare_digest(digest_ack, row["digest"]):
                self._sec_event("CONFIRM_DENIED", actor, command_id,
                                {"reason": "DIGEST_MISMATCH"})
                raise FrozenMismatch("冻结摘要复核不一致，拒绝确认（内容可能已被调包）")
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_SEC, "CMD_CONFIRMED",
                    {"command_id": command_id, "digest": row["digest"]},
                    command_id=command_id)
                self.db.mark_confirmed(command_id, actor, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_command(command_id)

    def reject_command(self, actor: str, command_id: str, reason: str) -> dict:
        with self._lock:
            now = self.now()
            row = self.db.get_command_row(command_id)
            if not row:
                raise NotFound("指令不存在")
            if row["status"] != M.CMD_PENDING:
                raise InvalidState("仅待确认指令可拒绝", details={"status": row["status"]})
            if now > row["confirm_deadline"]:
                self._expire_one(row, now)
                raise InvalidState("确认超时，指令已冻结为 EXPIRED")
            try:
                self.db.append_event(
                    now, actor, M.AUDIT_SEC, "CMD_REJECTED",
                    {"command_id": command_id, "reason": reason},
                    command_id=command_id)
                self.db.mark_rejected(command_id, reason or "第二角色拒绝", now)
                self.db.conn.execute(
                    "UPDATE targets SET status='SKIPPED',updated_at=? "
                    "WHERE command_id=? AND status='PENDING'", (now, command_id))
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.get_command(command_id)

    def _sec_event(self, action: str, actor: str, command_id: str, payload: dict):
        try:
            self.db.append_event(self.now(), actor, M.AUDIT_SEC, action, payload,
                                 command_id=command_id)
            self.db.commit()
        except Exception:
            self.db.rollback()

    def _expire_one(self, row: dict, now: float):
        try:
            self.db.append_event(
                now, "system", M.AUDIT_SYS, "CMD_EXPIRED",
                {"command_id": row["command_id"], "reason": "CONFIRM_TIMEOUT"},
                command_id=row["command_id"])
            self.db.conn.execute(
                "UPDATE commands SET status='EXPIRED' WHERE command_id=? AND status='PENDING'",
                (row["command_id"],))
            self.db.conn.execute(
                "UPDATE targets SET status='SKIPPED',updated_at=? "
                "WHERE command_id=? AND status='PENDING'",
                (now, row["command_id"]))
            self.db.commit()
        except Exception:
            self.db.rollback()

    # ================= 设备通道：握手 / 心跳 / 拉取 / 回执 =================
    def hello(self, device_id: str, boot_code: str, first_seq: int = 1,
              ledger: Optional[list[dict]] = None,
              ledger_sig: Optional[str] = None) -> dict:
        """设备（重新）上线握手。

        设备每次启动生成新 boot_code 并带上**带独立签名的持久账簿**：账簿是设备
        本地“执行事实”的权威来源（设备在执行前先落盘再上送回执）。网关独立校验：

        1. 整册签名 HMAC（设备预置密钥，独立于传输层签名）；
        2. 代次（boot_code 须为网关节过的启动代号，旧/未知代次材料隔离）；
        3. 单调编号（同代次内 seq 严格 +1，缺口/复用即断链）；
        4. 指令指纹（条目冻结摘要必须与指令创建时摘要一致）；
        5. 连续性（prev 哈希须接代次锚点/上一条目）。

        全部通过才补记既成执行；仅当设备已重启（换代号）、账簿无该指令且原时限
        仍有效时才重新派发。坏签名整册隔离且**绝不重投**（fail-closed）。
        同一册重复上送按幂等回放，不重复补记/隔离/派发。
        """
        with self._lock:
            now = self.now()
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")
            if not boot_code or first_seq < 1:
                raise DeviceRejected("boot_code / first_seq 非法")

            known = self.db.boot_known(device_id, boot_code)
            if known and known["first_seq"] != first_seq:
                raise DeviceRejected(
                    "同一起动代号声明了不同起始序号，疑似伪造",
                    details={"known": known["first_seq"], "got": first_seq})
            rebooted = dev["current_boot"] is not None and dev["current_boot"] != boot_code
            entries = ledger or []
            # 幂等键纳入本次 HELLO 的启动代号：同一设备同代次重连同册才视为重复，
            # 不同代次的空账簿重连是不同的对账动作，不能被空内容常量哈希误判
            book_hash = ledger_book_hash(
                [{"hello_boot": boot_code, "entries": entries}])
            duplicate = self.db.ledger_upload_seen(device_id, book_hash)
            summary = {"duplicate": bool(duplicate), "entries": len(entries),
                       "sig_valid": True, "accepted": [], "quarantined": []}
            try:
                self.db.know_boot(device_id, boot_code, first_seq, now)
                self.db.mark_online(device_id, boot_code, first_seq, now)
                self.db.append_event(
                    now, device_id, M.AUDIT_DEV, "DEVICE_HELLO",
                    {"boot_code": boot_code, "first_seq": first_seq,
                     "rebooted": rebooted, "ledger_entries": len(entries),
                     "ledger_duplicate": bool(duplicate)},
                    device_id=device_id)

                if duplicate:
                    # 同册重复上送：幂等回放，不重复补记、不重复隔离、不重复派发
                    summary["sig_valid"] = bool(duplicate["sig_valid"])
                elif entries:
                    sig_ok = ledger_signature_valid(dev["preshared_key"],
                                                    entries, ledger_sig or "")
                    self.db.record_ledger_upload(device_id, book_hash, boot_code,
                                                 sig_ok, len(entries), now)
                    if not sig_ok:
                        summary["sig_valid"] = False
                        summary["quarantined"] = \
                            self._quarantine_book_bad_signature(
                                device_id, entries, book_hash, now)
                        # fail-closed：坏签名不进入重投判断
                    else:
                        accepted, quarantined = self._reconcile_ledger(
                            device_id, entries, book_hash, now)
                        summary["accepted"] = accepted
                        summary["quarantined"] = quarantined
                        # fail-closed：存在任何被隔离的矛盾/缺口材料时，不得
                        # 仅凭“账簿没提到该指令”判定未执行而重投，保持 DOUBT
                        if not quarantined:
                            self._recover_undelivered(device_id, boot_code, now)
                else:
                    # 空账簿：设备声明相关代次下无执行事实
                    self.db.record_ledger_upload(device_id, book_hash, boot_code,
                                                 True, 0, now)
                    self._recover_undelivered(device_id, boot_code, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"device_id": device_id, "online": True, "boot_code": boot_code,
                    "rebooted": rebooted, "ledger": summary}

    def _quarantine_book_bad_signature(self, device_id: str, entries: list[dict],
                                       book_hash: str, now: float) -> list[dict]:
        """整册签名无效：每条材料隔离留痕，不采信、不补记、不触发重投。"""
        q = []
        for e in entries:
            q.append(self._quarantine_entry(device_id, e, M.Q_SIGNATURE,
                                            book_hash, now))
        self.db.append_event(
            now, device_id, M.AUDIT_DEV, "LEDGER_SIGNATURE_INVALID",
            {"upload_hash": book_hash, "entries": len(entries)},
            device_id=device_id)
        return q

    def _quarantine_entry(self, device_id: str, e: dict, reason: str,
                          book_hash: str, now: float,
                          incident: Optional[dict] = None) -> dict:
        """把一条问题材料隔离留痕；若属于某张未结工单，同时写入其处置历史。"""
        boot = e.get("boot_code") if isinstance(e, dict) else None
        seq = _safe_int(e.get("seq")) if isinstance(e, dict) else None
        cid = e.get("command_id") if isinstance(e, dict) else None
        inc = incident or (self.db.get_open_incident(cid, device_id) if cid else None)
        self.db.insert_quarantine(
            device_id, reason, e, now, boot_code=boot, seq=seq, command_id=cid,
            incident_id=inc["incident_id"] if inc else None, upload_hash=book_hash)
        if inc:
            self.db.add_incident_event(
                inc["incident_id"], now, device_id, M.IEV_QUARANTINE,
                {"reason": reason, "boot_code": boot, "seq": seq, "command_id": cid})
        return {"boot_code": boot, "seq": seq, "command_id": cid, "reason": reason}

    def _reconcile_ledger(self, device_id: str, ledger: list[dict],
                          book_hash: str, now: float
                          ) -> tuple[list[dict], list[dict]]:
        """用设备签名账簿恢复执行事实。五重校验不过只隔离，绝不改既有状态。"""
        accepted, quarantined = [], []

        # 按代次分组（保留设备写入顺序）；每个代次独立是一条 prev 哈希链
        groups: dict[str, list[dict]] = {}
        for e in ledger:
            groups.setdefault(e.get("boot_code", "") if isinstance(e, dict) else "",
                              []).append(e)
        known_boots = [(self.db.boot_known(device_id, b), b) for b in groups]
        known_boots.sort(key=lambda kb: kb[0]["first_seq"] if kb[0] else 10**12)

        for known, boot in known_boots:
            entries = sorted(groups[boot],
                             key=lambda e: int(e.get("seq", 0) or 0)
                             if isinstance(e, dict) else 0)
            if not known:
                # 未知/旧代次材料：不得影响任何当前状态
                for e in entries:
                    quarantined.append(
                        self._quarantine_entry(device_id, e, M.Q_UNKNOWN_BOOT,
                                               book_hash, now))
                continue

            expected_seq = int(known["first_seq"])
            expected_prev = ledger_anchor(device_id, boot, expected_seq)
            chain_broken = False
            for e in entries:
                seq = _safe_int(e.get("seq")) if isinstance(e, dict) else None
                cid = e.get("command_id", "") if isinstance(e, dict) else ""
                result = e.get("result", "") if isinstance(e, dict) else ""
                digest = e.get("digest") if isinstance(e, dict) else None
                prev = e.get("prev") if isinstance(e, dict) else None

                def _isolate(reason: str, *, break_chain: bool = True):
                    nonlocal chain_broken
                    quarantined.append(
                        self._quarantine_entry(device_id, e, reason, book_hash, now))
                    if break_chain:
                        chain_broken = True

                if chain_broken:
                    # 链在缺口/复用/断链处失效，其后同代次材料一律不可信
                    _isolate(M.Q_BROKEN_CHAIN, break_chain=False)
                    continue
                # 1) 结构合法
                if (not isinstance(e, dict) or not isinstance(seq, int) or seq < 1
                        or not isinstance(cid, str) or not cid
                        or result not in (M.RESULT_EXECUTED, M.RESULT_FAILED)
                        or not isinstance(digest, str) or not digest
                        or not isinstance(prev, str)):
                    _isolate(M.Q_BAD_ENTRY)
                    continue
                # 2) 单调编号：严格 +1
                if seq > expected_seq:
                    _isolate(M.Q_GAP)
                    continue
                if seq < expected_seq:
                    _isolate(M.Q_SEQ_REUSE)
                    continue
                # 3) 连续性：prev 必须接代次锚点 / 上一条目
                if prev != expected_prev:
                    _isolate(M.Q_BROKEN_CHAIN)
                    continue

                tgt = self.db.get_target(cid, device_id)
                cmd = self.db.get_command_row(cid) if tgt else None
                # 4) 目标与指令指纹
                if not tgt or not cmd:
                    self.db.insert_rejected(device_id, boot, seq,
                                            "LEDGER_NEVER_DISPATCHED", e, now)
                    _isolate(M.Q_NEVER_DISPATCHED, break_chain=False)
                    expected_prev = ledger_entry_hash(device_id, e)
                    expected_seq += 1
                    continue
                inc = self.db.get_open_incident(cid, device_id)
                if digest != cmd["digest"]:
                    _isolate(M.Q_FINGERPRINT, break_chain=False)
                    expected_prev = ledger_entry_hash(device_id, e)
                    expected_seq += 1
                    continue
                existing = self.db.get_receipt(cid, device_id)
                if existing:
                    if existing["result"] != result:
                        # 与已确认执行事实矛盾：事实不可覆盖，矛盾材料仅隔离
                        self.db.insert_rejected(device_id, boot, seq,
                                                "LEDGER_FACT_CONFLICT", e, now)
                        _isolate(M.Q_FACT_CONFLICT, break_chain=False)
                    else:
                        accepted.append({"command_id": cid, "result": result,
                                         "duplicate": True})
                    expected_prev = ledger_entry_hash(device_id, e)
                    expected_seq += 1
                    continue
                # 5) 目标状态防线
                if tgt["status"] == M.TGT_SKIPPED:
                    _isolate(M.Q_STATE_SKIPPED, break_chain=False)
                elif tgt["status"] == M.TGT_MISSED:
                    # 过期时限：即使账簿声称执行过，也只隔离留痕，
                    # 不得把已按未达关闭的目标改成执行事实
                    _isolate(M.Q_WINDOW_EXPIRED, break_chain=False)
                elif tgt["status"] == M.TGT_PENDING:
                    self.db.insert_rejected(device_id, boot, seq,
                                            "LEDGER_NEVER_DISPATCHED", e, now)
                    _isolate(M.Q_NEVER_DISPATCHED, break_chain=False)
                elif tgt["dispatched_boot"] not in (None, boot):
                    # 条目代次与实际投递代次不符：旧代次材料
                    self.db.insert_rejected(device_id, boot, seq,
                                            "LEDGER_BOOT_MISMATCH", e, now)
                    _isolate(M.Q_BOOT_MISMATCH, break_chain=False)
                elif now >= cmd["valid_to"]:
                    # 原有效时限已过：账簿材料只能隔离留痕，既不补记执行事实，
                    # 也不再据此改变目标状态（等安全角色人工处置）
                    _isolate(M.Q_WINDOW_EXPIRED, break_chain=False)
                else:
                    # —— 五重校验全部通过：补记既成执行（不可变事实）——
                    status = (M.TGT_EXECUTED if result == M.RESULT_EXECUTED
                              else M.TGT_FAILED)
                    entry_h = ledger_entry_hash(device_id, e)
                    event_id = self.db.append_event(
                        now, device_id, M.AUDIT_DEV, "LEDGER_RECOVERY",
                        {"command_id": cid, "boot_code": boot, "seq": seq,
                         "result": result, "message": e.get("message", ""),
                         "digest": digest, "entry_hash": entry_h,
                         "prev_hash": prev},
                        command_id=cid, device_id=device_id)
                    ok = self.db.insert_receipt({
                        "command_id": cid, "device_id": device_id, "boot_code": boot,
                        "seq": seq, "result": result, "message": e.get("message", ""),
                        "source": M.SRC_LEDGER, "event_id": event_id,
                        "received_at": now, "entry_hash": entry_h, "prev_hash": prev})
                    if ok:
                        self.db.settle_target(cid, device_id, status, now)
                        self.db.advance_ledger_head(device_id, seq)
                        accepted.append({"command_id": cid, "result": result})
                        self._recompute(cid, now)
                        if inc:
                            self.db.add_incident_event(
                                inc["incident_id"], now, device_id, M.IEV_EVIDENCE,
                                {"command_id": cid, "boot_code": boot, "seq": seq,
                                 "result": result, "digest": digest,
                                 "entry_hash": entry_h, "source": M.SRC_LEDGER},
                                audit_event_id=event_id)
                            self.db.resolve_incident(
                                inc["incident_id"], M.INC_RECOVERED,
                                f"LEDGER:{result}", now)
                expected_prev = ledger_entry_hash(device_id, e)
                expected_seq += 1

        self.db.append_event(
            now, device_id, M.AUDIT_DEV, "LEDGER_RECONCILED",
            {"upload_hash": book_hash,
             "accepted": accepted, "quarantined": quarantined},
            device_id=device_id)
        return accepted, quarantined

    def _recover_undelivered(self, device_id: str, current_boot: str, now: float):
        """重启/重连后处理仍悬而未决的目标（仅在签名账簿已通过校验后调用）。

        * 同一启动代号下仍在途 → 保持 DOUBT，等回执（账簿未提到它，可能正在
          执行，重投会双触发）；
        * 设备已重启（代号变化）且账簿无该指令 → 未执行确定：原时限仍有效则
          重置为 PENDING 重新派发；时限已过则保持 DOUBT、工单 OPEN，
          不补发也不判死，等待安全角色人工按未达关闭。
        """
        rows = self.db.conn.execute(
            "SELECT t.* FROM targets t JOIN commands c ON c.command_id=t.command_id "
            "WHERE t.device_id=? AND t.status='DOUBT'", (device_id,)).fetchall()
        for r in rows:
            t = dict(r)
            if t["dispatched_boot"] == current_boot:
                continue  # 同代号，执行与否未知，继续等回执
            if self.db.get_receipt(t["command_id"], device_id):
                continue  # 账簿阶段已补记
            cmd = self.db.get_command_row(t["command_id"])
            inc = self.db.get_open_incident(t["command_id"], device_id)
            if now < cmd["valid_to"] and cmd["status"] in (M.CMD_CONFIRMED,):
                self.db.reset_to_pending(t["command_id"], device_id, now)
                event_id = self.db.append_event(
                    now, device_id, M.AUDIT_SYS, "REDELIVER_AFTER_REBOOT",
                    {"command_id": t["command_id"], "old_boot": t["dispatched_boot"],
                     "new_boot": current_boot},
                    command_id=t["command_id"], device_id=device_id)
                if inc:
                    self.db.add_incident_event(
                        inc["incident_id"], now, "system", M.IEV_REDELIVER,
                        {"old_boot": t["dispatched_boot"], "new_boot": current_boot,
                         "valid_to": cmd["valid_to"]}, audit_event_id=event_id)
                    self.db.resolve_incident(
                        inc["incident_id"], M.INC_REDELIVERED,
                        "AUTO_AFTER_REBOOT", now)
            else:
                # 窗口已过/指令终结：不能补发，也不擅自判死为未执行。
                # 保持 DOUBT、工单 OPEN，等安全角色取得现场结论后人工按未达关闭。
                if inc:
                    self.db.add_incident_event(
                        inc["incident_id"], now, "system", M.IEV_QUARANTINE,
                        {"reason": M.Q_WINDOW_EXPIRED,
                         "detail": "设备已换代次但原时限失效，无法重新派发，"
                                   "保持 DOUBT 等待人工处置",
                         "cmd_status": cmd["status"]})
                    self.db.touch_incident(inc["incident_id"], now)

    def heartbeat(self, device_id: str, boot_code: str) -> dict:
        with self._lock:
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")
            now = self.now()
            if not self.db.heartbeat(device_id, boot_code, now):
                # 旧启动代号的心跳：设备疑似重启后的残影/伪造，不改在线状态
                self.db.append_event(
                    now, device_id, M.AUDIT_DEV, "HEARTBEAT_STALE_BOOT",
                    {"got": boot_code, "current": dev["current_boot"]},
                    device_id=device_id)
                self.db.commit()
                raise DeviceRejected("旧启动代号心跳被拒绝")
            self.db.commit()
            return {"ok": True}

    def pull(self, device_id: str, boot_code: str) -> dict:
        """设备拉取已确认且窗口内的指令。离线设备/旧代号一律不给指令。"""
        with self._lock:
            now = self.now()
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")
            if not dev["online"] or dev["current_boot"] != boot_code:
                raise DeviceRejected("握手失效或启动代号不匹配，请先 HELLO")
            rows = self.db.pending_for_device(device_id, now)
            delivered = []
            try:
                for r in rows:
                    if self.db.mark_dispatched(r["command_id"], device_id, boot_code, now):
                        self.db.append_event(
                            now, device_id, M.AUDIT_DEV, "COMMAND_DISPATCHED",
                            {"command_id": r["command_id"], "boot_code": boot_code,
                             "digest": r["digest"]},
                            command_id=r["command_id"], device_id=device_id)
                        delivered.append({
                            "command_id": r["command_id"],
                            "action": r["action"],
                            "params": json.loads(r["params"]),
                            "digest": r["digest"],
                            "valid_to": r["valid_to"],
                        })
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"device_id": device_id, "boot_code": boot_code,
                    "commands": delivered}

    def receipt(self, device_id: str, boot_code: str, seq: int,
                command_id: str, result: str, message: str = "") -> dict:
        """处理设备回执。核心防线：

        * 旧启动代号：拒绝（重启前的残影不得改变当前状态）；
        * 序号必须严格 +1：乱序/跳号拒绝，重复序号按幂等回放处理；
        * 网关未投递 / 已撤销过期 / 已有不同终态事实：拒绝且不改状态；
        * 一旦接受，执行事实唯一且不可被后续任何操作覆盖。
        """
        with self._lock:
            now = self.now()
            dev = self.db.get_device(device_id)
            if not dev:
                raise NotFound("设备未注册")

            def _reject(reason: str):
                try:
                    self.db.insert_rejected(device_id, boot_code, _safe_int(seq),
                                            reason,
                                            {"boot_code": boot_code, "seq": seq,
                                             "command_id": command_id, "result": result},
                                            now)
                    self.db.append_event(
                        now, device_id, M.AUDIT_DEV, "RECEIPT_REJECTED",
                        {"reason": reason, "boot_code": boot_code, "seq": seq,
                         "command_id": command_id, "result": result},
                        command_id=command_id, device_id=device_id)
                    self.db.commit()
                except Exception:
                    self.db.rollback()
                raise InvalidReceipt(f"回执被拒绝: {reason}", details={"reason": reason})

            if dev["current_boot"] != boot_code:
                _reject("STALE_BOOT")
            try:
                seq = int(seq)
            except (TypeError, ValueError):
                _reject("BAD_SEQ")
            if result not in (M.RESULT_EXECUTED, M.RESULT_FAILED):
                _reject("BAD_RESULT")

            head = dev["ledger_head_seq"] if dev["ledger_head_seq"] is not None else 0
            expected = head + 1

            # 幂等回放 / 序号复用
            prior = self.db.find_receipt_by_seq(device_id, boot_code, seq) if hasattr(
                self.db, "find_receipt_by_seq") else None
            if seq < expected:
                if prior and prior["command_id"] == command_id and prior["result"] == result:
                    return {"accepted": False, "duplicate": True,
                            "command_id": command_id, "result": result}
                _reject("REUSED_OR_OLD_SEQ")
            if seq > expected:
                _reject("OUT_OF_ORDER_GAP")

            tgt = self.db.get_target(command_id, device_id)
            if not tgt:
                _reject("UNKNOWN_TARGET")
            if tgt["status"] == M.TGT_PENDING:
                _reject("NOT_DISPATCHED")
            if tgt["status"] in (M.TGT_SKIPPED, M.TGT_MISSED):
                _reject(f"TARGET_{tgt['status']}")
            if tgt["status"] in (M.TGT_EXECUTED, M.TGT_FAILED):
                existing = self.db.get_receipt(command_id, device_id)
                if existing and existing["result"] == result:
                    return {"accepted": False, "duplicate": True,
                            "command_id": command_id, "result": result}
                _reject("FACT_IMMUTABLE")
            if tgt["dispatched_boot"] not in (None, boot_code):
                _reject("BOOT_MISMATCH")

            status = M.TGT_EXECUTED if result == M.RESULT_EXECUTED else M.TGT_FAILED
            try:
                event_id = self.db.append_event(
                    now, device_id, M.AUDIT_DEV, "RECEIPT_ACCEPTED",
                    {"command_id": command_id, "boot_code": boot_code, "seq": seq,
                     "result": result, "message": message},
                    command_id=command_id, device_id=device_id)
                ok = self.db.insert_receipt({
                    "command_id": command_id, "device_id": device_id,
                    "boot_code": boot_code, "seq": seq, "result": result,
                    "message": message, "source": M.SRC_RECEIPT,
                    "event_id": event_id, "received_at": now})
                if not ok:
                    # 并发重复：回滚事件，按幂等返回
                    self.db.rollback()
                    existing = self.db.get_receipt(command_id, device_id)
                    if existing and existing["result"] == result:
                        return {"accepted": False, "duplicate": True,
                                "command_id": command_id, "result": result}
                    _reject("FACT_IMMUTABLE")
                self.db.settle_target(command_id, device_id, status, now)
                self.db.advance_ledger_head(device_id, seq)
                self._recompute(command_id, now)
                inc = self.db.get_open_incident(command_id, device_id)
                if inc:
                    self.db.add_incident_event(
                        inc["incident_id"], now, device_id, M.IEV_FINAL_RECEIPT,
                        {"boot_code": boot_code, "seq": seq, "result": result,
                         "source": M.SRC_RECEIPT}, audit_event_id=event_id)
                    self.db.resolve_incident(
                        inc["incident_id"], M.INC_RECOVERED,
                        f"RECEIPT:{result}", now)
                self.db.commit()
            except InvalidReceipt:
                raise
            except Exception:
                self.db.rollback()
                raise
            return {"accepted": True, "duplicate": False,
                    "command_id": command_id, "result": result}

    # ================= 后台清扫 / 重启恢复 =================
    def _open_incident(self, command_id: str, device_id: str, reason: str,
                       dispatched_boot: Optional[str], now: float) -> Optional[dict]:
        """为缺终态目标打开一张对账工单（同目标已有 OPEN 工单时幂等返回）。"""
        inc = self.db.insert_incident({
            "incident_id": _new_incident_id(), "command_id": command_id,
            "device_id": device_id, "open_reason": reason,
            "dispatched_boot": dispatched_boot}, now)
        if inc is None:
            return None
        cmd = self.db.get_command_row(command_id)
        event_id = self.db.append_event(
            now, "system", M.AUDIT_SEC, "INCIDENT_OPENED",
            {"incident_id": inc["incident_id"], "command_id": command_id,
             "device_id": device_id, "reason": reason,
             "dispatched_boot": dispatched_boot,
             "digest": cmd["digest"] if cmd else None},
            command_id=command_id, device_id=device_id)
        self.db.add_incident_event(
            inc["incident_id"], now, "system", M.IEV_OPENED,
            {"reason": reason, "dispatched_boot": dispatched_boot,
             "command_digest": cmd["digest"] if cmd else None},
            audit_event_id=event_id)
        return inc

    def startup_recovery(self):
        """网关重启后：所有“已投递但无终态”的目标转 DOUBT，并逐一生成只能由
        安全角色查看/处置的事故恢复对账工单。

        不做任何乐观重放——设备可能已经执行。等设备重新 HELLO 带签名账簿对账，
        确保未执行指令不误执行、已执行事实不丢失。
        """
        with self._lock:
            now = self.now()
            rows = self.db.dangling_dispatched()
            if not rows:
                return {"doubt": 0, "incidents": 0}
            opened = 0
            try:
                for r in rows:
                    self.db.mark_doubt(r["command_id"], r["device_id"], now)
                    if self._open_incident(r["command_id"], r["device_id"],
                                           M.INC_REASON_RESTART,
                                           r.get("dispatched_boot"), now):
                        opened += 1
                self.db.append_event(
                    now, "system", M.AUDIT_SYS, "GATEWAY_RESTART_RECOVERY",
                    {"doubt_targets": rows, "incidents_opened": opened})
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"doubt": len(rows), "incidents": opened}

    def sweep(self) -> dict:
        with self._lock:
            now = self.now()
            expired, closed, offline = [], [], []
            try:
                for cid in self.db.expire_pending_commands(now):
                    self.db.append_event(
                        now, "system", M.AUDIT_SYS, "CMD_EXPIRED",
                        {"command_id": cid, "reason": "CONFIRM_TIMEOUT"},
                        command_id=cid)
                    expired.append(cid)

                # 先记录窗口即将关闭的指令当前仍 DISPATCHED 的目标（将转 DOUBT）
                due_rows = self.db.conn.execute(
                    "SELECT command_id FROM commands WHERE status='CONFIRMED' "
                    "AND valid_to<=?", (now,)).fetchall()
                pre_dispatched: dict[str, list[dict]] = {}
                for row in due_rows:
                    cid0 = row["command_id"]
                    pre_dispatched[cid0] = [
                        dict(r) for r in self.db.conn.execute(
                            "SELECT * FROM targets WHERE command_id=? "
                            "AND status='DISPATCHED'", (cid0,)).fetchall()]
                closed_ids = self.db.close_due_windows(now)
                for cid in closed_ids:
                    self.db.append_event(
                        now, "system", M.AUDIT_SYS, "WINDOW_CLOSED",
                        {"command_id": cid}, command_id=cid)
                    # 窗口关闭时仍在途（新转 DOUBT）的目标：生成对账工单。
                    # DOUBT 不因窗口关闭立即终结——继续等待设备账簿或安全角色处置；
                    # 事后到达的过期账簿材料只隔离留痕（Q_WINDOW_EXPIRED），不补记。
                    for t in pre_dispatched.get(cid, []):
                        self._open_incident(cid, t["device_id"],
                                            M.INC_REASON_WINDOW,
                                            t.get("dispatched_boot"), now)
                    self._recompute(cid, now)
                    closed.append(cid)

                for d in self.db.list_devices():
                    if d["online"] and d["last_seen"] is not None \
                            and now - d["last_seen"] > self.cfg.offline_seconds:
                        self.db.mark_offline(d["device_id"])
                        self.db.append_event(
                            now, "system", M.AUDIT_DEV, "DEVICE_OFFLINE",
                            {"device_id": d["device_id"], "last_seen": d["last_seen"]},
                            device_id=d["device_id"])
                        offline.append(d["device_id"])
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return {"expired": expired, "windows_closed": closed, "offline": offline}

    # ================= 派生状态 / 审计视图 =================
    def _recompute(self, command_id: str, now: float):
        """根据目标终态重算指令级状态（仅在已确认生命周期内演进）。"""
        row = self.db.get_command_row(command_id)
        if not row or row["status"] not in (
                M.CMD_CONFIRMED, M.CMD_CLOSED, M.CMD_PARTIAL_FAILED):
            return
        targets = self.db.list_targets(command_id)
        n_exec = sum(t["status"] == M.TGT_EXECUTED for t in targets)
        n_fail = sum(t["status"] == M.TGT_FAILED for t in targets)
        n_missed = sum(t["status"] == M.TGT_MISSED for t in targets)
        outstanding = [t for t in targets
                       if t["status"] in (M.TGT_PENDING, M.TGT_DISPATCHED, M.TGT_DOUBT)]
        new_status: Optional[str] = None
        if not outstanding:
            if n_exec and not n_fail and not n_missed:
                new_status = M.CMD_EXECUTED
            elif n_exec or n_fail:
                new_status = M.CMD_PARTIAL_FAILED
            else:
                new_status = M.CMD_CLOSED
        elif now >= row["valid_to"]:
            # 仍有悬置目标但窗口已关：先闭合，待账本对账后可继续演进为部分失败/完成
            new_status = M.CMD_CLOSED
        if new_status and new_status != row["status"]:
            self.db.set_command_status(command_id, new_status)

    def _target_view(self, t: dict) -> dict:
        out = dict(t)
        rec = self.db.get_receipt(t["command_id"], t["device_id"])
        out["receipt"] = {
            "boot_code": rec["boot_code"], "seq": rec["seq"], "result": rec["result"],
            "message": rec["message"], "source": rec["source"],
            "received_at": rec["received_at"],
        } if rec else None
        return out

    def audit_events(self, limit: int = 200, command_id: Optional[str] = None,
                     device_id: Optional[str] = None) -> list[dict]:
        with self._lock:
            rows = self.db.list_events(limit, command_id, device_id)
            for r in rows:
                r["payload"] = json.loads(r["payload"])
            return rows

    def verify_audit_chain(self) -> dict:
        with self._lock:
            return self.db.verify_chain()

    def rejected_receipts(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.db.list_rejected(limit)
            for r in rows:
                r["raw"] = json.loads(r["raw"])
            return rows

    # ================= 事故恢复对账工单（仅安全通道可访问）=================
    def list_incidents(self, status: Optional[str] = None) -> list[dict]:
        with self._lock:
            out = []
            for inc in self.db.list_incidents(status):
                item = dict(inc)
                cmd = self.db.get_command_row(inc["command_id"])
                item["action"] = cmd["action"] if cmd else None
                item["command_digest"] = cmd["digest"] if cmd else None
                tgt = self.db.get_target(inc["command_id"], inc["device_id"])
                item["target_status"] = tgt["status"] if tgt else None
                out.append(item)
            return out

    def incident_detail(self, incident_id: str) -> dict:
        with self._lock:
            inc = self.db.get_incident_row(incident_id)
            if not inc:
                raise NotFound("对账工单不存在")
            out = dict(inc)
            cmd = self.db.get_command_row(inc["command_id"])
            out["command"] = _cmd_dict(cmd) if cmd else None
            out["target"] = self._target_view(
                self.db.get_target(inc["command_id"], inc["device_id"]))
            out["history"] = self.db.list_incident_events(incident_id)
            out["quarantine"] = self.db.list_quarantine(incident_id=incident_id)
            out["window_open"] = bool(cmd and self.now() < cmd["valid_to"])
            return out

    def list_quarantine(self, device_id: Optional[str] = None) -> list[dict]:
        with self._lock:
            return self.db.list_quarantine(device_id=device_id)

    def _incident_action(self, actor: str, incident_id: str) -> dict:
        inc = self.db.get_incident_row(incident_id)
        if not inc:
            raise NotFound("对账工单不存在")
        if inc["status"] != M.INC_OPEN:
            raise InvalidState("工单已终结，不可再处置",
                               details={"status": inc["status"]})
        tgt = self.db.get_target(inc["command_id"], inc["device_id"])
        if not tgt:
            raise NotFound("目标不存在")
        # 任何人工处置都不能覆盖已经确认的执行事实
        if self.db.get_receipt(inc["command_id"], inc["device_id"]):
            raise Conflict("已确认执行事实存在，人工处置不得覆盖事实")
        return inc

    def incident_note(self, actor: str, incident_id: str, note: str) -> dict:
        """安全角色添加处置备注（不改任何状态，仅追加历史）。"""
        if not note or not note.strip():
            raise InvalidState("备注内容不能为空")
        with self._lock:
            now = self.now()
            inc = self.db.get_incident_row(incident_id)
            if not inc:
                raise NotFound("对账工单不存在")
            try:
                event_id = self.db.append_event(
                    now, actor, M.AUDIT_SEC, "INCIDENT_NOTE",
                    {"incident_id": incident_id, "note": note},
                    command_id=inc["command_id"], device_id=inc["device_id"])
                self.db.add_incident_event(
                    incident_id, now, actor, M.IEV_NOTE, {"note": note},
                    audit_event_id=event_id)
                self.db.touch_incident(incident_id, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.incident_detail(incident_id)

    def incident_redeliver(self, actor: str, incident_id: str,
                           reason: str = "") -> dict:
        """安全角色人工重新派发。硬条件：无执行事实、设备已换代次（确定未执行）、
        原有效时限仍有效、指令仍 CONFIRMED。任何一条不满足都拒绝。"""
        with self._lock:
            now = self.now()
            inc = self._incident_action(actor, incident_id)
            cid, dev_id = inc["command_id"], inc["device_id"]
            tgt = self.db.get_target(cid, dev_id)
            if tgt["status"] != M.TGT_DOUBT:
                raise InvalidState("仅 DOUBT 目标可重新派发",
                                   details={"target_status": tgt["status"]})
            dev = self.db.get_device(dev_id)
            if not dev["online"]:
                raise Conflict("设备当前离线，无法安全重新派发，请待其带账簿重连")
            if tgt["dispatched_boot"] in (None, dev["current_boot"]):
                raise Conflict(
                    "投递代次仍在线：是否执行不可证明，禁止重投（双触发风险）")
            cmd = self.db.get_command_row(cid)
            if cmd["status"] != M.CMD_CONFIRMED or now >= cmd["valid_to"]:
                raise Conflict("原有效时限已失效或指令已终结，禁止重新派发",
                               details={"status": cmd["status"]})
            try:
                self.db.reset_to_pending(cid, dev_id, now)
                event_id = self.db.append_event(
                    now, actor, M.AUDIT_SEC, "INCIDENT_MANUAL_REDELIVER",
                    {"incident_id": incident_id, "command_id": cid,
                     "device_id": dev_id, "old_boot": tgt["dispatched_boot"],
                     "new_boot": dev["current_boot"], "reason": reason},
                    command_id=cid, device_id=dev_id)
                self.db.add_incident_event(
                    incident_id, now, actor, M.IEV_MANUAL_REDELIVER,
                    {"old_boot": tgt["dispatched_boot"],
                     "new_boot": dev["current_boot"], "reason": reason},
                    audit_event_id=event_id)
                self.db.resolve_incident(
                    incident_id, M.INC_REDELIVERED, "MANUAL", now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.incident_detail(incident_id)

    def incident_close_unverified(self, actor: str, incident_id: str,
                                  reason: str = "") -> dict:
        """安全角色在窗口已关闭且无法取得账簿证据时，把目标记 MISSED 并关闭工单。
        该操作不产生任何执行事实；若窗口仍有效则拒绝（应等待对账）。"""
        with self._lock:
            now = self.now()
            inc = self._incident_action(actor, incident_id)
            cid, dev_id = inc["command_id"], inc["device_id"]
            tgt = self.db.get_target(cid, dev_id)
            cmd = self.db.get_command_row(cid)
            if tgt["status"] != M.TGT_DOUBT:
                raise InvalidState("仅 DOUBT 目标可按未达关闭",
                                   details={"target_status": tgt["status"]})
            if now < cmd["valid_to"]:
                raise Conflict("原有效时限仍有效，应等待设备账簿对账，不得提前关闭")
            try:
                self.db.close_doubt_as_missed(cid, dev_id, now)
                event_id = self.db.append_event(
                    now, actor, M.AUDIT_SEC, "INCIDENT_MANUAL_CLOSE",
                    {"incident_id": incident_id, "command_id": cid,
                     "device_id": dev_id, "reason": reason or "WINDOW_CLOSED"},
                    command_id=cid, device_id=dev_id)
                self.db.add_incident_event(
                    incident_id, now, actor, M.IEV_CLOSE_UNVERIFIED,
                    {"reason": reason or "WINDOW_CLOSED",
                     "note": "未取得执行证据，按未达关闭；不产生执行事实"},
                    audit_event_id=event_id)
                self.db.resolve_incident(incident_id, M.INC_EXPIRED,
                                         "MANUAL_UNVERIFIED", now)
                self._recompute(cid, now)
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            return self.incident_detail(incident_id)

    def list_devices(self) -> list[dict]:
        with self._lock:
            devs = self.db.list_devices()
            for d in devs:
                d.pop("preshared_key", None)
            return devs


def _safe_int(v: Any):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
