"""现场设备模拟器（带持久执行账本）。

模拟真实 PLC 的关键行为：

* 每次启动生成新 boot_code，回执 seq 从 1 严格递增；
* 本地持久账本 ledger.jsonl：执行前先 fsync 落盘，再上送回执——
  即使网关在中途崩溃/重启，设备重连 HELLO 时可凭账本对账补记；
* 周期心跳、周期 PULL；
* 故障注入：--drop-receipt 丢失回执（设备仍执行，考验账本补记）、
  --old-boot 伪造旧代号回执、--gap 跳号、--reuse 复用序号、
  --offline 启动后不握手（离线场景）。

用法:
  python -m dual_gateway.device_sim DEV-A1 --db ./data/dev-a1
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time

from .security import (hmac_sign, ledger_anchor, ledger_entry_hash,
                       ledger_sign, new_boot_code)

try:
    import urllib.request
    import urllib.error
except ImportError:  # pragma: no cover
    urllib = None


class SimDevice:
    def __init__(self, device_id: str, key: str, base_url: str, state_dir: str,
                 *, fail_rate: float = 0.0, drop_receipt: bool = False,
                 offline: bool = False, chaos: dict | None = None,
                 verbose: bool = True):
        self.device_id = device_id
        self.key = key
        self.base_url = base_url.rstrip("/")
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)
        self.ledger_path = os.path.join(state_dir, "ledger.jsonl")
        self.fail_rate = fail_rate
        self.drop_receipt = drop_receipt
        self.offline = offline
        self.chaos = chaos or {}
        self.verbose = verbose
        self.boot_code = new_boot_code()
        self.seq = 1
        self.online = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.executed: list[dict] = []
        self._load_ledger()

    def log(self, msg: str):
        if self.verbose:
            print(f"[{self.device_id}] {msg}")

    # ---------- 账本：执行前落盘（WAL 语义）----------
    def _load_ledger(self):
        if not os.path.exists(self.ledger_path):
            return
        with open(self.ledger_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.executed.append(json.loads(line))
        if self.executed:
            self.log(f"加载本地执行账本 {len(self.executed)} 条（跨重启保留）")

    def _append_ledger(self, entry: dict):
        with open(self.ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.executed.append(entry)

    # ---------- 账簿条目：指令指纹 + prev 哈希链 ----------
    def _prev_for(self, boot: str, seq: int) -> str:
        """同代次上一条目哈希；代次首条接代次锚点。"""
        for e in reversed(self.executed):
            if e.get("boot_code") == boot and e.get("seq") == seq - 1:
                return ledger_entry_hash(self.device_id, e)
        return ledger_anchor(self.device_id, boot, 1)

    def make_ledger_entry(self, command_id: str, result: str, digest: str,
                          message: str = "simulated actuation",
                          *, seq: int | None = None, boot: str | None = None) -> dict:
        boot = boot or self.boot_code
        seq = self.seq if seq is None else seq
        return {"command_id": command_id, "boot_code": boot, "seq": seq,
                "result": result, "digest": digest, "message": message,
                "prev": self._prev_for(boot, seq)}

    # ---------- HTTP ----------
    def _post(self, path: str, payload: dict):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sig = hmac_sign(self.key, raw)
        req = urllib.request.Request(
            self.base_url + path, data=raw, method="POST", headers={
                "Content-Type": "application/json",
                "X-Device-Id": self.device_id,
                "X-Signature": sig,
            })
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    # ---------- 协议动作 ----------
    def hello(self, boot_code: str | None = None, first_seq: int = 1,
              include_ledger: bool = True, *,
              ledger_sig: str | None = None):
        payload: dict = {"boot_code": boot_code or self.boot_code,
                         "first_seq": first_seq}
        if include_ledger:
            entries = self.executed
            payload["ledger"] = entries
            # 独立账簿签名（与传输 HMAC 分开，防止账簿被调包）
            payload["ledger_sig"] = (
                ledger_sig if ledger_sig is not None
                else ledger_sign(self.key, entries))
        return self._post("/api/device/hello", payload)

    def heartbeat(self, boot_code: str | None = None):
        return self._post("/api/device/heartbeat",
                          {"boot_code": boot_code or self.boot_code})

    def pull(self) -> list[dict]:
        _, body = self._post("/api/device/pull", {"boot_code": self.boot_code})
        return body.get("commands", [])

    def _send_receipt(self, command_id: str, result: str, message: str,
                      boot_code: str, seq: int):
        return self._post("/api/device/receipt", {
            "command_id": command_id, "boot_code": boot_code, "seq": seq,
            "result": result, "message": message})

    def execute_and_report(self, cmd: dict) -> tuple[str, dict]:
        """本地执行 + 先落账本再回执。返回 (回执行为描述, 响应)。"""
        import random
        with self._lock:
            result = "FAILED" if random.random() < self.fail_rate else "EXECUTED"
            seq = self.seq
            boot = self.boot_code
            entry = self.make_ledger_entry(
                cmd["command_id"], result, cmd.get("digest", ""),
                "simulated actuation", seq=seq, boot=boot)
            # 1) 执行事实先持久化（关键：先落盘后回执）
            self._append_ledger(entry)
            self.seq += 1

            # 2) 故障注入
            if self.chaos.get("gap"):
                self.log(f"故障注入: 跳号发送 seq={seq + 1}（真实序号 {seq} 被吞）")
                self.seq += 1
                return "GAP", self._send_receipt(
                    cmd["command_id"], result, entry["message"], boot, seq + 1)
            if self.drop_receipt:
                self.log(f"指令 {cmd['command_id']} 已执行({result})，"
                         f"但回执丢失 seq={seq}（账本保留，等重连补记）")
                return "DROPPED", {}
            status, body = self._send_receipt(
                cmd["command_id"], result, entry["message"], boot, seq)
            self.log(f"指令 {cmd['command_id']} 执行 {result}，回执 seq={seq} 被接受={body.get('accepted')}")
            return "SENT", body

    # ---------- 主循环 ----------
    def run(self):
        if self.offline:
            self.log("离线模式：不握手、不心跳、不拉取")
            self._stop.wait()
            return
        self._reconnect()
        while not self._stop.is_set():
            try:
                self.heartbeat()
                for cmd in self.pull():
                    try:
                        self.execute_and_report(cmd)
                    except Exception as e:  # 回执失败不影响已落盘事实
                        self.log(f"回执上送异常（账本已存）: {e}")
            except Exception as e:
                self.log(f"链路异常，5s 后重连: {e}")
                self.online = False
                self._stop.wait(5)
                try:
                    self._reconnect()
                except Exception:
                    pass
            self._stop.wait(1.5)

    def _reconnect(self):
        try:
            _, body = self.hello()
            self.online = True
            self.log(f"HELLO ok boot={self.boot_code} rebooted={body.get('rebooted')}")
        except Exception as e:
            self.log(f"HELLO 失败: {e}")
            raise

    def stop(self):
        self._stop.set()

    def reboot(self, keep_ledger: bool = True):
        """模拟设备重启：新启动代号 + 序号归 1，账本默认保留。"""
        self.boot_code = new_boot_code()
        self.seq = 1
        self.log(f"设备重启，新启动代号 {self.boot_code}，账本保留={keep_ledger}")
        self._reconnect()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("device_id")
    ap.add_argument("--url", default="http://127.0.0.1:8082")
    ap.add_argument("--key", default=None)
    ap.add_argument("--db", default="./data/sim")
    ap.add_argument("--fail-rate", type=float, default=0.0)
    ap.add_argument("--drop-receipt", action="store_true")
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()

    from .config import DEFAULT_DEVICE_KEYS
    key = args.key or DEFAULT_DEVICE_KEYS.get(args.device_id, "test-key")
    dev = SimDevice(args.device_id, key, args.url, os.path.join(args.db, args.device_id),
                    fail_rate=args.fail_rate, drop_receipt=args.drop_receipt,
                    offline=args.offline)
    try:
        dev.run()
    except KeyboardInterrupt:
        dev.stop()


if __name__ == "__main__":
    main()
