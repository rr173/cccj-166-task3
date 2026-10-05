"""网关装配：存储 + 服务 + 三通道 HTTP 服务器 + 后台清扫线程。"""
from __future__ import annotations

import threading
import time

from . import biz_api, dev_api, sec_web
from .config import GatewayConfig, load_config
from .http_common import ChannelServer, GatewayContext
from .service import CommandService
from .storage import Storage


class Gateway:
    def __init__(self, config: GatewayConfig | None = None):
        self.cfg = config or load_config()
        self.db = Storage(self.cfg.db_path)
        now = time.time()
        for dev_id, key in self.cfg.device_keys.items():
            self.db.seed_device(dev_id, key, now)
        self.db.commit()

        self.svc = CommandService(self.db, self.cfg)
        self.ctx = GatewayContext(self.svc, self.cfg)

        self.biz = ChannelServer("biz", self.cfg.biz_host, self.cfg.biz_port,
                                 biz_api.build_handler(self.ctx))
        self.sec = ChannelServer("sec", self.cfg.sec_host, self.cfg.sec_port,
                                 sec_web.build_handler(self.ctx))
        self.dev = ChannelServer("dev", self.cfg.dev_host, self.cfg.dev_port,
                                 dev_api.build_handler(self.ctx))
        self._stop = threading.Event()
        self._sweeper: threading.Thread | None = None

    def start(self, recover: bool = True):
        if recover:
            info = self.svc.startup_recovery()
            if info["doubt"]:
                print(f"[gateway] 重启恢复：{info['doubt']} 个在途目标转 DOUBT，等待设备账本对账")
        self.biz.start()
        self.sec.start()
        self.dev.start()
        self._sweeper = threading.Thread(target=self._sweep_loop, daemon=True,
                                         name="sweeper")
        self._sweeper.start()
        print(f"[gateway] 业务通道 http://{self.cfg.biz_host}:{self.cfg.biz_port}")
        print(f"[gateway] 安全通道 http://{self.cfg.sec_host}:{self.cfg.sec_port}")
        print(f"[gateway] 设备通道 http://{self.cfg.dev_host}:{self.cfg.dev_port}")

    def _sweep_loop(self):
        while not self._stop.wait(self.cfg.sweep_interval):
            try:
                r = self.svc.sweep()
                if any(r.values()):
                    print(f"[sweep] {r}")
            except Exception as exc:  # 清扫异常不能杀死线程
                print(f"[sweep] error: {exc}")

    def stop(self):
        self._stop.set()
        for s in (self.biz, self.sec, self.dev):
            s.stop()
        self.db.close()


def main():
    gw = Gateway()
    gw.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[gateway] 关闭中…")
        gw.stop()


if __name__ == "__main__":
    main()
