"""HTTP 公共工具：请求/响应、安全通道会话、三通道服务器管理。"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from .errors import GatewayError, Unauthorized
from .security import new_session_id


class Sessions:
    """安全工作台内存会话（与业务/设备凭据完全独立）。"""

    def __init__(self, ttl: int):
        self.ttl = ttl
        self._data: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, username: str) -> str:
        sid = new_session_id()
        with self._lock:
            self._data[sid] = {"user": username, "exp": time.time() + self.ttl}
        return sid

    def get(self, sid: Optional[str]) -> Optional[dict]:
        if not sid:
            return None
        with self._lock:
            s = self._data.get(sid)
            if s and s["exp"] > time.time():
                return s
            self._data.pop(sid, None)
        return None

    def drop(self, sid: str):
        with self._lock:
            self._data.pop(sid, None)


class GatewayContext:
    def __init__(self, service, config):
        self.svc = service
        self.cfg = config
        self.sessions = Sessions(config.session_ttl_seconds)


class JsonHandler(BaseHTTPRequestHandler):
    ctx: GatewayContext = None  # 由 make_server 注入到子类

    server_version = "DualGateway/1.0"

    def log_message(self, fmt, *args):  # 静默默认日志，走统一审计/控制台
        pass

    # ---------- 读取 ----------
    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def read_json(self) -> dict:
        raw = self._body()
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            raise GatewayError("请求体不是合法 JSON", )
        if not isinstance(data, dict):
            raise GatewayError("请求体必须是 JSON 对象")
        return data

    def query(self) -> dict:
        q = parse_qs(urlparse(self.path).query)
        return {k: v[-1] for k, v in q.items()}

    @property
    def raw_path(self) -> str:
        return urlparse(self.path).path

    # ---------- 响应 ----------
    def send_json(self, obj: Any, status: int = 200,
                  extra_headers: Optional[dict] = None):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str, status: int = 200,
                  extra_headers: Optional[dict] = None):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def handle_error(self, exc: Exception):
        if isinstance(exc, GatewayError):
            self.send_json({"error": exc.code, "message": exc.message,
                            "details": exc.details}, exc.http_status)
        else:
            self.send_json({"error": "INTERNAL", "message": str(exc)}, 500)

    # ---------- 会话 ----------
    COOKIE = "GWSEC_SESSION"

    def _session_cookie(self) -> Optional[str]:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == self.COOKIE:
                    return v
        return None

    def require_session(self) -> dict:
        s = self.ctx.sessions.get(self._session_cookie())
        if not s:
            raise Unauthorized("安全工作台未登录")
        return s

    # ---------- 路由分发 ----------
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        try:
            routes = getattr(self, "routes")
            import fnmatch
            handler = None
            for pat, meth, fn in routes:
                if meth != method:
                    continue
                if "*" in pat:
                    if fnmatch.fnmatchcase(self.raw_path, pat):
                        handler = fn
                        break
                elif pat == self.raw_path:
                    handler = fn
                    break
            if handler is None:
                self.send_json({"error": "NOT_FOUND", "message": self.raw_path}, 404)
                return
            handler(self)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001 — 统一错误边界
            self.handle_error(exc)


def make_handler(ctx: GatewayContext, routes, auth_hook: Optional[Callable] = None):
    """生成绑定了上下文与路由表的 Handler 类。"""

    class _Handler(JsonHandler):
        pass

    _Handler.ctx = ctx
    _Handler.routes = routes
    if auth_hook:
        _Handler.auth_hook = staticmethod(auth_hook)
    return _Handler


class ChannelServer:
    def __init__(self, name: str, host: str, port: int, handler_cls):
        self.name = name
        self.httpd = ThreadingHTTPServer((host, port), handler_cls)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, name=f"http-{name}", daemon=True)

    def start(self):
        self.thread.start()

    @property
    def bound_port(self) -> int:
        return self.httpd.server_address[1]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
