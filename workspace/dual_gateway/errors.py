"""领域错误码。"""
from __future__ import annotations


class GatewayError(Exception):
    """所有可预期业务错误的基类，携带稳定的错误码与 HTTP 状态码。"""

    code = "GATEWAY_ERROR"
    http_status = 400

    def __init__(self, message: str = "", *, details: dict | None = None):
        super().__init__(message or self.code)
        self.message = message or self.code
        self.details = details or {}


class Unauthorized(GatewayError):
    code = "UNAUTHORIZED"
    http_status = 401


class Forbidden(GatewayError):
    code = "FORBIDDEN"
    http_status = 403


class NotFound(GatewayError):
    code = "NOT_FOUND"
    http_status = 404


class Conflict(GatewayError):
    code = "CONFLICT"
    http_status = 409


class FrozenMismatch(Conflict):
    """确认 / 撤销请求与创建时冻结的内容不一致。"""

    code = "FROZEN_MISMATCH"


class InvalidState(Conflict):
    code = "INVALID_STATE"


class DeviceRejected(Conflict):
    """设备侧握手 / 回执被拒绝（错误代号、乱序等）。"""

    code = "DEVICE_REJECTED"


class InvalidReceipt(Conflict):
    code = "INVALID_RECEIPT"


class InvalidWindow(Conflict):
    code = "INVALID_WINDOW"
