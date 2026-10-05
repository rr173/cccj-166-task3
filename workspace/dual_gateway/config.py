"""网关配置。

真实部署中三条通道应绑定不同网卡 / 不同网段：业务通道对接 MES/调度系统，
安全通道仅在安全办公区可达，设备通道下现场控制网。这里用不同端口模拟隔离，
并使用互相独立的凭据，任何一条通道失陷都不能越权操作另外两条。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# 预置设备：device_id -> base64/hex 共享密钥（由密钥管理系统下发，演示用固定值）。
DEFAULT_DEVICE_KEYS = {
    "DEV-A1": "key-deva1-0001",
    "DEV-A2": "key-deva2-0002",
    "DEV-B1": "key-devb1-0003",
}


@dataclass
class GatewayConfig:
    # —— 三条通道监听地址（建议分别绑定不同网卡）——
    biz_host: str = field(default_factory=lambda: _env("GW_BIZ_HOST", "127.0.0.1"))
    biz_port: int = field(default_factory=lambda: int(_env("GW_BIZ_PORT", "8080")))
    sec_host: str = field(default_factory=lambda: _env("GW_SEC_HOST", "127.0.0.1"))
    sec_port: int = field(default_factory=lambda: int(_env("GW_SEC_PORT", "8081")))
    dev_host: str = field(default_factory=lambda: _env("GW_DEV_HOST", "127.0.0.1"))
    dev_port: int = field(default_factory=lambda: int(_env("GW_DEV_PORT", "8082")))

    # —— 通道凭据，互不相同 ——
    # 业务系统 API 令牌
    biz_token: str = field(default_factory=lambda: _env("GW_BIZ_TOKEN", "biz-token-ops-2026"))
    # 安全工作台第二角色口令（操作员 supervisor 与安全员 safety 职责分离：
    # supervisor 可批准/拒绝；safety 只读审计）
    sec_users: dict = field(default_factory=lambda: {
        "supervisor": _env("GW_SEC_SUPERVISOR_PW", "S@fety-Confirm-7"),
        "safety": _env("GW_SEC_SAFETY_PW", "Audit-Readonly-9"),
    })
    # 设备共享密钥
    device_keys: dict = field(default_factory=lambda: dict(DEFAULT_DEVICE_KEYS))

    # —— 时序参数（秒）——
    # 指令默认有效窗口：创建后多久内必须完成确认+下发，逾期冻结
    default_valid_seconds: int = field(
        default_factory=lambda: int(_env("GW_DEFAULT_VALID_SECONDS", "120")))
    # 确认超时：创建后多久未被第二角色确认即自动 EXPIRED
    confirm_timeout_seconds: int = field(
        default_factory=lambda: int(_env("GW_CONFIRM_TIMEOUT", "90")))
    # 设备心跳超时：超过该时长未心跳即判定离线
    offline_seconds: int = field(
        default_factory=lambda: int(_env("GW_OFFLINE_SECONDS", "6")))

    # —— 存储 ——
    db_path: str = field(default_factory=lambda: _env("GW_DB_PATH", "./data/gateway.db"))
    sweep_interval: float = field(
        default_factory=lambda: float(_env("GW_SWEEP_INTERVAL", "0.5")))

    # —— 安全工作台会话 ——
    session_ttl_seconds: int = field(
        default_factory=lambda: int(_env("GW_SESSION_TTL", "900")))


def load_config(**overrides) -> GatewayConfig:
    cfg = GatewayConfig()
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg
