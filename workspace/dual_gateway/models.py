"""状态机常量。

指令 (command) 级状态::

    PENDING ──确认──▶ CONFIRMED ──全部设备回执──▶ EXECUTED / PARTIAL_FAILED
       │                 │
       │             窗口过期/离线未达
       │                 ▼
       ├─拒绝─▶ REJECTED  EXPIRED（未确认）/ CLOSED（已确认但有未达目标）
       ├─超时─▶ EXPIRED
       └─撤销─▶ REVOKED（仅当尚无任何设备实际执行时允许）

目标 (command_target, 指令×单设备) 级状态::

    PENDING 未下发
    DISPATCHED 已投递给设备（设备已拉取）
    DOUBT 网关重启后、或长时间无回执，是否执行未知，需设备账本对账
    EXECUTED / FAILED 设备回执确认（终态，事实不可覆盖）
    SKIPPED 确认前设备被移出 / 指令未确认而冻结（终态）
    MISSED 窗口关闭时尚未下发成功（终态）

事故恢复对账工单 (incident_order)::

    网关进程重启后，凡“已送达现场但缺少终态回报”的目标各生成一张工单；
    工单只能经安全通道（第二角色）查看与处置，业务/设备通道不可见。
    OPEN        待对账（等待设备重连上送签名账簿，或等待安全角色处置）
    RECOVERED   账簿证据被采信，既成执行已补记（EXECUTED/FAILED 事实）
    REDELIVERED 账簿证明设备重启后未执行且窗口仍有效，已重新派发
    EXPIRED     窗口关闭仍无法取得账簿证据，目标记 MISSED 后人工/系统关闭
    人工只能在没有执行事实的前提下 REDELIVER / 关闭，永远不能写入或覆盖事实。

审计封存 (seal_request)::

    安全角色为事件链设定区间 [from_id, to_id]，系统生成不可变封存包
    （区间首尾 + 前序链头 + 末尾摘要 + 逐事件证明 + 整体摘要），
    离线核验命令据此可在库被篡改/删记录/整库替换后定位首个断点。
    同一区间至多一份有效申请；已封存内容不得覆盖；仅 PENDING 可撤销。
"""
from __future__ import annotations

# 指令级
CMD_PENDING = "PENDING"
CMD_CONFIRMED = "CONFIRMED"
CMD_EXECUTED = "EXECUTED"
CMD_PARTIAL_FAILED = "PARTIAL_FAILED"
CMD_REJECTED = "REJECTED"
CMD_EXPIRED = "EXPIRED"
CMD_REVOKED = "REVOKED"
CMD_CLOSED = "CLOSED"

CMD_TERMINAL = {
    CMD_EXECUTED, CMD_PARTIAL_FAILED, CMD_REJECTED,
    CMD_EXPIRED, CMD_REVOKED, CMD_CLOSED,
}

# 目标级
TGT_PENDING = "PENDING"
TGT_DISPATCHED = "DISPATCHED"
TGT_DOUBT = "DOUBT"
TGT_EXECUTED = "EXECUTED"
TGT_FAILED = "FAILED"
TGT_SKIPPED = "SKIPPED"
TGT_MISSED = "MISSED"

TGT_TERMINAL = {TGT_EXECUTED, TGT_FAILED, TGT_SKIPPED, TGT_MISSED}

# 回执结果
RESULT_EXECUTED = "EXECUTED"
RESULT_FAILED = "FAILED"

# 回执来源
SRC_RECEIPT = "RECEIPT"          # 设备正常上送
SRC_LEDGER = "LEDGER_RECOVERY"   # 重连/重启后从设备持久账簿补记

# ---- 事故恢复对账工单 ----
INC_OPEN = "OPEN"
INC_RECOVERED = "RECOVERED"
INC_REDELIVERED = "REDELIVERED"
INC_EXPIRED = "EXPIRED"
INC_TERMINAL = {INC_RECOVERED, INC_REDELIVERED, INC_EXPIRED}

# 工单打开原因
INC_REASON_RESTART = "GATEWAY_RESTART"  # 服务进程重启，在途无终态
INC_REASON_WINDOW = "WINDOW_CLOSED"     # 窗口关闭仍在途，终态缺失

# 工单处置历史事件类型
IEV_OPENED = "INCIDENT_OPENED"
IEV_EVIDENCE = "LEDGER_EVIDENCE_ACCEPTED"    # 账簿补记既成执行
IEV_QUARANTINE = "LEDGER_ENTRY_QUARANTINED"  # 隔离留痕（编号缺口/矛盾/过期/旧代次）
IEV_REDELIVER = "REDELIVERED"                # 自动重新派发
IEV_MANUAL_REDELIVER = "MANUAL_REDELIVER"    # 人工重新派发
IEV_CLOSE_UNVERIFIED = "MANUAL_CLOSE_UNVERIFIED"
IEV_NOTE = "MANUAL_NOTE"
IEV_FINAL_RECEIPT = "TERMINAL_RECEIPT"       # 工单挂起期间正常回执到达

# 账簿隔离原因（quarantined_ledger.reason，审计/工作台可见）
Q_SIGNATURE = "LEDGER_BAD_SIGNATURE"          # 整册签名无效
Q_UNKNOWN_BOOT = "UNKNOWN_BOOT_GENERATION"    # 旧代次/未知代次材料
Q_BAD_ENTRY = "BAD_ENTRY"                     # 条目结构非法
Q_GAP = "SEQ_GAP"                             # 编号缺口（不单调连续）
Q_SEQ_REUSE = "SEQ_REUSED"                    # 序号复用/倒序
Q_BROKEN_CHAIN = "CHAIN_DISCONTINUITY"        # 账簿连续性破坏（prev 不接）
Q_FINGERPRINT = "FINGERPRINT_MISMATCH"        # 指令指纹不符
Q_FACT_CONFLICT = "FACT_CONFLICT"             # 与已确认事实矛盾
Q_NEVER_DISPATCHED = "NEVER_DISPATCHED"       # 网关从未投递（伪造/串扰）
Q_STATE_SKIPPED = "TARGET_SKIPPED"            # 已撤销/拒绝/冻结
Q_BOOT_MISMATCH = "BOOT_GENERATION_MISMATCH"  # 条目代次与投递代次不符（旧代次）
Q_WINDOW_EXPIRED = "WINDOW_EXPIRED"           # 过期时限：事实不得补记，仅隔离留痕

# ---- 审计封存（不可变封存包 + 离线核验）----
# 封存申请状态机：
#   PENDING 待处理（已登记区间，尚未开始写包；只有此状态可撤销）
#   SEALING 生成中（已开始写包；崩溃后由重启恢复接管：要么续完同一份包，
#           要么明确回滚为 PENDING 可重试，绝不留半成品/永久锁）
#   SEALED 已封存（包已落盘并登记摘要；内容不得覆盖，只可核验）
#   VERIFY_FAILED 核验失败（在线核验发现包/库不一致；保留证据，可复核验）
#   CANCELLED 已撤销（仅 PENDING 可到达；撤销后同区间可重新申请）
SEAL_PENDING = "PENDING"
SEAL_SEALING = "SEALING"
SEAL_SEALED = "SEALED"
SEAL_VERIFY_FAILED = "VERIFY_FAILED"
SEAL_CANCELLED = "CANCELLED"
SEAL_ACTIVE = {SEAL_PENDING, SEAL_SEALING, SEAL_SEALED, SEAL_VERIFY_FAILED}

# 封存处置历史事件类型（seal_events.kind，只追加）
SEV_REQUESTED = "SEAL_REQUESTED"      # 安全角色登记封存申请
SEV_STARTED = "SEAL_STARTED"          # 开始写包（PENDING→SEALING）
SEV_COMPLETED = "SEAL_COMPLETED"      # 写包完成并登记摘要（SEALING→SEALED）
SEV_FAILED = "SEAL_FAILED"            # 生成失败，回滚为可重试（SEALING→PENDING）
SEV_CANCELLED = "SEAL_CANCELLED"      # 未开始写包的申请被撤销
SEV_VERIFY_OK = "SEAL_VERIFY_OK"      # 在线核验通过
SEV_VERIFY_FAILED = "SEAL_VERIFY_FAILED"  # 在线核验失败（首个断点见 detail）
SEV_ROLLBACK = "SEAL_ROLLBACK"        # 重启恢复：生成中断，回滚为可重试
SEV_ADOPTED = "SEAL_ADOPTED"          # 重启恢复：包已完整落盘，续完同一份包

# 审计动作分类
AUDIT_BIZ = "BIZ"
AUDIT_SEC = "SECURITY"
AUDIT_DEV = "DEVICE"
AUDIT_SYS = "SYSTEM"
