# 工业控制指令双通道确认网关

高风险工业控制指令（紧急停车、切电、旁路开启等）的**创建**与**确认下发**强制分离在
两条互相独立的通道上，并由网关向现场设备做一次确认性投递；设备回执携带
**启动代号（boot_code）+ 严格递增序号（seq）**，所有状态变迁写入
**append-only 哈希链审计日志**；安全角色可对事件链任意区间生成
**不可变封存包**，并用独立命令离线核验。

> 纯 Python 3 标准库实现，无任何第三方依赖。94 个测试（70 单元 + 24 端到端）全部通过。

## 一、安全模型（如何对应需求）

| 需求 | 实现机制 |
|---|---|
| 高风险指令创建后冻结设备集合、参数摘要、有效窗口 | 创建即对 `sorted(devices) + canonical(params) + 窗口` 计算 SHA-256 摘要，设备集合/参数/窗口入库后不可变；第二角色确认时必须回传同一摘要 |
| 独立安全通道的第二角色确认 | 业务通道（8080，`X-Biz-Token`）与安全通道（8081，独立用户库 + 会话 Cookie）端口/凭据/网络完全分离；确认还要输入**带外送达的 6 位确认码**（只在创建响应出现一次，库存哈希） |
| 设备回执含启动代号与递增序号 | 设备每次启动生成随机高熵 `boot_code`，`seq` 从 1 起；网关按设备维护 `ledger_head_seq`，只接受 `head+1` |
| 旧启动代号不能改变当前状态 | `STALE_BOOT`：当前代号不匹配的回执/心跳直接拒绝，写入 `rejected_receipts`，状态不变 |
| 乱序回执不能改变当前状态 | `OUT_OF_ORDER_GAP`（跳号）、`REUSED_OR_OLD_SEQ`（序号复用）拒绝；完全相同的重复回执按幂等回放返回 `duplicate`，不重复落状态 |
| 撤销安全 | 已存在**任何执行事实**（EXECUTED/FAILED）→ 拒绝；已**在途**（DISPATCHED/DOUBT，是否执行不可证）→ 拒绝，必须先设备账本对账；只有从未到达设备的指令可撤销 |
| 确认超时 | 后台清扫 + 确认入口懒检查双保险；超时指令 `PENDING→EXPIRED`，目标 `SKIPPED`，设备永远拉取不到 |
| 网关重启不误执行 | 重启时所有“已投递无终态”目标转 `DOUBT`，**不做任何乐观重放**，并为每个目标生成一张**只能由安全角色查看/处置的事故对账工单**；设备 HELLO 带**独立签名账簿**，通过代次/单调编号/指令指纹/连续性校验后：已执行→补记事实（`LEDGER_RECOVERY`），设备已换代次且未执行→窗口内才重投，窗口外→保持 DOUBT 转人工 |
| 签名账簿五重校验 | HELLO 上送 `ledger + ledger_sig`：① 整册 HMAC（设备密钥，独立于传输签名）② 代次 boot_code 须网关节过 ③ 同代次 seq 严格 +1 ④ 条目 `digest` 须等于指令冻结指纹 ⑤ `prev` 哈希链接代次锚点。任一不过只隔离不改状态；坏签名/有缺口时 **fail-closed，不触发重投** |
| 事故恢复对账工单 | 重启/窗口关闭时为每个缺终态目标开一张（同目标 OPEN 唯一，幂等不重复）；工作台展示**证据、冲突原因、处置历史**（只追加）。安全角色可：确认未执行且时限有效时重投、窗口过后按未达 MISSED 关闭、加备注；**任何人工处置都不能写入或覆盖已确认执行事实** |
| 重复上送幂等 / 隔离区 | 同一设备同一册（内容+上送代次）重复上送按幂等回放，不重复补记/隔离/派发；编号缺口、序号复用、断链、指纹不符、事实矛盾、未投递伪造、旧代次、过期时限、坏签名全部进入 `quarantined_ledger` 隔离区永久留痕 |
| 已执行事实不能被撤销覆盖 | `receipts` 表 `(command_id, device_id)` 唯一，目标终态 UPDATE 仅允许从在途态结算，终态之间互不可写；撤销接口对存在执行事实的指令硬性拒绝；过期后到达的账簿也只能隔离，不能把 MISSED/SKIPPED 翻成执行 |
| 设备离线恢复 | 心跳超时置离线，离线设备 PULL 被拒；窗口内上线正常投递；窗口结束仍未投递记 `MISSED` 且事后上线也不再给指令 |
| 审计 | 所有变迁先在同一事务写 `events` 全序哈希链 `hash_n = SHA256(hash_{n-1}‖action‖payload)`；工作台可一键重放校验，篡改任意一条即断链；被拒回执单独留痕 |
| 审计封存 | 安全角色为事件区间生成**不可变封存包**（区间首尾 + 前序链头 + 末尾摘要 + 逐事件证明 + 整体摘要，落盘 `seal_dir`）；同一区间幂等只产生一份结果；已封存内容不得覆盖，仅未开始写包（PENDING）的申请可撤销 |
| 离线核验 | `python3 -m dual_gateway.seal_verify <包.json> --db <库>` 独立于网关进程核验：数据库被离线修改/删除中间记录/换入另一份历史时**定位首个断点**，并区分**包内损坏 / 前序历史不匹配 / 数据库落后于封存**（另加库内容分歧）四类结论；在线核验与离线命令共用同一套逻辑 |
| 封存崩溃恢复 | 生成中（SEALING）重启：包已完整落盘且与链一致→**续完同一份包**；否则删除半成品并**明确回滚为可重试（PENDING）**，不留半成品、不占永久锁 |

状态机见 `dual_gateway/models.py` 顶部注释。

## 二、架构

```
   业务系统 (MES/调度)                第二角色 (安全员)                 现场设备/PLC
        │  业务通道 8080                    │  安全通道 8081              │  设备通道 8082
        │  X-Biz-Token                     │  口令+会话+带外确认码        │  HMAC-SHA256 设备密钥
        ▼                                  ▼                            ▼
  POST /api/commands               GET  /workbench                 POST /api/device/hello
  POST /api/commands/<id>/revoke   POST /api/commands/<id>/confirm      /api/device/heartbeat
  GET  /api/commands/...           POST /api/commands/<id>/reject       /api/device/pull
                                                                          /api/device/receipt
                                ┌──────────────────────────────┐
                                │  CommandService (单锁 + 事务)  │
                                │  状态机 / 对账 / 超时清扫       │
                                └──────────────┬───────────────┘
                                               ▼
                    SQLite: commands / targets / receipts /
                            rejected_receipts / device_boots /
                            incidents / incident_events /
                            quarantined_ledger / ledger_uploads /
                            events (哈希链) / devices /
                            seal_requests / seal_events
                    文件:  seal_dir/SEAL-*.json (不可变封存包，原子改名写入)
```

关键恢复语义：设备侧模拟器（`device_sim.py`）遵循真实 PLC 做法——
**执行前先把事实 fsync 写入本地 `ledger.jsonl`，再上送回执**；每条账簿条目带
**指令指纹（创建时冻结 SHA-256）+ prev 哈希链**，HELLO 时整册再用设备密钥
**独立签名**（`ledger_sig`，与传输 HMAC 分开）。网关或链路任何位置崩溃，
设备重连 HELLO 时带签名账簿，网关依次校验**代次→单调编号→指令指纹→连续性**
后与在途指令对账：

- 五重校验通过、账簿有而网关无回执（DOUBT）→ 补记 `LEDGER_RECOVERY`，
  **不重投、不双触发**，对账工单自动置 `RECOVERED`；
- 设备已换 boot_code（确定重启过）且账簿无该指令 → 未执行是确定事实，
  原时限仍有效才重置为可投递（工单 `REDELIVERED`）；时限已过则保持 DOUBT，
  由安全角色核实后人工按未达关闭（不产生任何执行事实）；
- 同 boot_code 但账簿无记录 → 是否正在执行未知，**保持 DOUBT 等待，绝不重投**；
- 坏签名整册隔离且 fail-closed 不重投；编号缺口/序号复用/断链/指纹不符/
  事实矛盾/未投递伪造/旧代次/过期时限材料 → 进隔离区留痕并挂到对应工单，
  不改任何状态；同册重复上送幂等回放。

## 三、快速开始

```bash
# 1. 启动网关（三个通道）
python3 -m dual_gateway.app
# 业务 http://127.0.0.1:8080  安全 http://127.0.0.1:8081  设备 http://127.0.0.1:8082

# 2. 打开安全工作台（第二角色）
#    http://127.0.0.1:8081/login
#    supervisor / S@fety-Confirm-7   （可确认/拒绝）
#    safety     / Audit-Readonly-9   （只读审计）

# 3. 启动模拟设备（真实 PLC 行为：账本 + 心跳 + 回执）
python3 -m dual_gateway.device_sim DEV-A1 --db ./data/sim
python3 -m dual_gateway.device_sim DEV-A2 --db ./data/sim
python3 -m dual_gateway.device_sim DEV-B1 --db ./data/sim

# 4. 业务系统创建高风险指令（返回的 confirm_code 走带外渠道交给第二角色）
curl -s -X POST http://127.0.0.1:8080/api/commands \
  -H 'X-Biz-Token: biz-token-ops-2026' -H 'Content-Type: application/json' \
  -d '{"action":"EMERGENCY_STOP","devices":["DEV-A1","DEV-A2"],
       "params":{"valve":"CLOSE","rpm":0},"valid_seconds":120}'

# 5. 第二角色在工作台输入确认码并复核摘要后确认；设备自动拉取执行并回执
# 6. 审计：工作台 /incidents（事故对账工单）、/quarantine（账簿隔离区）、
#    /audit（哈希链校验）、/seals（审计封存）、/receipts（接受/拒绝回执）

# 7. 审计封存与离线核验（安全通道，supervisor）
curl -s -X POST http://127.0.0.1:8081/api/session \
  -H 'Content-Type: application/json' \
  -d '{"username":"supervisor","password":"S@fety-Confirm-7"}' -c /tmp/ck
curl -s -X POST http://127.0.0.1:8081/api/seals -b /tmp/ck \
  -H 'Content-Type: application/json' -d '{"from_id":1,"to_id":42}'   # 登记申请（幂等）
curl -s -X POST http://127.0.0.1:8081/api/seals/<SEAL-ID>/generate -b /tmp/ck  # 生成封存包
curl -s -X POST http://127.0.0.1:8081/api/seals/<SEAL-ID>/verify   -b /tmp/ck  # 在线核验
python3 -m dual_gateway.seal_verify data/seals/<SEAL-ID>.json --db data/gateway.db  # 独立离线核验
```

一键观看全部攻击/故障场景（撤销边界、超时、旧代号、乱序、序号复用、
网关崩溃+回执丢失、设备重启、离线恢复、坏签名/指纹/缺口账簿隔离、
重复上送幂等、人工处置边界、审计校验）：

```bash
python3 demo.py
```

设备模拟器故障注入开关：`--drop-receipt`（执行了但丢回执，考验账本补记）、
`--offline`（全程离线）、`--fail-rate 0.5`（随机执行失败）。

## 四、业务通道 API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/commands` | 创建并冻结指令；响应一次性返回 `confirm_code` |
| GET | `/api/commands?status=` | 列表 |
| GET | `/api/commands/{id}` | 详情（含每个设备目标状态与回执） |
| POST | `/api/commands/{id}/revoke` | 撤销（受上述硬约束） |

设备通道全部 POST JSON，头部 `X-Device-Id` + `X-Signature: HMAC_SHA256(key, body)`：
`/api/device/hello`（含 `boot_code`、`first_seq`、`ledger` 及整册独立签名
`ledger_sig=HMAC(key,"gw-ledger/v1"‖canonical(ledger))`；条目含
`command_id,boot_code,seq,result,digest(指令指纹),message,prev(哈希链)`）、
`/heartbeat`、`/pull`、`/receipt`（`boot_code,seq,command_id,result,message`）。

## 五、审计封存与离线核验

**封存包**（`seal_dir/SEAL-*.json`，落盘后不可变）内容：

| 字段 | 含义 |
|---|---|
| `from_id` / `to_id` | 封存区间首尾事件号（含两端） |
| `prev_hash` | 前序链头：区间前一条事件的哈希（起点为 1 时是创世哈希） |
| `end_hash` | 末尾摘要：区间最后一条事件的哈希 |
| `events[]` | 逐事件证明：每条事件完整内容 + 链式哈希 |
| `package_hash` | 以上全部内容的整体摘要 |

**生命周期**：`PENDING 待处理`（唯一可撤销状态）→ `SEALING 生成中` →
`SEALED 已封存`；在线核验失败置 `VERIFY_FAILED 核验失败`（保留证据，可复核验回
SEALED）。同一区间 `(from_id,to_id)` 由数据库部分唯一索引保证**至多一份有效申请**，
重复/并发申请返回原结果；已封存记录没有任何代码路径会改写包字段。
生成中进程崩溃：重启恢复发现包已完整落盘且与当前链重算一致 → **续完同一份包**；
否则删除半成品（含 `.tmp`）并**回滚为 PENDING 可重试**——不留半成品、不占永久锁。

**核验**（在线 `POST /api/seals/{id}/verify` 与离线命令共用
`dual_gateway/seal.py::verify_package`，结论一致）按序检查并**定位首个断点**：

1. 包内校验：结构 → 逐事件哈希 → 链式指针 → 末尾摘要 → 整体摘要
   → 失败即 `PACKAGE_CORRUPT 包内损坏`；
2. 前序历史：重放数据库中区间前的链并比对链头锚点
   → 失败即 `PRIOR_HISTORY_MISMATCH 前序历史不匹配`（历史被改/整库被换）；
3. 覆盖性：数据库必须包含区间内全部事件号
   → 缺失即 `DB_LAGGING 数据库落后于封存`（中间记录被删/库被回滚）；
4. 逐事件比对：库中每条事件的哈希与全部字段必须与包内证明一致
   → 分歧即 `DB_DIVERGED 数据库内容与封存不符`（记录被离线修改）。

离线命令只读打开数据库，不依赖网关进程，退出码 0=通过 / 1=失败：

```bash
python3 -m dual_gateway.seal_verify data/seals/SEAL-xxx.json --db data/gateway.db [--json]
```

安全通道 API：`POST /api/seals`（申请，幂等）、`GET /api/seals?status=`、
`GET /api/seals/{id}`（含处置历史）、`POST /api/seals/{id}/generate`、
`POST /api/seals/{id}/cancel`（仅 PENDING）、`POST /api/seals/{id}/verify`、
`GET /api/seals/{id}/package`（下载封存包）。工作台页面：`/seals`。

## 六、运行测试

```bash
python3 -m unittest tests.test_service -v   # 领域规则单元测试（含工单/账簿五重校验）
python3 -m unittest tests.test_seal    -v   # 审计封存/离线核验/崩溃恢复单元测试
python3 -m unittest tests.test_e2e     -v   # 真实三端口 HTTP + 进程级重启端到端（含封存）
```

## 七、生产化备注（本实现未做、真实部署必须做的事）

- 三通道分别绑定独立网卡/网段并加 mTLS 或专线；本实现用端口隔离演示；
- 设备密钥经 KMS/烧录下发并支持轮换；确认码接真实带外通道（硬令牌/语音）；
- SQLite 可替换为 Postgres（接口已集中在 `storage.py`），多实例时用其行锁/SELECT FOR UPDATE；
- 工作台前置于企业 SSO + 强 MFA，会话 Cookie 加 Secure；
- 封存包应同步到独立 WORM 存储/异地，并把 `package_hash` 定期锚定到外部时间戳服务；
  本实现的封存包已具备自校验能力，但包文件本身与数据库放在同一台机器上时，
  两者同时被替换的攻击需要外部锚点才能发现。
