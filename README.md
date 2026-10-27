# 华为防火墙自动化 API 部署说明

接口、鉴权、任务队列和 Ansible 执行链的维护说明见
[`docs/接口设计与维护说明.md`](docs/接口设计与维护说明.md)。

本项目启动两个进程：

- FastAPI：提供 `/admin-ui`、`/test-ui` 和业务 API。
- Worker：从本地 SQLite 队列读取任务，调用 Ansible Runner 执行防火墙变更。

业务变更接口会先返回 `202 Accepted` 和 `job_id`。父任务内的防火墙子任务并行执行并逐台校验；配置失败在同一父任务内有限重试，预检失败则按计划释放队列后重试。全量快照会并行查询所有启用防火墙，但存在修复中的父任务时暂停查询，改用一致性检查查看差异。

## 1. 准备环境

服务器需要：

- Python 3.12
- Git
- OpenSSH Client
- OpenSSL
- 可访问 Keycloak
- 可 SSH 到 Huawei USG6000E

安装系统依赖：

```bash
# CentOS / RHEL
sudo yum install -y git openssh-clients openssl

# Ubuntu / Debian
sudo apt update
sudo apt install -y git openssh-client openssl
```

拉取代码：

```bash
git clone git@github.com:m15608293998-arch/FireWalld-AutoMation.git
cd FireWalld-AutoMation
```

安装 Python 依赖：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

检查：

```bash
python --version
ansible-playbook --version
```

## 2. 准备 Keycloak

在 `trade-access` Realm 下提前创建这些 Client。

### `trade-access-api`

创建 Client Role：

```text
trade-access-user
trade-access-admin
```

其他 Client 签发的 Access Token 需要让 `aud` 包含：

```text
trade-access-api
```

### `trade-access-portal`

普通用户登录 `/test-ui` 用。

```text
Client authentication: OFF
Standard flow: ON
PKCE method: S256
Valid redirect URIs: http://<API_HOST>:8000/test-ui
Web origins: http://<API_HOST>:8000
```

### `trade-access-admin-portal`

管理员登录 `/admin-ui` 用。

```text
Client authentication: OFF
Standard flow: ON
PKCE method: S256
Valid redirect URIs: http://<API_HOST>:8000/admin-ui
Web origins: http://<API_HOST>:8000
```

### `trade-access-offline`

普通用户创建长期 `sk-<offline_token>` API Key 用。

```text
Client authentication: ON
Standard flow: ON
PKCE method: S256
Valid redirect URIs: http://<API_HOST>:8000/api/v1/auth/offline/callback
Optional client scope: offline_access
```

记录这个 Client 的 Secret，后面写入 API 环境变量。

### `trade-access-provisioner`

后端管理 Keycloak User 用。

```text
Client authentication: ON
Service accounts: ON
```

Service Account 分配：

```text
realm-management:query-users
realm-management:query-clients
realm-management:manage-users
```

记录这个 Client 的 Secret，后面写入 API 环境变量。

## 3. 配置防火墙连接

编辑：

```bash
vi group_vars/all.yml
```

测试环境保持一个 `TEST-FW` 配置档即可。账号密码登录示例：

```yaml
trade_access_api:
  firewall_targets:
    - "TEST-FW"
  firewall_parallel_workers: 3
  # 整个父任务生命周期内，每个防火墙子任务累计最多执行 2 次。
  firewall_child_max_attempts: 2
  # 第一次可恢复配置失败后，在父任务内短暂退避再只重试失败节点。
  firewall_reconcile_retry_seconds: 3

default_firewall_code: "TEST-FW"
firewall_profiles:
  TEST-FW:
    firewall_device:
      device_host: "<FIREWALL_MGMT_IP>"
      device_port: 22
      device_user: "<FIREWALL_USER>"
      auth_type: "password"
      device_password: "<FIREWALL_PASSWORD>"
    address_vsystems:
      - name: "public"
        address_set_name: "TraderServers-DirectAccess-IPs"
        switch_required: false
      - name: "Internet"
        address_set_name: "TraderServers-DirectAccess-IPs"
        switch_required: true
      - name: "private"
        address_set_name: "TraderServers-DirectAccess-IPs"
        switch_required: true
    application_vsystem: "private"
    user_defined_application:
      name_prefix: "UD_TServe_"
      category: "General"
      subcategory: "General_TCP"
      data_model: "client-server"
      label: "Business-Applications"
      application_group_name: "UDG_TradeServers"
```

`trade_access_api` 会被 API 和 worker 直接读取；同名的
`TRADE_ACCESS_API_FIREWALL_*` 环境变量只作为兼容覆盖项。版本控制中的
`firewall_device` 保留连接信息占位值；实际管理 IP、用户名和密码填写到被 Git
忽略的 `.runtime/firewall-devices.yml`，以防火墙代码为键覆盖对应设备的连接字段。
`device_port` 省略时默认为 `22`，也可在本地文件中覆盖端口或 SSH 私钥配置。

```bash
mkdir -p .runtime
install -m 600 config/production/firewall-devices.yml.example .runtime/firewall-devices.yml
vi .runtime/firewall-devices.yml
```

本地文件示例：

```yaml
TEST-FW:
  device_host: "<FIREWALL_MGMT_IP>"
  device_user: "<FIREWALL_USER>"
  device_password: "<FIREWALL_PASSWORD>"
```

Role 只接受权限为 `0600` 或 `0400` 的本地凭据文件，加载时屏蔽敏感事件。API、worker
和直接执行 Playbook 均会使用该文件。部署在其他位置时，可通过 Ansible 变量
`firewall_device_credentials_file` 指定绝对路径。不要将填写后的文件提交到 Git。

也可以将配置档中的设备认证改为 SSH 私钥：

```yaml
firewall_profiles:
  TEST-FW:
    firewall_device:
      device_host: "<FIREWALL_MGMT_IP>"
      device_port: 22
      device_user: "<FIREWALL_USER>"
      auth_type: "publickey"
      identity_file: "/absolute/path/to/firewall_private_key"
```

私钥必须对运行 API 的账号可读，建议权限设为 `0600`。密码和私钥配置二选一。
同一个 `group_vars/all.yml` 文件末尾已经注释保存了完整生产配置：

```text
BEGIN_PRODUCTION_CONFIG ... END_PRODUCTION_CONFIG
```

生产启用时删除或注释上面的 TEST-FW 配置，将该生产区块整体取消注释，并在
`.runtime/firewall-devices.yml` 中填写 PG-FW、PG-FW-1、IDC-FW 各自的连接信息。
生产区块完整展开，不使用 `&/*`，也不使用环境变量引用。

生产拓扑为：

| 防火墙 | IP 空间 | Application 空间 |
| --- | --- | --- |
| `PG-FW` | `public`、`private`、`Internet` | `private` |
| `PG-FW-1` | `public` | `public` |
| `IDC-FW` | `private`、`Internet` | `private` |

公共容量配置继续保留在 `group_vars/all.yml`：

```yaml
rule_port_limit: 4
application_rule_limit: 8
enable_application_config: true
commit_security_engine: true
save_config: true
```

每条 Rule 最多 4 个端口、每个 Application 最多 8 条 Rule；超过 32 个端口后
依次创建 `_2`、`_3` 等对象。华为设备强制要求用户自定义 Application 名以
`UD_` 开头，Playbook 会在连接设备前校验。

## 4. 配置 API 环境变量

创建运行配置文件：

```bash
mkdir -p .runtime
vi .runtime/trade-access.env
```

写入：

```env
TRADE_ACCESS_API_AUTH_ENABLED=true

TRADE_ACCESS_API_DATABASE_PATH=.runtime/api/jobs.sqlite3
TRADE_ACCESS_API_RUNNER_PRIVATE_DATA_DIR=.runtime/runner
TRADE_ACCESS_API_JOB_TMP_ROOT=.runtime/jobs

# 防火墙目标、并发数、单轮重试次数和跨轮修复间隔统一配置在 group_vars/all.yml 的
# trade_access_api 中，不需要在这里重复配置。

TRADE_ACCESS_API_KEYCLOAK_SERVER_URL=http://<KEYCLOAK_HOST>:8080
TRADE_ACCESS_API_KEYCLOAK_REALM=trade-access
TRADE_ACCESS_API_KEYCLOAK_CLIENT_ID=trade-access-api

TRADE_ACCESS_API_KEYCLOAK_BROWSER_CLIENT_ID=trade-access-portal
TRADE_ACCESS_API_KEYCLOAK_BROWSER_SCOPE=openid profile email

TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_CLIENT_ID=trade-access-admin-portal
TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_SCOPE=openid profile email

TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_ID=trade-access-offline
TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_SECRET=<TRADE_ACCESS_OFFLINE_SECRET>
TRADE_ACCESS_API_KEYCLOAK_OFFLINE_SCOPE=openid profile offline_access
TRADE_ACCESS_API_OFFLINE_API_KEY_TOKEN_ENCRYPTION_KEY=<STABLE_RANDOM_ENCRYPTION_KEY>

TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_ID=trade-access-provisioner
TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET=<TRADE_ACCESS_PROVISIONER_SECRET>

TRADE_ACCESS_API_KEYCLOAK_USER_ROLE=trade-access-user
TRADE_ACCESS_API_KEYCLOAK_ADMIN_ROLE=trade-access-admin
```

`TRADE_ACCESS_API_OFFLINE_API_KEY_TOKEN_ENCRYPTION_KEY` 用于加密保存当前有效 offline token。Keycloak 轮换 refresh token 后，后端会加密保存新 token，因此这个密钥生成后必须长期保持不变。可以用下面命令生成：

```bash
openssl rand -base64 32
```

如果 Keycloak 是 HTTPS 且用了内部 CA，再加：

```env
TRADE_ACCESS_API_KEYCLOAK_CA_CERT=/path/to/internal-ca.pem
```

也可以用脚本生成这个文件：

```bash
source .venv/bin/activate
python scripts/configure_runtime.py \
  --keycloak-server-url http://<KEYCLOAK_HOST>:8080
```

脚本会提示输入：

```text
Provisioning Client Secret
Offline API Key Client Secret
Offline API Key Token Encryption Key
```

## 5. 初始化第一个管理员

先在 Keycloak 里给管理员 User 分配：

```text
trade-access-api:trade-access-admin
```

然后用该 User 的 Keycloak UUID 写入本地权限：

```bash
source .venv/bin/activate
python scripts/manage_permissions.py grant \
  --subject-id '<KEYCLOAK_USER_UUID>' \
  --profile admin
```

查看：

```bash
python scripts/manage_permissions.py list --subject-id '<KEYCLOAK_USER_UUID>'
```

## 6. 启动服务

启动 API 和 Worker：

```bash
source .venv/bin/activate
python scripts/run_services.py --host 0.0.0.0 --port 8000
```

指定配置文件启动：

```bash
source .venv/bin/activate
python scripts/run_services.py \
  --env-file .runtime/trade-access.env \
  --host 0.0.0.0 \
  --port 8000
```

访问：

```text
http://<API_HOST>:8000/admin-ui
http://<API_HOST>:8000/test-ui
```

健康检查：

```bash
curl http://127.0.0.1:8000/healthz
```

返回：

```json
{"status":"ok"}
```

`/healthz` 用于 API 进程存活检查。运行就绪检查使用：

```bash
curl -i http://127.0.0.1:8000/readyz
```

数据库可读写、Worker 心跳和任务阶段均正常时返回 `200`、`status=ready`；Worker
停止、心跳过期、持续无法领取任务、阶段超过预算或数据库不可用时返回 `503`。
响应包含检查结果、Worker 阶段、最近心跳年龄、待处理任务数量及最老排队时间。
正常配置/验证按各自执行预算判断，期间心跳独立更新，避免把长任务当作失联。
首次预检失败后的计划重试等待不算执行停滞，但仍受父任务截止时间约束。
就绪检查不访问 Keycloak 或防火墙，也不改变已有任务入队和查询语义。

## 7. 调用 API

浏览器用户可以通过 `/test-ui` 登录。Postman、`curl` 等外部调用统一使用 Bearer 认证，凭据可以是：

- Keycloak 返回的 Access Token。
- 页面创建的长期 API Key，格式必须是 `sk-<offline_token>`。

Keycloak 签名密钥默认缓存 300 秒；同一 API 进程的 JWKS 刷新默认至少间隔 10 秒，
并发请求共用一次刷新，未知 `kid` 不能逐次触发网络访问。刷新期间已有有效缓存的
Token 仍正常验签。新签名密钥若在冷却期内首次出现，调用方需在冷却结束后重试；
通过 `TRADE_ACCESS_API_KEYCLOAK_JWKS_REFRESH_MIN_INTERVAL_SECONDS` 调整间隔，
实际冷却不超过密钥缓存有效期。缓存已过期且 Keycloak 不可用时仍拒绝认证。

先调用当前身份接口，确认角色、权限和本地登记的 `allowed_ips`：

```bash
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/me
```

所有防火墙变更目前只接受单个 IPv4 地址，`mask` 必须是 `32`。三个放行接口
（`allow`、`allow/ip`、`allow/ports`）还会拒绝 RFC1918 私网地址：
`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`。API 会在任务入队前返回
`422`；`deny`、`deny/ip`、`deny/ports` 仍接受这些地址，以便清理历史错误配置。
例如，同时放行 IP 和端口：

```bash
curl -X POST \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "203.0.113.10",
    "mask": 32,
    "ports": [12001, 12002],
    "description": "trade-server-203.0.113.10",
    "client_request_id": "change-20260714-001"
  }' \
  http://127.0.0.1:8000/api/v1/trade-access/allow
```

变更接口：

| 接口 | 含义 | 请求是否包含 `ports` |
| --- | --- | --- |
| `POST /api/v1/trade-access/allow` | 放行 IP，并增加指定端口 | 是 |
| `POST /api/v1/trade-access/allow/ip` | 只将 IP 加入所有业务地址集 | 否 |
| `POST /api/v1/trade-access/allow/ports` | IP 已存在时增加指定端口 | 是 |
| `POST /api/v1/trade-access/deny/ports` | 删除指定端口 | 是 |
| `POST /api/v1/trade-access/deny/ip` | 确认该 IP 已无应用端口后，再移出所有业务地址集 | 否 |
| `POST /api/v1/trade-access/deny` | 删除该 IP 的全部应用端口，再移出所有业务地址集 | 否 |

`client_request_id` 是可选幂等键。同一用户使用相同键提交相同动作、IP、掩码、
规范化端口和描述时，返回原 `job_id` 及当前状态，保留原防火墙目标；已成功、失败或
取消的任务也不会重新执行。相同键用于不同内容返回 `409`。需要发起新变更或重做
已失败/取消的任务时使用新键；省略该字段则每次创建新任务。升级前若同一用户的某个
键对应多个历史任务，重用会返回 `409`，客户端需换新键。

接口路径不区分防火墙。新任务会创建 `firewall_targets` 中所有设备的子任务，
并在同一个父任务内并行执行。端口必须在 `1` 到 `65535` 之间，单次最多提交
256 个。变更接口返回 `job_id` 后，查询任务和 Ansible 事件：

```bash
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/<JOB_ID>

curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/events/<JOB_ID>

# 仅在深度排障时读取完整 Ansible 原始事件
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  'http://127.0.0.1:8000/api/v1/trade-access/jobs/events/<JOB_ID>?detail=full'
```

任务详情的 `desired_state` 是该 IP 的完整业务期望状态，`target_results` 是逐台
防火墙的变更前、期望和实测结果。只有全部子任务完成所启用的提交/保存，且逐虚拟
系统地址及原始应用配置实时校验一致，父任务才是
`successful`。已有期望基线的任务和配置阶段重试均跳过预检；未知 IP 的基线查询
失败会有限重试。完整 `deny` 直接采用“地址和应用全部不存在”的期望，无账本且
节点状态不一致时也可逐台清理；每台设备仍先检查应用归属，拒绝删除绑定其他 IP 或
详情不完整的对象。普通 runner 失败时不做中间完整查询，父任务内部短暂退避后只重试
失败节点。端口任务按固定的完整期望端口
重新计算差量，重试时即使没有增删也会补提交/保存。所有节点的 runner 均成功后做
最终验证；提交或保存失败不能仅凭配置已存在而改判成功。当前父任务终止前，后来
的任务不会插入这次修复过程。
事件接口默认返回关键业务步骤摘要，`detail=full` 才返回全部 Ansible 事件。普通用户
只能读取自己的任务，管理员可读取全部任务。
响应增加 `audit_status`、`audit_warnings`，每条事件携带 `run_id`，便于区分多次尝试。
日志不完整、已过期或被清理时接口与页面明确提示。变更、预检和最终验证日志按任务
长期保留；普通快照单独保留最近 20 次，查询轮转不会删除变更证据。旧日志路径仍可
读取；升级前已删除的日志无法恢复。
逐台结果的 `verification_attempt_count` 持久化验证尝试次数，重启后继续累计，
任一次已记录验证的日志缺失都会触发不完整提示；旧任务升级前的验证次数无法补算。

取消尚未准备配置的任务：

```bash
curl -X POST \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/<JOB_ID>/cancel
```

普通用户只能取消自己的任务，管理员使用
`POST /api/v1/admin/trade-access/jobs/<JOB_ID>/cancel` 取消任意用户任务。仅允许取消
排队、只读预检或等待预检重试的任务；进入配置准备后返回 `409`。取消成功返回
`200` 和 `canceled` 状态，重复取消仍返回原结果。正在运行的只读预检会在查询完成
或超时后退出，不会继续写入期望账本或下发配置。

执行边界通过 API 与 worker 共用的环境文件配置，生产示例见
[`config/production/trade-access.env.example`](config/production/trade-access.env.example)：

| 环境变量 | 默认值 | 含义 |
| --- | --- | --- |
| `TRADE_ACCESS_API_JOB_TIMEOUT_SECONDS` | `1800` | 首次认领起的父任务总预算，包含预检、退避、配置和验证 |
| `TRADE_ACCESS_API_RUNNER_TIMEOUT_SECONDS` | `900` | 单次配置 Runner 的执行预算 |
| `TRADE_ACCESS_API_SNAPSHOT_TIMEOUT_SECONDS` | `300` | 单次设备查询及全量查询的总预算 |
| `TRADE_ACCESS_API_RUNNER_LOCK_TIMEOUT_SECONDS` | `10` | 全局编排锁与单设备 Runner 锁的最长等待时间 |
| `TRADE_ACCESS_API_PRECHECK_MAX_ATTEMPTS` | `3` | 持久化的基线查询尝试上限，包含首次查询 |
| `TRADE_ACCESS_API_WORKER_HEARTBEAT_INTERVAL_SECONDS` | `2` | Worker 独立心跳写入周期 |
| `TRADE_ACCESS_API_WORKER_HEARTBEAT_TIMEOUT_SECONDS` | `15` | 心跳过期时间及阶段结束宽限，须大于两倍心跳周期 |
| `TRADE_ACCESS_API_WORKER_PROGRESS_TIMEOUT_SECONDS` | `60` | 任务轮询、准备阶段的推进预算 |
| `TRADE_ACCESS_API_QUERY_MAX_WAITERS` | `16` | 额外等待同一实时查询的请求上限 |
| `TRADE_ACCESS_API_QUERY_WAIT_TIMEOUT_SECONDS` | `10` | 同类合并请求的最长等待时间 |

任务详情增加 `deadline_at`、`precheck_attempt_count`。排队时间不计入父任务预算；
首次认领后，重试和 worker 重启都保留原截止时间。预检退避从
`firewall_reconcile_retry_seconds` 开始倍增，最多 60 秒，并受剩余预算限制。
超时停止继续执行；若已开始配置，设备可能存在部分变更，须结合逐台结果和 `check`
人工处理。快照锁等待或执行超时返回 `503`。

## 8. 查询与一致性检查

快照数据来自所有启用防火墙的实时 CLI 查询，任务库用于执行边界和状态检查：

每个 API 进程最多运行一个全节点查询，内部仍按设备并行配置执行。正在运行的同类
查询可由其他请求共享，额外最多 16 个等待请求，默认等待 10 秒；不同类型查询或
等待人数超限时快速返回 `503` 和 `Retry-After: 1`。`snapshot` 与 `snapshot/ports`
共用同类额度，一致性检查也受查询额度限制。结果只在执行期间共享，后续请求重新
查询设备。取消 HTTP 请求不会提前释放仍在执行的 Runner 额度。
同组请求共享结果等待，连续取消或超时不会在底层执行上累积等待回调。

```bash
# 一次查询每台防火墙的 IP 和端口，并生成逐台人工纠错建议
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/firewall/check

# 同时存在于 address_vsystems 所有业务地址集中的有效 /32 IP
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/firewall/snapshot/ips

# 有效 IP 在应用规则中实际绑定的 TCP 端口
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/firewall/snapshot/ports
```

`check` 在三台一致或存在漂移时均返回 HTTP `200`，通过 `overall_status` 区分
`consistent` 和 `drifted`。响应包含 IP/端口差异、每台设备的缺失/多余项，以及
按严格多数节点计算的 `suggested_actions`；建议仅供人工核实，不会自动执行。任一
设备查询失败时返回 HTTP `503`、`overall_status=incomplete`，且不生成纠错动作。

存在 `reconciling` 父任务时，普通全量快照接口返回 HTTP `409`，避免把已知不一致
状态当作可用清单；`check` 仍可执行，用于查看失败节点和人工纠错建议。测试页和管理
页均提供“检查节点一致性”按钮，测试页任务详情还会展示逐台子任务状态。

三台逻辑结果完全一致时返回 HTTP `200` 和干净的 `items`；结果漂移返回 HTTP
`409` 及逐台差异；任一设备查询失败返回 HTTP `503`，不会把部分结果当成全量
结果。完整恢复和一致性边界见
[`docs/多防火墙并行编排与一致性说明.md`](docs/多防火墙并行编排与一致性说明.md)。
