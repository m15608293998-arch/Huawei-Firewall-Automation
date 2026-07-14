# 华为防火墙自动化 API 部署说明

本项目启动两个进程：

- FastAPI：提供 `/admin-ui`、`/test-ui` 和业务 API。
- Worker：从本地 SQLite 队列读取任务，调用 Ansible Runner 执行防火墙变更。

业务变更接口会先返回 `202 Accepted` 和 `job_id`，再由 Worker 串行执行。防火墙快照接口会同步调用 Ansible Runner，直接返回设备当前的有效 IP 或 IP:Port 结果。

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
git clone git@github.com:m15608293998-arch/Huawei-Firewall-Automation.git
cd Huawei-Firewall-Automation
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

账号密码登录：

```yaml
firewall_device:
  device_host: "<FIREWALL_MGMT_IP>"
  device_user: "<FIREWALL_USER>"
  auth_type: "password"
  device_password: "<FIREWALL_PASSWORD>"
```

或者使用 SSH 私钥登录：

```yaml
firewall_device:
  device_host: "<FIREWALL_MGMT_IP>"
  device_user: "<FIREWALL_USER>"
  auth_type: "publickey"
  identity_file: "/absolute/path/to/firewall_private_key"
```

私钥必须对运行 API 的账号可读，建议权限设为 `0600`。密码和私钥配置二选一。

继续确认这些业务配置：

```yaml
address_vsystems:
  - name: "public"
    address_set_name: "<PUBLIC_ADDRESS_SET>"
    switch_required: false

  - name: "Internet"
    address_set_name: "<INTERNET_ADDRESS_SET>"
    switch_required: true

  - name: "private"
    address_set_name: "<PRIVATE_ADDRESS_SET>"
    switch_required: true

application_vsystem: "private"

user_defined_application:
  name_prefix: "UD_TS_"
  category: "General"
  subcategory: "General_TCP"
  data_model: "client-server"
  label: "Business-Applications"
  application_group_name: "<APPLICATION_GROUP_NAME>"

rule_port_limit: 4
enable_application_config: true
commit_security_engine: true
save_config: true
```

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
TRADE_ACCESS_API_RUNNER_TIMEOUT_SECONDS=900
TRADE_ACCESS_API_SNAPSHOT_RUNNER_TIMEOUT_SECONDS=300

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
# API 进程存活
curl http://127.0.0.1:8000/healthz

# API 和任务数据库已就绪
curl http://127.0.0.1:8000/readyz
```

返回：

```json
{"status":"ok"}
{"status":"ready"}
```

## 7. 调用 API

浏览器用户可以通过 `/test-ui` 登录。Postman、`curl` 等外部调用统一使用 Bearer 认证，凭据可以是：

- Keycloak 返回的 Access Token。
- 页面创建的长期 API Key，格式必须是 `sk-<offline_token>`。

先调用当前身份接口，确认角色、权限和本地登记的 `allowed_ips`：

```bash
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/me
```

所有防火墙变更目前只接受单个 IPv4 地址，`mask` 必须是 `32`。例如，同时放行 IP 和端口：

```bash
curl -X POST \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "203.0.113.10",
    "mask": 32,
    "ports": [12001, 12002],
    "description": "trade-server-203.0.113.10"
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

端口必须在 `1` 到 `65535` 之间，单次最多提交 256 个。变更接口返回 `job_id` 后，查询任务和 Ansible 事件：

```bash
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/<JOB_ID>

curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/events/<JOB_ID>
```

普通用户只能读取自己的任务；管理员可在 `/admin-ui` 查看全部任务。

## 8. 查询防火墙快照

快照来自防火墙实时 CLI 查询，不读取 SQLite 任务库：

```bash
# 同时存在于 address_vsystems 所有业务地址集中的有效 /32 IP
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/firewall/snapshot/ips

# 有效 IP 在应用规则中实际绑定的 TCP 端口
curl \
  -H 'Authorization: Bearer <ACCESS_TOKEN_OR_SK>' \
  http://127.0.0.1:8000/api/v1/trade-access/firewall/snapshot/ports
```

IP 快照返回：

```json
{
  "generated_at": "2026-07-14T10:00:00+00:00",
  "items": [
    {"ip": "203.0.113.10"}
  ]
}
```

端口快照返回：

```json
{
  "generated_at": "2026-07-14T10:00:00+00:00",
  "items": [
    {"ip": "203.0.113.10", "port": 12001}
  ]
}
```

`GET /api/v1/trade-access/firewall/snapshot` 是兼容接口，当前与 `/snapshot/ports` 返回相同类型的 IP:Port 结果。

## 9. 运行测试

项目测试使用 Python 标准库 `unittest`：

```bash
source .venv/bin/activate
python -m unittest discover -s tests
```

## 10. 后台运行

简单后台运行：

```bash
nohup .venv/bin/python scripts/run_services.py \
  --env-file .runtime/trade-access.env \
  --host 0.0.0.0 \
  --port 8000 \
  > .runtime/trade-access.log 2>&1 &
echo $! > .runtime/trade-access.pid
```

查看日志：

```bash
tail -f .runtime/trade-access.log
```

停止：

```bash
kill "$(cat .runtime/trade-access.pid)"
rm -f .runtime/trade-access.pid
```
