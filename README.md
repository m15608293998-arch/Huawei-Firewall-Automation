# Huawei 防火墙自动化脚本使用

本项目用于通过 Ansible 自动化管理 Huawei USG6000E 防火墙上的交易服务器临时放行和撤销操作。

当前执行模型：

```text
Ansible 控制节点本地执行 playbook
  ↓
playbook 调用 usg6000e_trade_access role
  ↓
role 调用 files/run_usg_cli.py
  ↓
run_usg_cli.py 通过 SSH 登录 Huawei USG6000E
  ↓
执行 system-view / switch vsys / address-set / application / commit / save 等 CLI 命令
```

API 和 Worker 启动后，可通过下面的地址打开内置测试页面：

```text
http://<API节点IP>:8000/test-ui
http://<API节点IP>:8000/admin-ui
```

管理员使用 Keycloak User 登录 `/admin-ui`，为已有 Keycloak User 配置接口权限和启停状态。
普通员工访问 `/test-ui` 完成 Keycloak 登录后，可以创建以 `sk-` 开头的长期 API Key。
该 Key 可通过 `curl`、Postman 或自动化脚本调用业务 API，不需要重复登录页面获取短期 Token。

本地或测试环境可以一次性保存Keycloak配置，之后启动时自动加载：

```bash
python3.12 scripts/configure_runtime.py \
  --keycloak-server-url http://192.168.6.30:8080
```

命令会隐藏读取Provisioning Client Secret，并保存到已被Git忽略的：

```text
.runtime/trade-access.env
```

文件权限为`600`。此后只需执行：

```bash
python3.12 scripts/run_services.py
```

也可显式指定其他配置文件：

```bash
python3.12 scripts/run_services.py --env-file /etc/trade-access/trade-access.env
```

首次生产环境部署请参阅：

[docs/首次生产环境部署全流程准备操作.md](docs/首次生产环境部署全流程准备操作.md)

注意：Ansible 的任务执行目标是 `localhost`，不是直接把 Ansible module 下发到防火墙。防火墙连接由 `run_usg_cli.py` 负责。



## 1. 在新机器上部署

假设你拿到的包名为：

```bash
ansible-firewalld_cli_files.tar.gz
```

### 1.1 解压

```bash
tar zxf ansible-firewalld_cli_files.tar.gz
cd ansible-firewalld_cli_files
```

### 2.2 安装系统依赖

CentOS / RHEL：

```bash
sudo yum install -y python3 python3-pip openssh-clients tree
```

Ubuntu / Debian：

```bash
sudo apt update
sudo apt install -y python3 python3-pip openssh-client tree
```

注意：上面的 `python3` 是系统基础包。API 服务和本项目 Python 依赖统一使用 `python3.12`，不要使用系统默认 Python 3.6 运行。

### 2.3 安装 Ansible Runner 和 Python 依赖

```bash
python3.12 -m pip install --user -r requirements.txt
```

检查：

```bash
python3.12 -m pip --version
ansible-playbook --version
python3.12 -c "import pexpect; print('pexpect ok')"
```

如果提示找不到 `ansible-playbook`，执行：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

建议写入 `~/.bashrc`：

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### 2.4 设置脚本权限

```bash
chmod +x roles/usg6000e_trade_access/files/run_usg_cli.py
chmod +x roles/usg6000e_trade_access/files/extract_usg_address_id.py
```

---

## 3. 配置防火墙 SSH 登录方式

只有底层 Ansible API 服务需要 SSH 登录防火墙。业务调用方的 Keycloak 凭据只用于换取访问令牌，不参与防火墙 SSH 登录。

当前项目支持两种设备认证方式：

```text
1. password   账号密码登录，适合你当前“不使用预置公钥私钥免密登录”的要求
2. publickey  私钥登录，保留为兼容方案
```

推荐优先使用 `password`，并把设备密码放进 `Ansible Vault`，不要在 `group_vars/all.yml` 里保存明文密码。

### 3.1 使用账号密码登录（推荐）

`group_vars/all.yml` 示例：

```yaml
firewall_device:
  device_host: "192.168.6.54"
  device_user: "admin"
  auth_type: "password"
  device_password: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    ...
```

生成加密密码：

```bash
ansible-vault encrypt_string 'YourPassword' --name 'device_password'
```

手工验证 SSH：

```bash
ssh -tt \
  -o PreferredAuthentications=password,keyboard-interactive \
  -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  admin@192.168.6.54
```

如果你本机装了 `sshpass`，也可以这样做非交互验证：

```bash
sshpass -p 'YourPassword' ssh \
  -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  admin@192.168.6.54 "display version"
```

### 3.2 使用私钥登录（兼容保留）

当前服务运行用户为 `ansiblerun`，防火墙私钥建议固定放在：

```text
/home/ansiblerun/.ssh/usg6000e_slpeng
```

#### 3.2.1 在 Ansible 控制节点生成密钥

```bash
mkdir -p /home/ansiblerun/.ssh
chmod 700 /home/ansiblerun/.ssh
ssh-keygen -t rsa -b 2048 -f /home/ansiblerun/.ssh/usg6000e_slpeng -C "trade-access-api-usg6000e"
chmod 600 /home/ansiblerun/.ssh/usg6000e_slpeng
```

生成文件：

```text
/home/ansiblerun/.ssh/usg6000e_slpeng      私钥
/home/ansiblerun/.ssh/usg6000e_slpeng.pub  公钥
```

查看公钥：

```bash
粘贴此公钥
cat /home/ansiblerun/.ssh/usg6000e_slpeng.pub
```

#### 3.2.2 在 Huawei USG6000E 上绑定公钥

需要防火墙管理员在设备上为 SSH 用户绑定公钥。示例逻辑如下，具体命令以现场设备版本为准：

```text
system-view
rsa peer-public-key ansible-usg6000e-key
public-key-code begin
  粘贴 /home/ansiblerun/.ssh/usg6000e_slpeng.pub 中的 key 内容
public-key-code end
peer-public-key end

ssh user slpeng
ssh user slpeng authentication-type rsa
ssh user slpeng assign rsa-key ansible-usg6000e-key
ssh user slpeng service-type all
```

如果现场已有 SSH 用户和密钥，只需要保证：

```text
1. group_vars/all.yml 中的 device_user 与设备 SSH 用户一致
2. group_vars/all.yml 中的 identity_file 指向正确私钥
3. 控制节点可以 SSH 登录防火墙
```

#### 3.2.3 手工验证 SSH

```bash
ssh -tt \
  -i /home/ansiblerun/.ssh/usg6000e_slpeng \
  -o PreferredAuthentications=publickey \
  -o PasswordAuthentication=no \
  -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  -o HostkeyAlgorithms=+ssh-rsa \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  slpeng@192.168.6.54
```

看到类似下面提示符说明 SSH 正常：

```text
<MicrotradeBJOffice>
```

退出：

```text
quit
```

---

## 4. 变量配置说明

主要修改两个地方：

```text
group_vars/all.yml       平台固定配置，由管理员维护
requests/example_*.yml   每次请求变量，未来可由 API 生成
```

### 4.1 group_vars/all.yml

#### 防火墙连接信息

```yaml
firewall_device:
  device_host: "192.168.6.54"
  device_user: "slpeng"
  auth_type: "publickey"
  identity_file: "/home/ansiblerun/.ssh/usg6000e_slpeng"
```

含义：

```text
device_host   防火墙管理 IP
device_user   SSH 登录用户名
auth_type     password 或 publickey
identity_file SSH 私钥路径
device_password SSH 登录密码（建议用 Ansible Vault 加密）
```

更换防火墙时修改 `device_host`。
更换用户或认证方式时修改 `device_user`、`auth_type` 以及对应的认证字段。

#### address-set 配置

```yaml
address_vsystems:
  - name: "public"
    address_set_name: "VerifyBJ195"
    switch_required: false

  - name: "Internet"
    address_set_name: "Verify195-TradeServers"
    switch_required: true

  - name: "private"
    address_set_name: "Verify195-TradeServers"
    switch_required: true
```

含义：

```text
name              虚拟系统名称
address_set_name  目标 IP 要加入或删除的地址集名称
switch_required   是否需要执行 switch vsys
```

注意：

```text
public 默认就在全局系统视图下，所以 switch_required: false
Internet/private 需要 switch vsys，所以 switch_required: true
```

#### application 配置

```yaml
application_vsystem: "private"

user_defined_application:
  name_prefix: "UD_TS_"
  category: "General"
  subcategory: "General_TCP"
  data_model: "client-server"
  label: "Business-Applications"
  application_group_name: "UD_TradeGroup_Internet"
```

常见需要改的是：

```yaml
application_group_name: "新的应用组名称"
```

#### 业务端口列表

```yaml
application_ports:
  - 12002
  - 12009
  - 12046
  - 12047
  - 12044
  - 12045
```

直接运行 `ansible-playbook` 时，这个列表是默认业务端口。通过 API 执行 `allow` 时，
API 会使用请求体中的 `ports` 动态覆盖它。超过 32 个端口时，role 会自动拆分多个
application。

`allow` 使用追加合并语义。role 会先读取该 IP 已有的 application 端口，再计算：

```text
最终端口 = 已有端口 + 本次请求端口（去重）
```

因此客户端可以重复提交已经放行的端口，也可以只提交本次需要新增的端口，不需要
记住或重新发送完整历史端口列表。存在新增端口时，role 会按每条 rule 4 个端口、
每个 application 8 条 rule 的限制重新生成 `UD_TS_IP`、`UD_TS_IP_2` 等对象。

application 查询采用两阶段精确读取：先通过配置过滤获取属于目标 IP 的 application
名称，再使用 `display application name` 批量读取这些对象的规则和端口。新增端口时，
旧对象删除和完整端口并集重建在一个 SSH 会话中完成，避免返回目标对象之后的整份
防火墙配置，也避免逐个 application 建立 SSH 会话。

#### rule 限制

```yaml
rule_port_limit: 4
application_rule_limit: 8
```

一般不要改。

#### commit / save

```yaml
commit_security_engine: true
save_config: true
```

含义：

```text
commit_security_engine: true  执行 engine configuration commit
save_config: true             执行 save 保存配置
```

安全引擎提交在 `application_vsystem` 指定的虚拟系统中执行。该命令是异步操作，SSH
执行器在设备接受命令并返回 CLI 提示符后继续，不等待引擎编译完成消息。设备立即返回
明确失败时，Ansible 任务仍会失败。

测试阶段如果不想落盘保存，可以临时设置：

```yaml
save_config: false
```

生产建议保持：

```yaml
commit_security_engine: true
save_config: true
```

#### 临时目录

```yaml
local_tmp_dir: "/tmp/usg6000e_trade_access"
```

role 会在这里生成临时 CLI 文件和查询输出。

---

## 5. 请求文件说明

### 5.1 放行请求,修改target_ip为你想放行的ip即可

`requests/example_allow.yml`：

```yaml
access_request:
  action: allow
  target_ip: 192.168.66.22
  mask: 32
  requester: ansible-test
  request_id: REQ-ALLOW-1921686622
  description: 临时放行 192.168.66.22 外网访问
```

字段说明：

```text
action       allow 表示放行
target_ip    要放行的交易服务器 IP
mask         掩码长度，通常为 32
requester    请求人或调用方
request_id   请求编号，建议唯一
description  写入 address-set 的描述信息
```

### 5.2 撤销请求，同5.1

`requests/example_deny.yml`：

```yaml
access_request:
  action: deny
  target_ip: 192.168.66.22
  mask: 32
  requester: ansible-test
  request_id: REQ-DENY-1921686622
  description: 撤销 192.168.66.22 临时外网访问
```

---

## 6. 执行命令

### 6.1 语法检查

```bash
ansible-playbook -i inventory playbooks/trade_server_access.yml --syntax-check
```

### 6.2 执行放行

```bash
ansible-playbook -i inventory playbooks/trade_server_access.yml -e @requests/example_allow.yml
```

### 6.3 执行撤销

```bash
ansible-playbook -i inventory playbooks/trade_server_access.yml -e @requests/example_deny.yml
```

### 6.4 查看执行耗时

```bash
time ansible-playbook -i inventory playbooks/trade_server_access.yml -e @requests/example_allow.yml
```

---

## 7. API 接口化第一版

项目新增了一个 FastAPI API 层，用于通过 HTTP 接口提交放行和撤销任务。

当前 API 执行模型：

```text
HTTP Client
  ↓
FastAPI
  ↓
SQLite 持久化任务队列
  ↓
独立单 Worker
  ↓
ansible-runner
  ↓
playbooks/trade_server_access.yml
  ↓
usg6000e_trade_access role
  ↓
run_usg_cli.py
  ↓
Huawei USG6000E
```

API 层只负责认证鉴权、请求校验、创建任务和状态查询。独立 Worker 按创建顺序领取
`pending` 任务并串行调用 ansible-runner。防火墙配置逻辑仍然由现有 Ansible role 完成。

### 7.1 安装依赖

当前代码已按 Python 3.12 运行环境更新。由于现场 Python 3.12 是通过 `make altinstall` 安装，安装和启动命令都显式使用 `python3.12`，避免落回系统默认 Python 3.6。

```bash
python3.12 -m pip install --user -r requirements.txt
```

如果提示找不到 `uvicorn` 或 `ansible-playbook`：

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 7.2 启动 API 和 Worker

推荐使用统一启动命令：

```bash
python3.12 scripts/run_services.py
```

默认监听 `0.0.0.0:8000`，Worker 每 0.5 秒检查一次队列。需要修改时：

```bash
python3.12 scripts/run_services.py \
  --host 0.0.0.0 \
  --port 8000 \
  --poll-interval 0.5
```

该命令会管理两个独立子进程。按 `Ctrl+C` 会统一停止 API 和 Worker。

排查问题时也可以分别启动：

```bash
python3.12 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

```bash
python3.12 -m api.worker
```

只启动 Uvicorn 时，POST 请求仍会成功创建 `pending` 任务，但没有 Worker 执行任务。

健康检查：

```bash
curl http://127.0.0.1:8000/healthz
```

### 7.3 提交放行任务

`allow` 必须指定本次需要放行的 TCP 端口：

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/trade-access/allow \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "192.168.66.22",
    "mask": 32,
    "ports": [12001, 12002, 12003],
    "description": "临时放行 192.168.66.22 外网访问",
    "client_request_id": "REQ-ALLOW-1921686622"
  }'
```

返回示例：

```json
{
  "job_id": "b2d6f8b9-0c5e-4c4a-9c63-2a1e1c4b7d91",
  "status": "pending",
  "action": "allow",
  "target_ip": "192.168.66.22",
  "ports": [12001, 12002, 12003],
  "client_request_id": "REQ-ALLOW-1921686622"
}
```

端口属于业务请求字段，不再作为 Keycloak 凭据属性。已有 IP 的应用端口与新请求存在
重复时不会报错；role 会保留已有端口，并将本次新增端口合并后重新生成 application。

### 7.4 提交撤销任务

`deny` 会按 IP 删除对应地址集成员和该 IP 的全部应用对象，不需要再次传端口：

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/trade-access/deny \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "192.168.66.22",
    "mask": 32,
    "description": "撤销 192.168.66.22 临时外网访问",
    "client_request_id": "REQ-DENY-1921686622"
  }'
```

### 7.5 查询任务状态

```bash
curl -s \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/<job_id>
```

普通接口按 Keycloak access token 中稳定的 `sub` 隔离任务。令牌刷新后 `sub` 不变，因此
仍可查询原任务。普通用户还可以查询自己的任务列表：

```bash
curl -s \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  'http://127.0.0.1:8000/api/v1/trade-access/jobs?limit=100&status=successful'
```

任务状态：

```text
pending     已提交，等待执行
running     已由 Worker 领取，正在执行 ansible-runner
successful  执行成功
failed      执行失败
canceled    预留状态，当前未实现取消
```

### 7.6 查询任务事件

```bash
curl -s \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://127.0.0.1:8000/api/v1/trade-access/jobs/events/<job_id>
```

该接口返回经过简化的 ansible-runner 事件，不默认暴露完整防火墙输出。

### 7.7 API 请求字段说明

API 请求体不再接受 `requester` 和 `requester_id`。

原因：

```text
requester/requester_id 属于身份信息。
身份必须由已验证 Access Token 的 sub 生成，不能由调用方在 JSON 里自报。
```

API 字段：

```text
target_ip          目标交易服务器 IPv4 地址
mask               掩码长度，固定 32
ports              allow 必填的 TCP 端口数组；deny 不需要
description        描述信息，禁止换行和控制字符
client_request_id  调用方业务请求号，可选，用于追踪
```

服务端内部会生成：

```text
job_id
principal_subject
access_request.requester
access_request.request_id
```

其中：

```text
access_request.requester  由 Keycloak Client 对应的 Principal.subject 生成；关闭认证时才使用 api-placeholder
access_request.request_id 当前使用服务端生成的 job_id
```

这样可以兼容当前 Ansible role，又不会让外部调用方伪造身份。

### 7.8 API 运行目录

API 任务元数据默认写入：

```text
.runtime/api/jobs.sqlite3
```

该 SQLite 数据库同时作为持久化任务队列。FastAPI 插入 `pending` 任务，Worker 使用
事务原子领取最早的任务并更新为 `running`。当前只应运行一个 Worker，以保证同一台
防火墙上的 allow/deny 操作严格串行。

每个任务独立的 CLI 临时目录：

```text
.runtime/jobs/<job_id>
```

ansible-runner artifact 默认目录：

```text
.runtime/runner/artifacts/<job_id>
```

如需改到固定系统目录，可以通过环境变量覆盖：

```bash
export TRADE_ACCESS_API_DATABASE_PATH=/tmp/usg6000e_trade_access/api/jobs.sqlite3
export TRADE_ACCESS_API_JOB_TMP_ROOT=/tmp/usg6000e_trade_access/jobs
export TRADE_ACCESS_API_RUNNER_PRIVATE_DATA_DIR=/tmp/usg6000e_trade_access/runner
```

### 7.9 Keycloak Offline API Key 认证

普通用户可以在 `/test-ui` 创建长期 API Key：

```text
sk-<keycloak_offline_token>
```

完整 Key 只显示一次。数据库只保存 SHA-256 哈希、名称、所属 Keycloak `sub`、创建时间、
最后使用时间和吊销状态，不保存完整 Offline Token。业务调用格式：

```text
Authorization: Bearer sk-<keycloak_offline_token>
```

后端使用一个固定的 Confidential Client，把 Offline Token 换成短期 Access Token，验证
RS256签名、`iss`、`aud`、`exp`、`sub` 和 Client Role，再按 `sub` 读取最新本地接口权限。
Access Token 会缓存到过期前30秒，用户不需要处理300秒Token续签。

管理员流程：

```text
浏览器访问 /admin-ui
  -> 跳转 Keycloak trade-access Realm 登录
  -> Authorization Code Flow + PKCE
  -> 浏览器获得短期 Access Token
  -> 使用 Bearer Token 管理 Keycloak User 的业务权限
```

在 Keycloak `trade-access` Realm 创建独立 Public Client `trade-access-admin-portal`：

```text
Client authentication: OFF
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
PKCE method: S256
Valid redirect URIs:
  https://<API域名>/admin-ui
Valid post logout redirect URIs:
  https://<API域名>/admin-ui
Web origins:
  https://<API域名>
```

该 Client 必须添加 Audience Mapper，使 `aud` 包含 `trade-access-api`。管理员必须具有
`trade-access-api:trade-access-admin` 和本地 `identity.user.manage` 权限。普通入口 Client 的 Token 不能访问管理接口。

`test-ui` 仍使用 `trade-access` Realm 的 `trade-access-portal`。运行配置增加：

```bash
export TRADE_ACCESS_API_KEYCLOAK_BROWSER_CLIENT_ID=trade-access-portal
export TRADE_ACCESS_API_KEYCLOAK_BROWSER_SCOPE='openid profile email'
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_CLIENT_ID=trade-access-admin-portal
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_SCOPE='openid profile email'
export TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_ID=trade-access-offline
export TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_SECRET='<confidential-client-secret>'
export TRADE_ACCESS_API_KEYCLOAK_OFFLINE_SCOPE='openid profile offline_access'
```

在 Keycloak 中创建 `trade-access-offline`：

```text
Client authentication: ON
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
Valid redirect URIs:
  https://<API域名>/api/v1/auth/offline/callback
Optional client scope:
  offline_access
```

该 Client 必须添加 Audience Mapper，使 Access Token 的 `aud` 包含 `trade-access-api`，并允许
对应用户的 `trade-access-api:trade-access-user` Role进入Token。为保持 `sk-<offline_token>`
长期固定，必须针对该 Client 使用 `suppress-refresh-token-rotation` Client Policy，或关闭Realm级
`Revoke Refresh Token`。推荐只通过Client Policy影响该专用Client。

Keycloak User 使用稳定的 `sub` 作为本地权限主体。FastAPI 验证 Access Token 后，按 Token 的
`sub` 读取最新接口权限；业务权限变化不需要修改 Token 自定义属性。

首次管理员必须是 trade-access Realm User。分配 `trade-access-api:trade-access-admin` 后，仍需按
该 User 的 Keycloak UUID 执行 `scripts/manage_permissions.py grant --profile admin` 完成本地管理权限引导。

之后管理员登录 `/admin-ui`，可以：

- 搜索现有 Keycloak User，并按 `sub` 配置角色、本地接口权限和启停状态。
- 管理普通用户和管理员的角色、接口权限和启停状态。

浏览器登录的 Access Token 和 Refresh Token 仍只保存在 `sessionStorage`。新建 API Key 时，
Keycloak Offline Token只在创建结果中显示一次；关闭结果弹窗后页面会清除明文。

示例：

```bash
curl -X POST \
  -H "Authorization: Bearer $TRADE_ACCESS_SK" \
  -H 'Content-Type: application/json' \
  -d '{"target_ip":"192.168.5.224","mask":32,"ports":[80,443]}' \
  http://127.0.0.1:8000/api/v1/trade-access/allow
```

### 7.10 历史组合 Key 方案（已停用）

下面内容仅保留用于理解旧版本迁移，不适用于当前 API。当前请求使用这些 Header 或脚本会失败。

每个调用方在 Keycloak 中使用独立 Client 和独立 Client Secret。管理员通过本项目工具
将二者封装成一条组合 Key，调用者只需保存和提交这一条值：

```text
kc1.<base64url(client_id)>.<base64url(client_secret)>
```

调用流程：

```text
X-API-Key
  -> FastAPI解析client_id和client_secret
  -> 后台调用Keycloak token endpoint
  -> 校验并缓存短期access token
  -> 读取Keycloak身份和普通/管理员角色
  -> 检查API本地接口权限
  -> 创建Ansible任务
```

Base64URL 只用于封装，不是加密。生产环境必须使用 HTTPS，不能在日志中输出
`X-API-Key`、Client Secret 或 Access Token。

API 只读取 Keycloak 标准 token 字段：`sub`、`preferred_username`、`iss`、`aud`、
`exp`，以及 `resource_access.trade-access-api.roles`。不读取 IP、CIDR、端口或 action
等自定义凭据属性。

在 Keycloak 的 `trade-access-api` client 下创建两个 client role：

```text
trade-access-user   调用 /allow、/deny 和普通任务查询接口；mask 必须为 32
trade-access-admin  同时可调用 /api/v1/admin 下的跨用户查询接口
```

Keycloak角色只进行普通用户和管理员分类。更细的接口权限由 FastAPI本地表控制：

```text
firewall.allow      POST /api/v1/trade-access/allow
firewall.deny       POST /api/v1/trade-access/deny
firewall.job.read   GET  /api/v1/trade-access/jobs/**
firewall.job.audit  GET  /api/v1/admin/trade-access/jobs/**
identity.user.manage    /api/v1/admin/users/**
```

配置 API：

```bash
export TRADE_ACCESS_API_KEYCLOAK_SERVER_URL=https://keycloak.internal.example
export TRADE_ACCESS_API_KEYCLOAK_REALM=trade-access
export TRADE_ACCESS_API_KEYCLOAK_CLIENT_ID=trade-access-api
export TRADE_ACCESS_API_KEYCLOAK_USER_ROLE=trade-access-user
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_ROLE=trade-access-admin
```

如果 Keycloak 使用企业内部 CA：

```bash
export TRADE_ACCESS_API_KEYCLOAK_CA_CERT=/path/to/internal-ca.pem
```

给普通 Client 授予防火墙接口权限：

```bash
python3.12 scripts/manage_permissions.py grant \
  --client-id trade-access-zhangsan \
  --profile user
```

当前业务不再按管理员分配的 IP 白名单限制普通用户。普通用户和管理员都只能对合法
IPv4 单地址执行 allow/deny，并且只能使用 `/32`。接口权限仍由 API 后端按用户 `sub`
强制校验，不能通过绕过前端规避。

管理员 Client 使用：

```bash
python3.12 scripts/manage_permissions.py grant \
  --client-id trade-access-ops \
  --profile admin
```

也可以只授权单个接口：

```bash
python3.12 scripts/manage_permissions.py grant \
  --client-id trade-access-lisi \
  --permission firewall.allow \
  --permission firewall.job.read
```

生成交给调用方的单个组合 Key：

```bash
python3.12 scripts/build_client_key.py \
  --client-id trade-access-zhangsan
```

命令会隐藏读取 Keycloak Client Secret，然后只输出组合 Key。查看或撤销接口权限：

```bash
python3.12 scripts/manage_permissions.py list \
  --client-id trade-access-zhangsan

python3.12 scripts/manage_permissions.py revoke \
  --client-id trade-access-zhangsan \
  --permission firewall.deny
```

调用方在 Postman 中添加请求头：

```text
X-API-Key: kc1.xxxxx.xxxxx
```

调用方 service account 仍必须被分配 `trade-access-api` 下的对应 Keycloak client role，
并确保 access token 的 `aud` 包含 `trade-access-api`。FastAPI 会验证 RS256签名、
`iss`、`aud`、`exp`、`sub` 和 `azp`。Token 在内存中缓存到过期前30秒，不写入数据库。

原来的 Bearer Access Token 方式仍兼容，可用于排障：

```text
Authorization: Bearer eyJ...
```

### 管理员用户管理界面

管理员界面地址：

```text
http://<API节点IP>:8000/admin-ui
```

首次使用前，需要在 Keycloak 的 `trade-access` Realm 中创建一个专用于 API 后端的
Confidential Client，例如：

```text
trade-access-provisioner
```

启用 `Client authentication` 和 `Service accounts roles`，然后给它的 Service Account
分配 `realm-management` Client 下的这些角色：

```text
query-clients
manage-users
query-users
```

将 Provisioning Client 的凭据配置到 API 服务端环境变量：

```bash
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_ID=trade-access-provisioner
export TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET='Keycloak中的Client Secret'
```

给现有管理员 User 补充管理员接口权限：

```bash
python3.12 scripts/manage_permissions.py grant \
  --subject-id '<Keycloak User UUID>' \
  --profile admin
```

重启服务后，管理员可以在界面中搜索 Keycloak User、配置角色、接口权限和启停状态。普通用户在
`/test-ui` 中自行创建和删除 `sk-<offline_token>` API Key。

调用方可以查询自己的角色和接口权限：

```text
GET /api/v1/trade-access/me
```

管理员接口：

```text
GET /api/v1/admin/trade-access/jobs
GET /api/v1/admin/trade-access/jobs/{job_id}
GET /api/v1/admin/trade-access/jobs/events/{job_id}
```

每个新任务会审计 Keycloak `sub`、浏览器 Client ID、认证类型和本次使用的接口权限代码，
但不会保存 Access Token 或 Refresh Token。

如需临时关闭认证进行本地调试：

```bash
export TRADE_ACCESS_API_AUTH_ENABLED=false
```

生产或联调环境建议保持默认开启认证。

修改 API 或 Worker 代码后需要重启统一服务。权限表修改立即生效；Keycloak User 禁用后，
已签发的短期 Access Token 最迟会在 Token 过期时失效。
