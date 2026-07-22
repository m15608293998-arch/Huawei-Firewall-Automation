# 后端业务逻辑与 Keycloak 认证鉴权现状说明

> 当前实现基准：2026-07-21。
>
> 本文只描述当前代码实际运行的逻辑，不描述已经废弃的“每个员工一个 Keycloak Client”、
> `client_id + client_secret` 组合 `X-API-Key` 方案。

## 1. 当前系统解决什么问题

系统把原有 Huawei USG6000E Ansible 自动化能力封装成 HTTP API。用户不需要修改
`requests/*.yml`，只需要在页面或 API 请求中提交：

- 目标 IPv4 地址。
- 放行时需要开放的 TCP 端口。
- 可选描述和业务请求编号。

后端负责：

1. 认证调用者身份。
2. 检查接口权限和可操作 IP。
3. 创建持久化异步任务。
4. 同一 IP 的父任务按 FIFO 处理；失败父任务等待下一轮时，其他 IP 可继续执行。
5. 通过 SSH 修改三台防火墙各自配置的 Address Set 和 Application。
6. 逐台实时查询本次 IP 的完整状态，全部符合期望后才标记父任务成功。
7. 保存期望状态、逐台结果、调用身份和 Ansible 事件用于恢复、查询和审计。

## 2. 当前总体架构

```text
普通用户浏览器
  -> test-ui 跳转 Keycloak 登录
  -> Keycloak 返回 Access Token
  -> Authorization: Bearer <Keycloak Access Token>
  -> FastAPI 校验 JWT
  -> 按 Token sub 查询本地业务权限
  -> 用户可通过固定 Confidential Client 创建 sk-<offline_token>

普通用户脚本/Postman
  -> Authorization: Bearer sk-<offline_token>
  -> FastAPI 向Keycloak换取短期Access Token
  -> 验证JWT并按sub查询本地业务权限

管理员浏览器
  -> admin-ui 跳转 Keycloak 登录
  -> Authorization Code Flow + PKCE
  -> Authorization: Bearer <Keycloak Access Token>
  -> FastAPI 校验 JWT、管理员角色和本地管理权限
  -> FastAPI 使用 Provisioning Client 调 Keycloak Admin API

通过授权的业务请求
  -> SQLite pending Job
  -> 独立 Worker 按 FIFO 领取父任务
  -> PG-FW / PG-FW-1 / IDC-FW 子任务并行
  -> 各自 Ansible Runner -> SSH -> Huawei USG6000E
```

系统主要分层如下：

| 层次 | 当前实现 | 职责 |
| --- | --- | --- |
| 用户界面 | `/test-ui`、`/admin-ui` | 登录、输入业务参数、管理授权、查询任务和检查节点一致性 |
| 身份认证 | Keycloak Access Token + Offline API Key | 浏览器短期登录与普通用户长期调用 |
| 业务鉴权 | FastAPI + SQLite | 接口权限、IPv4 `/32` 校验、任务所有权和本地启用状态 |
| 任务队列 | SQLite 父任务、子任务和期望状态表 | FIFO、恢复、状态版本和审计记录 |
| 执行层 | Worker + Ansible Runner | 父任务分轮调度、设备子任务并行、逐台校验 |
| 设备层 | Ansible Role + SSH CLI | 修改防火墙并确认安全引擎提交完成 |

## 3. 三类凭据及其关系

当前系统存在三类凭据，不能混为一谈。

### 3.1 浏览器 Keycloak Access Token

`test-ui` 和 `admin-ui` 都使用 Authorization Code Flow with PKCE 登录 Keycloak。
Keycloak 返回 Access Token、Refresh Token 和 ID Token，前端保存在浏览器
`sessionStorage` 中。

Access Token 是使用 `RS256` 签名的 JWT，不是加密内容。FastAPI 会：

1. 读取 JWT Header 中的 `alg` 和 `kid`。
2. 强制要求 `alg=RS256`。
3. 从 Keycloak JWKS 地址读取并缓存公钥。
4. 验证签名、`issuer`、`audience`、`exp`、`iat` 和 `sub`。
5. 从 `resource_access.trade-access-api.roles` 读取基础角色。

后端通常不会在每次业务请求时向 Keycloak 在线查询用户。只有 JWKS 缓存过期或遇到未知
`kid` 时才重新获取公钥。

前端在 Access Token 距离过期不足 30 秒时使用 Refresh Token 换取新 Token。如果刷新失败，
清理浏览器会话并要求重新登录。当前默认 Scope 是：

```text
openid profile email
```

当前没有默认申请 `offline_access`。浏览器 Token 生命周期由 Keycloak 配置决定。

### 3.2 Keycloak Offline API Key

普通用户在 `/test-ui` 中创建：

```text
sk-<keycloak_offline_token>
```

所有用户共用一个 `trade-access-offline` Confidential Client。Client Secret只保存在API服务端。
创建时通过Authorization Code Flow、PKCE和`offline_access`获取绑定用户`sub`的Offline Token。
业务调用时，后端使用加密保存的当前Offline Token向Keycloak换取短期Access Token，验证后按`sub`读取最新权限。

数据库保存完整SK的SHA-256哈希、管理元数据，以及加密后的当前有效Offline Token，不保存明文SK。用户可命名、查看使用状态和删除Key。
删除后本地认证立即拒绝。完整SK只在创建成功后显示一次。

### 3.3 已下线的旧应用用户 SK

旧 `sk1.*` 自定义 SK 生成、认证和管理员代用户管理接口已下线。管理员只负责在 `admin-ui`
维护用户本地接口权限和启停状态；长期 API Key 由普通用户在 `/test-ui` 中自行创建和删除。

普通用户可以使用浏览器Access Token或新的`sk-<offline_token>`调用业务API。

### 3.4 Provisioning Client Access Token

`trade-access-provisioner` 是 FastAPI 服务端专用 Confidential Client。后端使用
Client Credentials 获取短期 Access Token，并调用 Keycloak Admin REST API：

- 搜索 Keycloak User。
- 查询 User 详情。
- 给 User 分配 `trade-access-user` 或 `trade-access-admin` Client Role。

该 Token 只存在于 FastAPI 进程内存中，并缓存到过期前 30 秒。Client Secret 只保存在 API
节点的安全配置文件中，不提供给浏览器和普通用户。

### 3.5 当前认证入口

FastAPI 从统一的 HTTP Header 接收凭据：

```http
Authorization: Bearer <credential>
```

判断逻辑为：

```text
Keycloak Access Token
  -> 按 RS256 JWT 校验
  -> 从 Token 读取 sub 和 Client Role
  -> 按 sub 查询本地接口权限
  -> 在 API 边界执行实际业务鉴权

sk-<offline_token>
  -> 查询本地哈希和吊销状态
  -> 向Keycloak换取短期Access Token
  -> 验证Keycloak签名和sub
  -> 按sub读取最新接口权限

```

所以当前运行模式是Keycloak签发的短期/离线凭据认证、本地数据库细粒度授权。

## 4. Keycloak 中的对象和职责

所有对象都位于 `trade-access` Realm。`master` Realm 管理员不作为业务管理员身份。

| Client | 类型 | 用途 |
| --- | --- | --- |
| `trade-access-api` | Resource Client | 定义 API Audience 和 `trade-access-user/admin` 角色 |
| `trade-access-portal` | Public Client | `/test-ui` 普通用户 PKCE 登录 |
| `trade-access-admin-portal` | Public Client | `/admin-ui` 管理员 PKCE 登录 |
| `trade-access-offline` | Confidential Client | 所有普通用户创建和使用长期Offline API Key |
| `trade-access-provisioner` | Confidential Client | FastAPI 调 Keycloak Admin API |

`trade-access-api` 定义两个 Client Role：

```text
trade-access-user
trade-access-admin
```

两个 Portal Client 的 Access Token 都必须通过 Audience Mapper 包含：

```text
aud = trade-access-api
```

Portal Client 使用：

```text
Client authentication: OFF
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
PKCE: S256
```

测试环境回调地址为：

```text
trade-access-portal:
  http://192.168.6.38:8000/test-ui

trade-access-admin-portal:
  http://192.168.6.38:8000/admin-ui
```

`trade-access-provisioner` 使用：

```text
Client authentication: ON
Service accounts: ON
Standard flow: OFF
Direct access grants: OFF
```

其 Service Account 至少需要 `realm-management` 中用于查询用户、管理用户和查询 Client 的权限。

## 5. 当前授权模型

Keycloak 只保存基础身份和粗粒度角色。动态业务权限保存在 SQLite，不写入 Token，也不写入 SK。

本地表以 Keycloak User 的稳定 `sub` 作为主键，保存：

- `profile`：`user` 或 `admin`。
- `enabled`：是否允许使用本业务。
- `permissions`：可调用的 API 操作。
- `allowed_ips`：历史兼容字段，当前业务授权不再使用它限制目标 IP。

当前权限代码：

```text
firewall.allow
firewall.deny
firewall.job.read
firewall.job.audit
identity.user.manage
```

普通用户最多只能拥有：

```text
firewall.allow
firewall.deny
firewall.job.read
```

管理员可以拥有全部权限。最终授权条件是：

```text
凭据有效
AND Keycloak 基础角色满足接口要求
AND 本地 enabled=true
AND 本地 permissions 包含当前接口权限
AND 请求目标是合法 IPv4 单地址
AND mask=32
```

普通用户可以提交任意合法 IPv4 单地址，但不能因为某个 IP 位于同一个 `/24` 就操作整个网段。
端口是每次请求的业务参数，不存入 Keycloak Token、SK 或固定权限记录。

管理员同样使用 `/32` 单地址提交防火墙操作；管理员后台能力仍必须通过管理员 Portal 登录，并同时具备：

- Keycloak `trade-access-admin` Client Role。
- 本地对应的管理员权限。

## 6. 管理员实际操作流程

### 6.1 首次管理员引导

1. 在 `trade-access` Realm 创建真实管理员 User。
2. 给该 User 分配 `trade-access-api:trade-access-admin`。
3. 获取 User UUID，也就是后续 Token 的 `sub`。
4. 在 API 节点授予初始本地管理员权限：

```bash
python3.12 scripts/manage_permissions.py grant \
  --subject-id '<Keycloak User UUID>' \
  --profile admin
```

该脚本用于首次引导或故障恢复。正常运行后，用户管理主要通过 `/admin-ui` 完成。

### 6.2 保存 Keycloak 运行配置

```bash
python3.12 scripts/configure_runtime.py \
  --keycloak-server-url http://192.168.6.30:8080 \
  --realm trade-access \
  --resource-client-id trade-access-api \
  --browser-client-id trade-access-portal \
  --admin-browser-client-id trade-access-admin-portal \
  --admin-client-id trade-access-provisioner
```

命令会隐藏读取 `trade-access-provisioner` Client Secret，并写入：

```text
.runtime/trade-access.env
```

文件权限为 `0600`，之后重启服务不需要重新导入环境变量。

### 6.3 在 Admin UI 管理普通用户

1. 打开 `http://192.168.6.38:8000/admin-ui`。
2. 跳转 `trade-access` Realm，使用管理员 User 登录。
3. 搜索已经存在的 Keycloak User。
4. 选择普通用户 Profile。
5. 勾选 `allow`、`deny`、任务查询等接口权限。
6. 点击“保存用户授权”。

保存时后端会同时：

- 在 Keycloak 给 User 分配 `trade-access-user` Client Role。
- 在 SQLite 按 User `sub` 保存 Profile、权限和 allowed IP。

后续只修改授权时点击“保存用户授权”即可，现有 SK 不会变化。

### 6.4 旧 SK 管理能力

Admin UI 已隐藏创建和吊销 SK 的区域。后端相关代码和接口暂时保留，但当前正常业务不再签发 SK。

## 7. 普通用户实际操作流程

### 7.1 使用 Test UI

1. 打开 `http://192.168.6.38:8000/test-ui`。
2. 页面跳转 `trade-access` Realm 登录。
3. 用户完成 Keycloak 身份验证后返回 Test UI。
4. 页面自动调用 `/api/v1/trade-access/me`，不显示短期Access Token。
5. 页面根据管理员配置展示当前接口权限和 allowed IP。
6. 点击“创建API Key”，输入名称并完成Keycloak Offline Access授权。
7. 创建成功后复制仅显示一次的`sk-<offline_token>`。
8. 也可以继续在页面输入目标IP、端口并提交放行或取消放行。
9. 使用返回的`job_id`查询任务详情和事件。

页面内业务请求仍自动使用浏览器Access Token并在临近过期时续签，但页面不再展示或复制该Token。

### 7.2 通过 curl 调用

```bash
read -rsp 'Trade Access API Key: ' TRADE_ACCESS_SK
echo
```

放行：

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $TRADE_ACCESS_SK" \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "192.168.5.224",
    "mask": 32,
    "ports": [12001, 12002, 12003],
    "description": "temporary trade access",
    "client_request_id": "REQ-ALLOW-001"
  }' \
  http://192.168.6.38:8000/api/v1/trade-access/allow
```

取消该 IP 的全部放行：

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $TRADE_ACCESS_SK" \
  -H 'Content-Type: application/json' \
  -d '{
    "target_ip": "192.168.5.224",
    "mask": 32,
    "description": "remove trade access",
    "client_request_id": "REQ-DENY-001"
  }' \
  http://192.168.6.38:8000/api/v1/trade-access/deny
```

查询任务：

```bash
curl -sS \
  -H "Authorization: Bearer $TRADE_ACCESS_SK" \
  http://192.168.6.38:8000/api/v1/trade-access/jobs/<job_id>
```

查询 Ansible 事件：

```bash
curl -sS \
  -H "Authorization: Bearer $TRADE_ACCESS_SK" \
  http://192.168.6.38:8000/api/v1/trade-access/jobs/events/<job_id>
```

## 8. 当前 API 接口

### 8.1 公共和登录辅助接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | API 健康检查 |
| `GET` | `/test-ui` | 普通用户测试页面 |
| `GET` | `/admin-ui` | 管理员授权页面 |
| `GET` | `/api/v1/auth/config?portal=test/admin` | 返回对应 Portal 的 OIDC 配置 |
| `GET` | `/api/v1/auth/offline/callback` | Keycloak Offline Access创建回调 |
| `GET` | `/docs` | Swagger UI |

### 8.2 普通业务接口

| 方法 | 路径 | 本地权限 |
| --- | --- | --- |
| `GET` | `/api/v1/trade-access/me` | 业务角色和本地启用状态 |
| `POST` | `/api/v1/api-keys/authorize` | 发起当前用户API Key创建 |
| `GET` | `/api/v1/api-keys` | 查询当前用户API Key列表 |
| `DELETE` | `/api/v1/api-keys/{key_id}` | 删除当前用户API Key |
| `POST` | `/api/v1/trade-access/allow` | `firewall.allow` |
| `POST` | `/api/v1/trade-access/deny` | `firewall.deny` |
| `GET` | `/api/v1/trade-access/jobs` | `firewall.job.read` |
| `GET` | `/api/v1/trade-access/jobs/{job_id}` | `firewall.job.read` |
| `GET` | `/api/v1/trade-access/jobs/events/{job_id}` | `firewall.job.read` |

普通用户只能查询 `principal_id` 等于自身 Keycloak `sub` 的任务。查询其他用户任务返回 `404`。

### 8.3 管理员接口

| 方法 | 路径 | 本地权限 |
| --- | --- | --- |
| `GET` | `/api/v1/admin/users/status` | `identity.user.manage` |
| `GET` | `/api/v1/admin/users` | `identity.user.manage` |
| `GET` | `/api/v1/admin/users/search` | `identity.user.manage` |
| `PUT` | `/api/v1/admin/users/{subject_id}` | `identity.user.manage` |
| `GET` | `/api/v1/admin/trade-access/jobs` | `firewall.job.audit` |
| `GET` | `/api/v1/admin/trade-access/jobs/{job_id}` | `firewall.job.audit` |
| `GET` | `/api/v1/admin/trade-access/jobs/events/{job_id}` | `firewall.job.audit` |

管理员接口只接受来自 `trade-access-admin-portal` 的有效 Keycloak Access Token，不接受用户 SK。

## 9. 任务队列和状态

API 完成参数与权限检查后，把任务写入 SQLite 并返回 `202 Accepted`：

```text
pending -> running -> successful
             |-----> reconciling --(到点重试)--> running
             `-----> failed
```

`canceled` 当前仅作为预留状态，尚未提供任务取消接口。单 Worker 每轮只执行一个父任务；
失败任务写入 `next_attempt_at` 后释放队列。调度器跳过尚未到点的修复任务，并阻止同一 IP
的后续任务越过它，不同 IP 的变更仍可继续执行。

统一启动命令：

```bash
python3.12 scripts/run_services.py
```

该命令同时启动：

- Uvicorn/FastAPI API 进程。
- SQLite 持久化队列 Worker 进程。

API 进程重启不会删除已持久化任务。worker 会重新认领异常中断前尚未完成的父任务，
复用已写入的期望状态版本；已经达标的设备只校验，未达标设备继续执行。

## 10. 防火墙业务执行逻辑

### 10.1 Allow

Allow 采用追加合并语义：

```text
最终端口 = 已有端口集合 ∪ 本次请求端口集合
```

工作流会：

1. 按当前防火墙配置档查询并补齐目标 IP 的 Address Set 成员关系：`PG-FW`
   使用 `public/private/Internet`，`PG-FW-1` 使用 `public`，`IDC-FW` 使用
   `private/Internet`。
2. 查询该 IP 已有的 `UD_TServe_<IP>` Application 和端口。
3. 忽略重复端口，合并已有端口和新端口。
4. 每条 Rule 最多放 4 个端口。
5. 每个 Application 最多 8 条 Rule，即最多 32 个端口。
6. 超过 32 个端口时自动创建：

```text
UD_TServe_192.168.5.224
UD_TServe_192.168.5.224_2
UD_TServe_192.168.5.224_3
```

7. 在一次 SSH 会话中执行增量变更，并将 Application 加入
   `UDG_TradeServers` Application Group。
8. 再次查询并验证端口、IP 和 Application Group。

重复提交已存在端口不会报错，也不会删除之前已经存在但本次没有提交的端口。

### 10.2 Deny

组合接口 `POST /deny` 的语义是撤销该 IP 的全部放行；只删除部分端口使用
`POST /deny/ports`。完整撤销工作流会：

1. 精确匹配 `UD_TServe_<IP>` 及其数字后缀 Application。
2. 从 `UDG_TradeServers` Application Group 删除对应成员。
3. 删除该 IP 的全部 Application，包括 `_2`、`_3` 等对象。
4. 从每台防火墙配置档声明的全部 Address Set 中删除该 IP。
5. 再次查询验证删除结果。

匹配使用完整名称规则，不会因子串相同而误删其他 IP 的 Application。

### 10.3 Commit 和 Save

只有检测到 Application 实际变化时才执行安全引擎提交；任何配置变化按配置执行
保存：

```text
engine configuration commit
save
```

当前不会在设备刚接受 `engine configuration commit` 后立即把任务标记成功。CLI 执行器会：

1. 看到 `The operation may last several minutes, please wait.` 后保持任务运行。
2. 每 2 秒重新检查一次提交状态。
3. 只有收到 `The submission of the compilation is unnecessary.`，才认为安全引擎编译完成。
4. 编译确认后继续执行 `save`。
5. 最长等待 180 秒；超时、错误或未知状态会使任务失败。

因此当前 `successful` 还要求所有防火墙在执行后实时查询到本次 IP 的完整状态与
`desired_state` 一致，而不只是 CLI 已接受命令。

## 11. 当前安全边界和已知限制

- 生产环境必须使用 HTTPS。JWT Payload 可读，SK 也可被窃取后重放。
- 业务 API 接受短期 Keycloak Access Token 和 `sk-<offline_token>`。
- Access Token 是短期凭据，复制到 Postman 后只能使用到其 `exp` 时间；外部工具应使用长期 `sk-`。
- 后端使用数据库中加密保存的当前 Offline Token 自动换取短期Access Token；Keycloak 返回新 refresh token 时立即加密覆盖保存。
- 管理员 Access Token 和 Refresh Token 当前保存在浏览器 `sessionStorage`，关闭标签页后不会作为
  长期持久凭据保留。
- 禁用 Keycloak User 不会被每次 SK 请求实时查询；当前 SK 校验依赖本地 `managed_users.enabled`。
  离职或禁用用户时应同时在 Admin UI 停用该用户并吊销 SK。
- SQLite 适合当前单 API/单 Worker 部署。未来多实例部署需要重新评估数据库和队列方案。
- Access Token、Refresh Token 和 Authorization Header 不得写入日志。

## 12. 核心结论

当前认证鉴权职责划分为：

```text
Keycloak
  -> 浏览器登录认证
  -> 签发普通用户和管理员 Access Token
  -> 保存 User 和基础 Client Role

FastAPI + SQLite
  -> 验证 Keycloak JWT
  -> 保存动态接口权限和启停状态
  -> 根据 Keycloak sub 执行业务鉴权
  -> 创建任务并隔离任务所有权

Worker + Ansible
  -> 父任务 FIFO，设备子任务并行
  -> 持久化并恢复业务期望状态
  -> 逐台验证本次 IP 的完整最终状态
  -> 所有目标一致后才标记 successful
```

管理员负责给用户分配业务权限；普通用户负责登录并提交 IP 与端口；Keycloak 负责登录身份和基础
角色；FastAPI 负责最终细粒度授权；Ansible 负责实际防火墙变更。
