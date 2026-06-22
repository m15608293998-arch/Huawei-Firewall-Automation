# Keycloak Access Token 与 Offline API Key 认证鉴权实施说明

## 1. 当前认证模型

浏览器中的普通用户和管理员使用Keycloak Access Token：

```http
Authorization: Bearer <keycloak_access_token>
```

Keycloak 负责认证和基础角色，FastAPI 使用 Token 中稳定的 `sub` 查询 SQLite 中的动态接口权限。
IP、端口和接口权限不写入 Token。

旧 `sk1.*` 自定义 SK 已下线。后端不再生成、校验或提供管理员代用户创建旧 SK 的管理接口。

普通用户还可以通过固定的`trade-access-offline` Confidential Client创建长期凭据：

```http
Authorization: Bearer sk-<keycloak_offline_token>
```

后端使用Offline Token向Keycloak换取短期Access Token，并以验证后的`sub`作为用户身份。

## 2. 完整流程

```text
管理员访问 admin-ui
-> Keycloak Authorization Code Flow + PKCE
-> 获得管理员 Access Token
-> FastAPI 验证 Token、管理员角色和本地管理权限
-> 管理员搜索 Keycloak User
-> 按 User sub 保存 allow/deny/read 权限和启停状态

普通用户访问 test-ui
-> Keycloak Authorization Code Flow + PKCE
-> 获得普通用户 Access Token
-> Test UI 自动作为 Bearer Token 调 API，但不显示短期Token
-> 用户可创建命名的sk-<offline_token>
-> curl/Postman使用SK时由后端自动向Keycloak换取Access Token
-> FastAPI 验证 Token，按 sub 读取本地权限和 IP
-> 创建 Ansible Runner 任务
```

权限或 allowed IP 修改后，用户后续请求立即读取新配置。若管理员改变用户的 Keycloak Client
Role，用户需要刷新 Token 或重新登录，才能取得新的角色 Claims。

## 3. Keycloak Client

| Client | 类型 | 用途 |
| --- | --- | --- |
| `trade-access-api` | Resource Client | API Audience 和 `trade-access-user/admin` 角色 |
| `trade-access-portal` | Public Client | `/test-ui` 普通用户 PKCE 登录 |
| `trade-access-admin-portal` | Public Client | `/admin-ui` 管理员 PKCE 登录 |
| `trade-access-offline` | Confidential Client | 普通用户长期Offline API Key |
| `trade-access-provisioner` | Confidential Client | FastAPI 搜索 User 和同步 Client Role |

系统不为每个员工创建 Client，也不向员工分发 Client Secret。

## 4. Keycloak 配置

### 4.1 `trade-access-api`

创建 Client Roles：

```text
trade-access-user
trade-access-admin
```

### 4.2 `trade-access-portal`

```text
Client authentication: OFF
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
Service accounts: OFF
PKCE method: S256
Valid redirect URIs: http://192.168.6.38:8000/test-ui
Valid post logout redirect URIs: http://192.168.6.38:8000/test-ui
Web origins: http://192.168.6.38:8000
```

添加 Audience Mapper，使 Access Token 的 `aud` 包含 `trade-access-api`，并确保用户 Token 包含
`resource_access.trade-access-api.roles`。

### 4.3 `trade-access-admin-portal`

```text
Client authentication: OFF
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
PKCE method: S256
Valid redirect URIs: http://192.168.6.38:8000/admin-ui
Valid post logout redirect URIs: http://192.168.6.38:8000/admin-ui
Web origins: http://192.168.6.38:8000
```

同样添加 `trade-access-api` Audience Mapper。管理员 User 必须具有：

```text
trade-access-api:trade-access-admin
```

API 还会检查本地 `identity.user.manage` 权限。普通 Portal Token 不能访问管理员 API。

### 4.4 `trade-access-provisioner`

```text
Client authentication: ON
Service accounts: ON
Standard flow: OFF
Direct access grants: OFF
```

Service Account 分配 `realm-management`：

```text
manage-users
query-users
query-clients
```

Client Secret 仅保存在 API 节点 `.runtime/trade-access.env`。

### 4.5 `trade-access-offline`

```text
Client authentication: ON
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
Valid redirect URIs: http://192.168.6.38:8000/api/v1/auth/offline/callback
Optional client scope: offline_access
```

添加Audience Mapper，使Access Token的`aud`包含`trade-access-api`。配置Client Policy
`suppress-refresh-token-rotation`，保证用户保存的`sk-<offline_token>`不会在首次换票后失效。
Client Secret仅保存在API节点，不返回浏览器。

## 5. 首次管理员引导

1. 在 `trade-access` Realm 创建管理员 User。
2. 分配 `trade-access-api:trade-access-admin`。
3. 获取该 User UUID，并授予本地管理权限：

```bash
python3.12 scripts/manage_permissions.py grant \
  --subject-id '<Keycloak User UUID>' \
  --profile admin
```

4. 保存运行配置：

```bash
python3.12 scripts/configure_runtime.py \
  --keycloak-server-url http://192.168.6.30:8080 \
  --browser-client-id trade-access-portal \
  --admin-browser-client-id trade-access-admin-portal
```

5. 启动服务：

```bash
python3.12 scripts/run_services.py
```

6. 打开 `http://192.168.6.38:8000/admin-ui`，登录并给普通用户保存接口权限和启停状态。

## 6. 普通用户调用

打开 `http://192.168.6.38:8000/test-ui` 并登录。页面会：

- 展示用户已有API Key的名称、指纹、创建时间和最后使用时间。
- 允许输入名称后创建`sk-<offline_token>`，完整Key只显示一次。
- 自动加载当前用户的本地权限和 allowed IP。
- 自动使用 Access Token 调用 allow、deny 和任务查询接口。
- 在 Access Token 临近过期时使用 Refresh Token 续签。

复制新建的API Key后，可以长期用于Postman或curl：

```bash
read -rsp 'Trade Access API Key: ' TRADE_ACCESS_SK
echo

curl -sS \
  -H "Authorization: Bearer $TRADE_ACCESS_SK" \
  -H 'Content-Type: application/json' \
  -d '{"target_ip":"192.168.5.224","mask":32,"ports":[12001,12002]}' \
  http://192.168.6.38:8000/api/v1/trade-access/allow
```

后端使用Offline Token自动换取短期Access Token，调用方不需要处理JWT的`exp`。

## 7. 权限和安全边界

- FastAPI 验证 RS256 签名、`iss`、`aud`、`exp`、`iat` 和 `sub`。
- 普通用户必须具有 `trade-access-user`，管理员必须具有 `trade-access-admin`。
- 每次请求按 `sub` 读取本地接口权限。
- 防火墙操作只接受合法 IPv4 单地址，掩码固定 `/32`。
- 管理员页面只接受来自 `trade-access-admin-portal` 的管理员 Token。
- Access Token 是 Bearer 凭据，泄露后可在过期前被重放，生产环境必须使用 HTTPS。
- 不得在代理、应用日志或错误输出中记录 Access Token 和 Refresh Token。
- Keycloak 禁用用户后，已签发 Token 在到期前可能仍能通过离线验签；需要结合较短 Token 生命周期、
  本地停用状态或 Token introspection/event 同步控制立即失效需求。

## 8. 未来中心服务和 CI/CD

用户在 Test UI 复制的 Access Token 适合测试，不适合作为 CI/CD 的长期固定 Key，因为它会过期。
未来中心 Service 应使用独立机器身份：

```text
中心 Service Confidential Client
-> Client Credentials
-> Keycloak 返回短期 Access Token
-> 中心 Service 自动缓存并在过期前重新获取
-> Bearer Access Token 调用 Trade Access API
```

机器 Client 应分配独立角色，并在本地权限表中作为独立主体授权和审计，不能复用员工浏览器 Token。
