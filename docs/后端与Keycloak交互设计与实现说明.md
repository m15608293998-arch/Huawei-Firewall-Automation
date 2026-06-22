# 后端与 Keycloak 交互设计与实现说明

## 1. 设计目标

本系统不在后端自建用户密码体系，也不让调用方在请求里自报身份。

整体边界如下：

- Keycloak 负责用户登录、Token 签发、基础角色。
- FastAPI 后端负责业务权限、账号启停、任务审计和长期 API Key 状态。
- 用户身份统一使用 Keycloak Token 中稳定的 `sub`。
- 长期 `sk-` API Key 基于 Keycloak Offline Token，不是后端自造密钥。

一句话：Keycloak 管“你是谁”，后端管“你在本业务里能做什么”。

## 2. Keycloak 中需要提前配置的对象

所有对象都放在 `trade-access` Realm 下。

| Client | 类型 | 作用 |
| --- | --- | --- |
| `trade-access-api` | Resource Client | 后端 API 的 audience 和基础角色 |
| `trade-access-portal` | Public Client | 普通用户 `/test-ui` 登录 |
| `trade-access-admin-portal` | Public Client | 管理员 `/admin-ui` 登录 |
| `trade-access-offline` | Confidential Client | 创建长期 `sk-` API Key |
| `trade-access-provisioner` | Confidential Client | 后端调用 Keycloak Admin API |

### 2.1 `trade-access-api`

在 `trade-access-api` 下创建两个 Client Role：

```text
trade-access-user
trade-access-admin
```

这两个角色只做粗粒度分类：普通用户和管理员。具体能调用哪些接口，不放进 Keycloak，而是由后端本地数据库保存，这样权限调整后下一次请求就能生效。

其他登录 Client 需要配置 Audience Mapper，让 Access Token 的 `aud` 包含：

```text
trade-access-api
```

后端会校验这个 audience，确认 token 是签给本 API 使用的。

### 2.2 `trade-access-portal`

普通用户浏览器登录使用这个 Client。

Keycloak 管理界面建议配置：

```text
Client authentication: OFF
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
Service accounts: OFF
PKCE method: S256
Valid redirect URIs: https://<API域名>/test-ui
Web origins: https://<API域名>
```

原因：

- 浏览器不能安全保存 Client Secret，所以使用 Public Client。
- Standard Flow 用于 Authorization Code Flow。
- PKCE `S256` 用来保护授权码交换。
- 关闭 Implicit 和 Direct Access Grants，避免启用不需要的登录方式。

### 2.3 `trade-access-admin-portal`

管理员浏览器登录使用这个 Client。

建议配置：

```text
Client authentication: OFF
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
Service accounts: OFF
PKCE method: S256
Valid redirect URIs: https://<API域名>/admin-ui
Web origins: https://<API域名>
```

它和普通用户 Client 分开，是为了让后端能判断 token 来自普通入口还是管理入口。管理员接口会要求 token 来自 `trade-access-admin-portal`，同时用户具备 `trade-access-admin` 角色和本地管理权限。

### 2.4 `trade-access-provisioner`

这是后端专用管理 Client，用来调用 Keycloak Admin API。

建议配置：

```text
Client authentication: ON
Service accounts: ON
Standard flow: OFF
Implicit flow: OFF
Direct access grants: OFF
```

Service Account 分配最小可用权限，例如：

```text
realm-management:query-users
realm-management:query-clients
realm-management:manage-users
```

用途：

- 管理员页面搜索 Keycloak User。
- 保存用户授权时同步 `trade-access-user` 或 `trade-access-admin` 角色。
- Client Secret 只保存在 API 服务器，不返回浏览器。

### 2.5 `trade-access-offline`

这是创建长期 `sk-` API Key 的 Client。

建议配置：

```text
Client authentication: ON
Standard flow: ON
Implicit flow: OFF
Direct access grants: OFF
PKCE method: S256
Valid redirect URIs: https://<API域名>/api/v1/auth/offline/callback
Optional client scope: offline_access
```

它使用 Confidential Client，是因为后端需要用 `client_secret` 和 authorization code 换 token。这个 secret 只能保存在后端，不能放进浏览器。

如果 Keycloak 开启了 refresh token rotation，需要对 `trade-access-offline` 抑制或关闭轮换。否则用户保存的 `sk-<offline_token>` 可能在首次刷新后失效。

## 3. 后端如何读取 Keycloak 配置

后端通过运行环境读取 Keycloak 配置，主要包括：

```text
TRADE_ACCESS_API_KEYCLOAK_SERVER_URL
TRADE_ACCESS_API_KEYCLOAK_REALM
TRADE_ACCESS_API_KEYCLOAK_CLIENT_ID
TRADE_ACCESS_API_KEYCLOAK_BROWSER_CLIENT_ID
TRADE_ACCESS_API_KEYCLOAK_ADMIN_BROWSER_CLIENT_ID
TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_ID
TRADE_ACCESS_API_KEYCLOAK_OFFLINE_CLIENT_SECRET
TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_ID
TRADE_ACCESS_API_KEYCLOAK_ADMIN_CLIENT_SECRET
```

这些配置决定后端连接哪个 Realm、校验哪个 API audience、使用哪个 Client 创建长期 SK，以及使用哪个 Client 调 Keycloak Admin API。

## 4. 普通用户登录和业务调用

普通用户访问 `/test-ui` 后，前端使用 `trade-access-portal` 跳转 Keycloak 登录。

流程：

```text
/test-ui
-> Keycloak Authorization Code Flow + PKCE
-> 前端获得 Access Token
-> Authorization: Bearer <keycloak_access_token>
-> 后端验证 Token
-> 后端按 sub 查询本地业务权限
-> 通过后创建防火墙任务
```

后端验证 Token 时会检查：

- RS256 签名。
- `iss` 是否是当前 Realm。
- `aud` 是否包含 `trade-access-api`。
- `sub`、`exp`、`iat` 是否有效。
- `resource_access.trade-access-api.roles` 是否包含所需基础角色。

验证通过后，后端把 Keycloak 身份转换成内部 `Principal`，再读取本地数据库里的权限和启停状态。

## 5. 管理员如何管理用户

管理员访问 `/admin-ui`，通过 `trade-access-admin-portal` 登录。

管理员接口需要同时满足：

```text
token 来自 trade-access-admin-portal
Keycloak Role 包含 trade-access-admin
本地权限包含 identity.user.manage
本地账号未禁用
```

管理员保存用户授权时，后端做两件事：

1. 通过 `trade-access-provisioner` 调 Keycloak Admin API，给用户设置 `trade-access-user` 或 `trade-access-admin` 角色。
2. 在本地 SQLite 保存用户 profile、启停状态和具体业务接口权限。

这样 Keycloak 只维护基础身份，后端维护动态业务授权。

## 6. 长期 `sk-` API Key 如何创建

长期 SK 用于 Postman、脚本或外部系统长期调用。

创建流程：

```text
用户已登录 /test-ui
-> 点击创建 API Key
-> 后端生成 state、code_verifier、code_challenge
-> 浏览器跳转到 trade-access-offline 授权地址
-> Keycloak 登录并授权 offline_access
-> Keycloak 回调 /api/v1/auth/offline/callback
-> 后端用 code + code_verifier + client_secret 换 token
-> Keycloak 返回 access_token 和 offline_token
-> 后端校验 access_token 中的 sub 等于当前用户 sub
-> 后端生成 sk-<offline_token>
```

这里要区分两个概念：

- Keycloak 上开启 PKCE，是为了强制校验授权码交换安全。
- `/api/v1/auth/offline/callback` 是后端接收 code、换 offline token、保存 API Key 元数据的入口。

两者都需要。

完整 SK 只展示一次：

```text
sk-<keycloak_offline_token>
```

数据库不保存明文 SK，只保存 SHA-256 hash、所属 Keycloak `sub`、名称、创建时间、最后使用时间和吊销状态。

## 7. 长期 `sk-` API Key 如何使用

外部调用时使用：

```http
Authorization: Bearer sk-<keycloak_offline_token>
```

后端处理逻辑：

```text
识别 sk- 前缀
-> 对完整 SK 做 hash，查本地记录
-> 确认未吊销、用户未禁用
-> 取出 offline token
-> 用 offline token + trade-access-offline client_secret 向 Keycloak 换短期 Access Token
-> 验证 Access Token 的签名、iss、aud、sub
-> 确认换回来的 sub 和本地 SK 绑定的 subject_id 一致
-> 按 sub 读取最新本地业务权限
-> 通过鉴权后执行业务接口
```

因此 `sk-` 不是脱离 Keycloak 的后端自造身份，它本质上仍然依赖 Keycloak Offline Token。

## 8. 防火墙任务如何接入认证结果

认证通过后，后端会把身份整理成内部 `Principal`：

```text
subject_id: Keycloak sub
subject: preferred_username 或 sub
roles: Keycloak Client Role
permissions: 本地业务权限
auth_type: keycloak_bearer 或 offline_api_key
```

创建防火墙任务时，后端记录操作动作、目标 IP、端口、Keycloak `sub`、认证类型、权限代码和任务状态。

实际连接华为防火墙不由 Keycloak 完成，而是：

```text
FastAPI 创建任务
-> Worker 领取任务
-> ansible-runner 执行 Playbook
-> Huawei CLI 脚本连接防火墙
```

Keycloak 只参与认证和基础身份确认，不参与设备 SSH 登录。

## 9. 安全边界

需要注意：

- Access Token 和 `sk-` 都是 Bearer 凭据，生产环境必须使用 HTTPS。
- 浏览器 Client 不保存 Secret。
- `trade-access-offline` 和 `trade-access-provisioner` 的 Secret 只保存在后端。
- 完整 `sk-` 只展示一次，后端只保存 hash。
- 管理员接口只接受管理员 Portal 登录得到的 Token，不接受普通 Portal Token 或个人 SK。
- 权限、启停和 SK 吊销状态由后端本地库控制，修改后下一次请求生效。

## 10. 总结

本方案的核心是边界清晰：

- Keycloak 是身份中心和 Token 签发中心。
- FastAPI 是业务鉴权、任务审计和长期 SK 状态管理中心。
- `sk-<offline_token>` 是 Keycloak Offline Token 的 API Key 化表达。
- 防火墙变更继续沿用 worker、ansible-runner 和现有 Playbook 执行链路。

这样既支持浏览器登录，也支持 Postman 或脚本长期调用，同时业务权限仍然由后端即时控制。
