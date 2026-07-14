# 长效 SK 方案简要说明

## 目标

让普通用户在完成一次 Keycloak 登录后，可以创建类似开放平台 API Key 的长期凭据：

```text
sk-<keycloak_offline_token>
```

## Keycloak 做了什么

Keycloak 仍然是身份来源，重点配置如下：

- 使用现有 `trade-access` Realm。
- 保留普通用户浏览器登录 Client：`trade-access-portal`。
- 新增一个固定的 Confidential Client：`trade-access-offline`。
- 给 `trade-access-offline` 开启 Authorization Code Flow。
- 允许请求 `offline_access` scope。
- 配置回调地址到后端：

```text
/api/v1/auth/offline/callback
```

- 允许 `offline_access`，并支持 Keycloak 开启 refresh token rotation / Revoke Refresh Token。

Keycloak 只负责认证、签发 offline token、后续用 offline token 换短期 access token；具体的业务权限、可操作 IP、API Key 名称和删除状态由本项目后端管理。

## 创建 SK 的流程

```text
用户登录 /test-ui
  |
  | 点击创建 API Key，输入名称
  v
后端生成授权请求，并带上 PKCE 参数
  |
  v
浏览器跳转到 Keycloak trade-access-offline 授权流程
  |
  v
Keycloak 返回 authorization code 到后端 callback
  |
  v
后端用 code + PKCE + client_secret 换取 token
  |
  v
Keycloak 返回短期 access_token 和长期 offline_token
  |
  v
后端校验 access_token 的 sub 必须等于当前用户 sub
  |
  v
后端生成 sk-<offline_token> 并只展示一次
```
数据库不保存明文 SK。它保存完整 SK 的 SHA-256 hash、名称、所属 Keycloak `sub`、创建时间、最后使用时间、吊销状态，以及加密后的当前有效 offline token。

## 使用 SK 的流程

外部调用时请求头为：

```http
Authorization: Bearer sk-<offline_token>
```

后端处理逻辑：

```text
收到 sk-
  |
  v
对完整 SK 做 hash，查本地记录
  |
  v
解密数据库中的当前有效 offline token
  |
  v
用 offline token + trade-access-offline client_secret 请求 Keycloak token endpoint
  |
  v
换取新的短期 access_token
  |
  v
如果 Keycloak 返回新的 refresh_token，立即加密覆盖保存
  |
  v
验签 access_token，并读取 sub
  |
  v
用 sub 查询本地权限、可操作 IP、账号启用状态
  |
  v
通过权限校验后执行防火墙业务接口
```

因此，SK 本身不是脱离 Keycloak 的自造身份。创建时 `sk-` 后面是初始 offline token；后续在开启 refresh token rotation 时，Keycloak 会轮换 offline token，后端使用数据库中加密保存的当前 token 继续换取并验证短期 access token。

## 为什么它能长期有效

普通浏览器登录拿到的 Access Token 是短期的，例如 300 秒。

而这个方案保存的是 Keycloak 的 offline token：

- offline token 生命周期可以配置得很长。
- offline token 专门用于离线场景刷新 access token。
- 后端使用当前有效 offline token 换取短期 access token 后再执行业务鉴权。
- 如果 Keycloak 开启 Revoke Refresh Token，后端会保存每次刷新返回的新 refresh token。
- 只要 Keycloak offline session 未过期、未被 Keycloak 或本系统吊销，用户手里的 `sk-...` 就可以持续使用。

## 为什么每个用户的 SK 只属于自己

每个 SK 都来自该用户本人登录后的授权流程。

Keycloak 签发的 token 中包含稳定用户身份：

```text
sub
```

后端创建 SK 时会校验：

- 当前登录用户的 `sub`
- Keycloak 返回 access token 中的 `sub`
- 本地 API Key 记录所属的 `subject_id`

三者必须一致。

后续每次用 SK 调用接口时，后端仍会用当前有效 offline token 换 access token，并再次校验换回来的 `sub` 是否和本地记录一致。
