# 排障 MCP 端点

Status: implemented

## Problem

排障与调优需要一个能在团队 IM 或托管 agent 平台上运行的 agent。它的输入是四样：对象存储上的 session log 归档、指标系统里的节点流量与请求数、当前生效的配置、以及用户提供的客户端日志。前三样都要凭据，而凭据不能交给 agent：agent 读的客户端日志是终端用户提供的内容，一段构造好的文本就能把上下文里的长期密钥带走；对象存储 key 与指标 token 一旦进了模型上下文，沙箱拦不住外带。

没有任何一个组件能替 agent 保管这些凭据并只放出短时效、只读的能力。会话惩罚、按节点健康检查结果、当日带宽计数、缓存来源这些运行时状态只在存储后端里，agent 拿不到，只能靴带式地从日志重放推算。托管 agent 平台的接入方式是「填一个 URL」，自定义请求头并不总是可填，也不一定有能连通对象存储与指标系统的自建沙箱。

## Decision

DFS2 进程内挂一个只读 MCP 端点，Streamable HTTP 传输，挂载路径 `/{MCP_PREFIX}/mcp`。传输用官方 `rmcp` 3 的 `StreamableHttpService`（Tower service，`nest_service` 进现有 axum 0.8 路由），不另起 listener。它是凭据代理、目录与查询转发，不解析日志、工具不写任何存储、不暴露原始存储命令、不暴露配置重载。agent 在自己的沙箱里下载与处理数据，MCP 只保证数据可达。

`rmcp` 的 `StreamableHttpServerConfig` 默认只接受 loopback `Host`，用来挡本地进程的 DNS rebinding。本端点挂在前置反向代理后面、面向公网名，默认 allowlist 会 403。进程对这条路径调用 `disable_allowed_hosts()`：`Host` 校验交给反代，本路径的门是 `MCP_TOKEN`。

### 放在进程内

脱敏是整套设计里风险最高的动作，它决定了放置位置。进程内对加载时留下的配置文件原文做与 `dfs2 redact` 同一套改写，见 [配置原文脱敏](./2026-09-20-config-yaml-redact.md)。

进程内还直接复用 `ArcSwap` 里的当前配置（热重载后即是真实生效版本）、`DataStore` 句柄、`S3Signer` 的 SigV4 实现、以及 `SESSION_LOG_ARCHIVE_S3` 等已有环境变量。管理端点的 token 不再需要，进程内直接调服务，自然只暴露读路径。

### 门控与鉴权

`MCP_TOKEN` 与 `MCP_PREFIX` 同时存在才挂载路由；缺任一项时路径不存在，启动时打一行 info 说明 MCP 未启用。配置不完整（只设其一、非法 prefix、指标三项只设部分、归档 URL 无法解析）时 `dfs2 validate` 与 `serve` 都失败。`MCP_PREFIX` 只允许 URL 安全字符、不含 `/`。这条路径不进 OpenAPI 文档。

同一个 `MCP_TOKEN` 接受三个入口，命中任一即通过：`Authorization: Bearer`、`X-API-Key` 头、`?token=` query。header 能用的平台用 header，只能填 URL 的平台用 query，只认 OAuth 的平台走下文的授权服务器，拿到的 access token 经 `Authorization: Bearer` 生效。`Authorization` 的 scheme 按 RFC 7235 不区分大小写。缺失或不匹配返回空 body 的 401；设了 `MCP_PUBLIC_URL` 时响应带 `WWW-Authenticate: Bearer resource_metadata="{MCP_PUBLIC_URL}/.well-known/oauth-protected-resource/{MCP_PREFIX}/mcp"`，未设时 401 只有状态码。`MCP_TOKEN` 允许逗号分隔两个值并存，用于轮换。

接受 query 形态意味着 DFS2 自身在这条路径上不得把 query 写进任何日志，部署说明要求前置反向代理对该 location 关闭 access log 或剥除 query。`MCP_PREFIX` 的职责退化为挡扫描器，真正的密钥是 token。

### OAuth 授权服务器

面向 Gemini 自定义应用这类只接受 OAuth 的客户端：RFC 9728 受保护资源元数据、RFC 8414 授权服务器元数据、RFC 7591 动态注册、授权码 + PKCE（只收 `S256`）、RFC 7009 令牌撤销。OAuth 要求设 `MCP_PUBLIC_URL`：设了才挂下表的路由，issuer 是 `{MCP_PUBLIC_URL}/{MCP_PREFIX}`；未设时下表路径与未知路径同为 404，`/{MCP_PREFIX}/mcp` 只认三个静态入口，启动照常。所有端点都在前缀下，根路径不新增任何路由：

| 路径 | 作用 |
|---|---|
| `/.well-known/oauth-protected-resource/{MCP_PREFIX}/mcp` | 受保护资源元数据，`resource` 为 `…/{MCP_PREFIX}/mcp` |
| `/.well-known/oauth-authorization-server/{MCP_PREFIX}`、`/.well-known/openid-configuration/{MCP_PREFIX}` | 授权服务器元数据（路径插入） |
| `/{MCP_PREFIX}/.well-known/oauth-authorization-server`、`/{MCP_PREFIX}/.well-known/openid-configuration` | 同上（issuer 后缀形态） |
| `/{MCP_PREFIX}/oauth/register` | 动态注册 |
| `/{MCP_PREFIX}/oauth/authorize` | 授权页 |
| `/{MCP_PREFIX}/oauth/token` | `authorization_code` 与 `refresh_token` 两种 grant |
| `/{MCP_PREFIX}/oauth/revoke` | 撤销 access 或 refresh token |

不带完整前缀的 `/.well-known/...` 与未知路径同为空 body 的 404。前缀只出现在客户端后台请求与授权时浏览器的地址栏；授权页与令牌响应带 `Referrer-Policy: no-referrer`，授权页另带 `X-Frame-Options: DENY` 与 `frame-ancestors 'none'`。

注册。只收 `https` 回调，`http` 只收 `localhost`、`127.0.0.1`、`[::1]`；最多 16 个，不得带 fragment。`token_endpoint_auth_method` 缺省为 `none`（公共客户端）；请求 `client_secret_basic` / `client_secret_post` 时签发 secret，换令牌时必须出示。全局每小时最多 20 次注册，按固定窗口计：窗口从其中第一次注册起算一小时，到点清零。

授权。先校验 `client_id` 已注册、`redirect_uri` 与注册值逐字一致（只注册了一个时可省略），二者不成立只出错误页、不回跳；`response_type=code` 与 `S256` code_challenge 不成立按 RFC 6749 回跳带 `error`。通过后显示只有一个 `MCP_TOKEN` 输入框的页面，填对则回跳带 `code`、`state`、`iss`。填错按两层固定窗口计数：同一 `client_id` 错 10 次后，该 client 的授权页拒绝；所有 client 合计错 100 次后，所有 client 的授权页拒绝。窗口从该层第一次错误起算 15 分钟，到点清零；被拒期间正确的 `MCP_TOKEN` 也拿不到授权码。

令牌。授权码 5 分钟、一次性，读取与删除是一步原子操作，并发兑换同一个码只有一方拿到；换令牌校验 client、`redirect_uri`（请求里带了时）与 PKCE verifier。access token 1 小时，refresh token 30 天，refresh 时沿用原值不轮换、有效期从这次 refresh 起重算 30 天，持续使用就一直有效（Google 连接要求的持续连接）。令牌都是 32 字节随机值，存储里只放 SHA-256。每条授权记下所用 `MCP_TOKEN` 的指纹，该值从 `MCP_TOKEN` 移除后派生令牌一并失效。客户端注册与 refresh token 同寿，每次签发顺延。

撤销。`/{MCP_PREFIX}/oauth/revoke` 收表单 `token` 与可选的 `token_type_hint`，客户端认证与令牌端点相同：公共客户端带 `client_id`，机密客户端经 Basic 或表单出示 secret，认证失败为 `invalid_client`。只撤销记录里 `client_id` 与认证结果一致的令牌；未知、已过期或属于别的 client 的令牌同样回 200、不改任何状态。撤销 access token 只删这一个；撤销 refresh token 删掉它，并给这条授权链记一个 1 小时的作废标记，由它 refresh 出的 access token 随即失效。一条授权链从一次授权码兑换开始，refresh 沿用；本功能上线前签发的 refresh token 在下一次 refresh 时补上链标识，在此之前撤销它只删 refresh token 本身。

状态全部走 `DataStore` 的带 TTL 字符串，键在 `mcp_oauth:` 下；Redis 部署里这些键直接用原始键名，与 `REDIS_PREFIX` 无关（`get_string` / `set_string` 不经 `redis_key`）。计数器（注册数、两层错误数）用 `DataStore::incr_fixed_window` 原子自增，Redis 上是同一个 MULTI 里的 `SET NX EX` + `INCR`；授权码兑换用 `DataStore::take_string`，Redis 上是同一个 MULTI 里的 `GET` + `DEL`。文件后端在进程内加锁实现这两个操作。

外部地址。issuer 与元数据里的 URL 只取 `MCP_PUBLIC_URL`。前置反代要把上表两条根路径 `/.well-known/...` 转发给 DFS2。

### 脱敏边界

当前生效文件由 `config()` 返回打星后的 YAML 原文，规则见 [配置原文脱敏](./2026-09-20-config-yaml-redact.md)。`plugin_code` 不在这份 YAML 里。完整历史仍由 CI 镜像仓库承担；`config_mirror()` 返回镜像 clone 地址。MCP 不读配置目录的版本控制元数据。

### 工具面

按组裁剪见 [MCP 工具组开关](./2026-09-18-mcp-tool-groups.md)。

日志。不实现对象列举。文件名由 [Session log 自管理切桶与归档](./2026-09-11-session-log-rotate.md) 确定。`log_objects` / `log_objects_for_sid` 按 [归档对象存在探测](./2026-09-15-log-objects-exist.md) 同时探测日桶与小时桶，只返回确认存在的 GET presign。响应带当前桶标记、可能截半行、落后一轮同步间隔、时区偏移、当前与已探测的切桶小时数、以及 `probed` / `missing`。`MCP_LOG_PREFIXES` 列出的兄弟实例 prefix 一并推算。配合 [服务端 sid 携带创建时间](./2026-09-15-sid-time-prefix.md)，`log_objects_for_sid(sid)`：`sid_created_at` 解出创建时间后，把「创建时间 + `SESSION_TIMEOUT_HOURS` + `SESSION_CLEANUP_INTERVAL_MIN`」的搜索窗口换算收进服务端；解不出则返回明确错误，agent 退回 `log_objects`。

配置。`config()` 返回打星后的 config.yaml 原文，后接一行 `---`，再附 `loaded_at` 与加载时摘掉的 flow 节点引用，全部在同一个文本块里。`config_mirror()` 返回 `MCP_CONFIG_MIRROR_URL` 原文。

运行时状态。全部是点查，不做 SCAN：`server_health(server_id?)` 读健康检查缓存；`session(sid)` 返回仍在存储中的 session 与按 [调度惩罚拆分](./2026-08-27-schedule-penalty-split.md) 算出的 `banned` / `demoted`，记录里的 URL 去掉 query；`cache_entry(resid, version, path)` 返回缓存元数据含 [缓存来源](./2026-08-27-cache-provenance.md) 的 `src`；`bandwidth_today(resource|server, id)` 是签发时按请求大小计入的计数，不是送达字节；`override_binding(ip|sid)` 读 [强制调度 override](./2026-09-11-schedule-override.md) 的绑定。按配置枚举的全量查询与纯计算类查询见 [MCP 查询扩展](./2026-09-15-mcp-query-expansion.md)。`metrics_snapshot` 只在 Grafana 三项未配时注册。

指标。`grafana_query(promql, from, to, step)` 转发到指标系统的数据源查询接口，返回 Grafana frames。数据源 uid 与 viewer token 在环境变量里。跨度与 step 不做配置，代码里按单序列点数上限裁剪。三项配置缺一则该工具不注册。

签发。`sign_url` 按配置模板给单个节点签一条短 TTL 的 GET，见 [MCP 签发节点下载链接](./2026-09-21-mcp-sign-url.md)。

方法论。两个 resource：指标语义目录（哪个方向是下行、节点 id 落在哪个 label、哪些指标只有部分节点上报）随二进制版本走；排障说明默认内嵌，`MCP_PLAYBOOK_PATH` 设了则改读文件。

### 配置项

| 变量 | 必填 | 作用 |
|---|---|---|
| `MCP_TOKEN` | 是（启用时） | Bearer / `X-API-Key` / `?token=` 共用；逗号分隔允许两个值 |
| `MCP_PREFIX` | 是（启用时） | 路径段，挂到 `/{MCP_PREFIX}/mcp` |
| `MCP_LOG_S3` | 否 | presign 用的只读 S3 URL，缺省回落 `SESSION_LOG_ARCHIVE_S3` |
| `MCP_LOG_PREFIXES` | 否 | 逗号分隔的兄弟实例归档 prefix |
| `MCP_PRESIGN_TTL_SECONDS` | 否 | 默认 900 |
| `MCP_GRAFANA_URL` | 否 | 指标系统地址；与下两项齐全才注册指标工具 |
| `MCP_GRAFANA_TOKEN` | 否 | viewer 级 service account token |
| `MCP_GRAFANA_DATASOURCE_UID` | 否 | 数据源 uid |
| `MCP_CONFIG_MIRROR_URL` | 否 | 含 deploy token 的镜像 clone 地址，原样返回 |
| `MCP_PLAYBOOK_PATH` | 否 | 覆盖内嵌的排障说明 |
| `MCP_TOOL_GROUPS` | 否 | 逗号分隔的工具组 allowlist；语义见 [MCP 工具组开关](./2026-09-18-mcp-tool-groups.md) |
| `MCP_PUBLIC_URL` | 否（OAuth 必填） | 外部 origin，如 `https://charlotte.cocogoat.cn`；OAuth issuer 与元数据 URL 以它为准。设了才启用 OAuth 路由与 401 上的 `WWW-Authenticate` |

复用而不新增：`SESSION_LOG_ARCHIVE_S3`、`SESSION_LOG_ARCHIVE_PREFIX`、`SESSION_LOG_ROTATE_HOURS`、`SESSION_TIMEOUT_HOURS`、`SESSION_CLEANUP_INTERVAL_MIN`、`DATA_STORE_TYPE`、`REDIS_URL`、`REDIS_PREFIX`。

### 校验

`dfs2 validate` 检查：只设 `MCP_TOKEN` 或只设 `MCP_PREFIX` 报错；`MCP_PREFIX` 含非法字符报错；三项指标配置只设部分报错；`MCP_LOG_S3` 或回落的归档 URL 解析失败报错；`MCP_TOOL_GROUPS` 含未知组名或没有可用值报错；`MCP_PUBLIC_URL` 不是不带 query 的 http(s) 地址报错。

### 不包含

按人身份、工具调用的速率限制、OAuth scope、日志解析、对象列举、本地 `SESSION_LOG_PATH` 文件访问、任何写操作、配置重载、版本刷新、challenge 点查。sid 时间前缀本身在 [服务端 sid 携带创建时间](./2026-09-15-sid-time-prefix.md)。`sign_url` 不代测、不写 session。

## Alternatives considered

**独立程序与外置仓库，共享 DFS2 的环境变量。** 落选：日志 presign 与运行时点查仍要进程内句柄；MCP 逻辑薄到不值得第二套配置解析与 listener。文本改写规则见 [配置原文脱敏](./2026-09-20-config-yaml-redact.md)。

**`dfs2 mcp` 子命令，独立进程同一二进制。** 落选于第一版：换来进程隔离，付出独立 listener、反代多一条路由、配置自己重读。代码在同一 crate，进程内方案日后拆成子命令代价小。

**只接受 Bearer。** 落选：托管平台的接入常常只有 URL 输入框。

**只做 OAuth。** 落选：自写脚本与本地调试都要走浏览器流程；IM bot 是单身份接入，OAuth 拿不到额外的东西。OAuth 与三个静态入口并存。

**OAuth 端点放在根路径（`/authorize`、`/token`、`/.well-known/oauth-authorization-server`）。** 落选：扫描器按固定路径即可确认这是 MCP 服务并拿到入口；放到前缀下后，不知道前缀的请求在任何固定路径上都只得到 404。

**前置现成的 OAuth 代理。** 落选：要求 MCP 入口经过该代理所在的边缘，且多一套外部身份配置；单用户场景下 `MCP_TOKEN` 已是唯一身份。

**把 `MCP_PREFIX` 当唯一密钥。** 落选：泄露一次 URL 就要改路径，所有接入方重配；token 轮换只改环境变量。

**plugin options 走键名 allowlist。** 落选：每个插件一份 allowlist，维护成本落在 MCP 上；完整文本已有镜像仓库承担。

**实现 S3 对象列举。** 落选：文件名仍由切桶规则推候选 key。存在性由 [归档对象存在探测](./2026-09-15-log-objects-exist.md) 对候选做点查，不解析 ListObjects XML。

**MCP 内联返回日志内容。** 落选：小时桶 zstd 仍有数 MB 到数十 MB，走 presign 让 agent 沙箱自己下载。

**暴露本地 `SESSION_LOG_PATH` 文件。** 落选：多实例下 agent 拿到的是随机一台的本地视图。

**运行时状态暴露原始 GET / SCAN。** 落选：SCAN 给生产存储加负载；原始 key 布局是实现细节。

## Verification

| 判据 | 结果 |
|---|---|
| 未设 `MCP_TOKEN` 或 `MCP_PREFIX` 时路径不存在，启动日志有一行 info | PASS：`maybe_router_disabled_when_unset`、`disabled_when_unset`；`maybe_router` 在 Disabled 时打 info 且不 nest |
| 只设其一时 `dfs2 validate` 报错并退出非零 | PASS：`half_set_is_error`；`validate_env` 写入 `ValidationReport.env_valid` |
| 同一 token 经 Bearer / `X-API-Key` / `?token=` 通过；缺失或错误 401；两个逗号分隔值均可用 | PASS：`auth_three_entries_dual_tokens_and_401`、`extract_token_three_entries`、`two_tokens_match` |
| 以 query 形态请求时，捕获的 tracing 输出中不出现 token 字面量 | PASS：`query_token_is_absent_from_tracing` |
| fixture YAML 打星后查不到密钥字面量，注释与 host/path 仍在 | PASS：`config_returns_redacted_yaml`；规则测试见 [配置原文脱敏](./2026-09-20-config-yaml-redact.md) |
| `ROTATE_HOURS=1` 与 `24` 下，候选 key 与 `session_log_rotate` stem 规则一致；返回的 presign 为 GET 且 `X-Amz-Expires` 等于 TTL | PASS：`log_object_candidates_cover_daily_and_hourly`、`archive_keys_cross_midnight_hourly`、`archive_keys_daily_window`、`presign_uses_configured_ttl`；存在探测见 [归档对象存在探测](./2026-09-15-log-objects-exist.md) |
| 指标三项缺一时 `grafana_query` 不在工具列表中，且 `dfs2 validate` 报错；三项齐全时不注册 `metrics_snapshot` | PASS：`grafana_tool_absent_when_unset`、`grafana_partial_errors`、`grafana_tool_present_when_configured` |
| 运行时状态工具在 `MockDataStore` 上只触发读方法，不触发 SCAN | PASS：`runtime_tools_do_not_scan` |
| MCP 路径不出现在 OpenAPI 文档 | PASS：`mcp_sources_are_not_in_openapi`；MCP 模块无 `utoipa` 注解 |
| `sign_url` 见 [MCP 签发节点下载链接](./2026-09-21-mcp-sign-url.md) | PASS：该 note 的 Verification |
| 加 OAuth 后 Bearer / `X-API-Key` / `?token=` 三个静态入口行为不变，`bearer` 小写 scheme 同样通过；缺失或错误 token 仍为空 body 的 401，带指向受保护资源元数据的 `WWW-Authenticate`；前缀下其他路径仍 404 | PASS：`auth_three_entries_dual_tokens_and_401`、`extract_token_three_entries`、`static_tokens_unchanged_and_401_carries_resource_metadata` |
| 未设 `MCP_PUBLIC_URL` 时发现、注册、授权、令牌、撤销路径都与未知路径同为 404；401 不带 `WWW-Authenticate`；三个静态入口照常通过 | PASS：`without_public_url_oauth_is_absent_and_static_tokens_work` |
| 不带完整前缀的 `/.well-known/...` 与根路径 `/authorize`、`/token`、`/register` 和未知路径的响应完全相同（404、空 body、无额外头） | PASS：`well_known_without_exact_prefix_is_plain_404` |
| 前缀下的四种发现路径给出同一 issuer 与端点（含 `revocation_endpoint`），均取自 `MCP_PUBLIC_URL` | PASS：`discovery_under_prefix_uses_public_url`、`public_url_trims_slash_and_rejects_non_http` |
| 动态注册 → 授权页 → 填 `MCP_TOKEN` → 回跳带 `code`/`state`/`iss` → PKCE 换令牌 → access token 经 Bearer（含小写 `bearer`）访问 `/{MCP_PREFIX}/mcp` 通过；同一 access token 走 `X-API-Key` / `?token=` 为 401；refresh 返回原 refresh token，可反复使用，每次发新 access token | PASS：`dcr_authorize_token_flow_and_access_token_at_mcp` |
| 错误 PKCE、别的 client、重复使用的授权码、未知 client 被拒；授权码一次失败后即作废 | PASS：`wrong_pkce_and_wrong_client_rejected_and_code_consumed` |
| 未注册 client 或不一致的 `redirect_uri` 只出错误页不回跳；`plain`、过短 challenge、非 `code` 的 response_type 回跳带 `error` 不带 `code` | PASS：`authorize_validates_client_redirect_and_pkce` |
| 某 client 授权页错误 10 次后，该 client 正确 token 也被 429 拒绝，另一个 client 照常授权 | PASS：`failed_attempts_lock_only_that_client` |
| 所有 client 合计错误 100 次后，新注册的 client 也被 429 拒绝 | PASS：`global_failure_cap_locks_every_client` |
| 错误计数窗口从第一次错误起算，到期后解除 | PASS：`failure_window_is_not_extended_by_later_failures`、`store_counter_window_is_fixed_and_take_is_single_use` |
| 撤销：别的 client 撤销不生效且回 200；未知 token 回 200；未认证为 `invalid_client`；撤销 access token 后它即 401；撤销 refresh token 后它不能再 refresh，由它 refresh 出的 access token 401；机密客户端须带 secret 才能撤销 | PASS：`revocation_deletes_tokens_of_the_authenticated_client_only`、`confidential_client_must_present_secret` |
| 注册拒绝非 loopback 的 `http`、非 http(s)、带 fragment、空列表与不支持的 grant；loopback 通过；每小时第 21 次注册 429 | PASS：`register_validates_metadata_and_caps_count` |
| 机密客户端换令牌不带 secret 为 `invalid_client`，Basic 认证通过 | PASS：`confidential_client_must_present_secret` |
| 从 `MCP_TOKEN` 移除授权时所用的值后，派生的 access 与 refresh token 失效 | PASS：`removing_mcp_token_revokes_derived_tokens` |
| `cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test` | PASS：`cargo test --offline` 350 通过（本机 `dev` profile） |

## Consequences

生产二进制多一块网络可达的表面，MCP 依赖的缺陷会直接影响服务进程。路由只在两项配置齐全时挂载，所有工具只读；Streamable HTTP 长连接与出站请求的失败都收敛为工具级错误。

query 形态的 token 会被任何未按部署说明配置的中间层记录下来。缓解是双 token 轮换与部署说明中的反代要求，无法从代码侧强制。

presigned URL 与配置快照在 TTL 内对任何持有者有效；面向团队内成员的前提下接受。脱敏后的配置仍暴露节点拓扑与资源规则，这是排障所需，同样在团队内前提下接受。

配置原文按键名与 URL userinfo 打星，键名不匹配的新密钥字段会原样留下；见 [配置原文脱敏](./2026-09-20-config-yaml-redact.md)。

进程内转发指标查询让 DFS2 多一条出站依赖；指标系统不可达时只影响该工具。

OAuth 授权状态（注册、授权码、令牌、失败计数）写进 `DataStore`，均带 TTL。拿到前缀的人可以注册客户端、打开授权页；授权仍要 `MCP_TOKEN`；填错会让该 client 的授权页最长锁 15 分钟，合计错 100 次会让所有 client 的授权页锁到窗口到期，期间静态入口不受影响。拿到前缀的人因此能让 OAuth 授权页暂时不可用，最长到当前窗口到期。已签发的 access token 在 1 小时内、refresh token 自最近一次 refresh 起 30 天内持续有效；客户端可经撤销端点作废自己的令牌，运维侧撤销靠从 `MCP_TOKEN` 移除对应值。授权页的错误计数是先读后加，并发填错可以略超过上限。

`disable_allowed_hosts()` 把 DNS rebinding 防护交给前置反向代理；反代若未校验 `Host`，本路径只剩 token 一道门。

MCP 依赖只开 `server` / `macros` / `transport-streamable-http-server`，不开 `auth` 与 `reqwest`，避免再拉一套 HTTP 客户端；指标转发走进程已有的 `reqwest`。

多实例部署下每台都有该端点，`MCP_LOG_PREFIXES` 配置不一致会让不同实例给出不同的日志目录，需要在部署侧保持一致。
