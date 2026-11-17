# MCP 查询扩展

Status: implemented

## Problem

[排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md) 的运行时状态工具全部是按请求给出的身份点查：一个 sid、一个节点、一条缓存路径。全量问题答不了——「现在哪些节点挂了」「这个资源现在有没有版本不一致」「此刻谁在吃流量」——不是因为数据不存在，而是工具面没有把「枚举源」这一步做出来。

禁 SCAN 的理由仍然成立：SCAN 给生产存储加负载，且原始 key 布局是实现细节。但 SCAN 只在「不知道 key 是谁」时才需要。节点与资源的身份全在配置里，版本文件普查的结果已经按 (资源, 路径) 落在存储里，进程自己的指标 registry 也在内存中。这些都能不碰 SCAN 地回答。

另有一批排「为什么这个用户被调到这里」所需的判定完全不碰存储：调度器眼里某个 IP 是什么、某个节点会被要求取哪条路径。它们现在只能带管理 token 走管理端点，或者由 agent 读配置自己推。

## Decision

查询按数据来源分四类，每类一个原则。所有工具仍然只读，不做 SCAN，不暴露写路径。

### 纯计算：只用配置与进程内的库

`geoip(ip)` 返回 flow 规则求值所见的同一份地理字符串、IP 版本、是否公网地址；同时给出 `internal.egress_ip` 的同款判定。`egress` 未配置时是 `configured: false`，不是工具错误。数据源是进程已加载的 ipdb，与 `cnip` / `geoip` 条件同一路径。

`resolve_paths(resid, version?)` 按 `versions` / `default` 模板与节点 id 展开，返回该资源在每个节点上的实际取件路径，以及 `version_files` 各条展开后的路径。`version` 省略时用 `get_effective_version`。复用 `version_path_for_resource` 与 `version_file_path_for_resource`，前缀资源在 `version_path_for_resource` 为 `None` 时回落到 `version_base_path_for_resource`。

### 进程内快照：后台状态直接读

`metrics_snapshot()` gather 进程自己的 Prometheus registry，原样返回文本。三项 Grafana 配置齐全时不注册。

`runtime_info()` 返回包版本、启动时刻、配置加载时刻、数据后端类型、切桶小时数、session 超时小时数、清理间隔。全部是非密的派生设置，不含环境变量原值。

### 配置枚举加有界扇出：全量视角

扇出上限是配置里的节点数或资源数，每个元素一次点查。省略筛选参数即全量。

`version_census(resid?)` 对配了 `version_files` 的资源，按 `resolved_version_file_paths` 展开路径，逐条读存储里的 `VersionFileView`，并按 `evaluate_server` 给出每个节点的 Match / Mismatch / Unknown / SplitFailed。不 ping、不写回普查视图；等后台任务。

`server_health()` 无参形态遍历带 `health_check_path` 的节点，响应为 `{ checked, unchecked }`。`unchecked` 是没有配健康检查路径的节点 id。`checked` 读的是 [周期 ping 发布节点健康结果](./2026-09-15-ping-publishes-health.md) 写入的连通性条目，每条带 `age_seconds`。

`bandwidth_recent(server_id?, minutes)` 读 `BandwidthCacheService::get_server_minutes_bandwidth` 的分钟环，省略 `server_id` 时按节点扇出。`minutes` 截到 `BANDWIDTH_MINUTE_RING_SIZE`（1440）。响应带 `read_at`。

`bandwidth_today()` 无参形态按全部资源与全部节点扇出今日累计，加全局值。带 `kind` / `id` 的形态不变。

`cache_entries(resid)` 对 `cache_enabled` 且配了 `version_files` 的资源，用与 `cache.rs` 相同的 key 构造逐条读 `CacheMetadata`，含 [缓存来源](./2026-08-27-cache-provenance.md) 的 `src`。不返回内容字节。`cache_enabled=false` 或无 `version_files` 时返回空列表。`cache_subpaths` 通配下的条目身份不可枚举，不覆盖。

`resource_versions(resid?)` 按资源扇出：静态 `latest`、`get_effective_version`、`get_cached_version_info` 的缓存版本与更新时刻、`version_provider` 的插件名与 `cache_ttl`。无 `version_provider` 时这些字段为空，不报错。

### 请求身份点查：补齐现有集合

`override_ticket(uuid)` 读 [强制调度 override](./2026-09-11-schedule-override.md) 的票：目标节点、可选 `resid`、剩余 TTL。不存在或已过期返回 `found: false`。

`session(sid)` 在现有 Session 与惩罚之外并入 `get_session_stats` 的 `download_counts` 与按 chunk 的 `cdn_records`。记录里的 URL 去掉 query 与 fragment。

### 不包含

调度 dry-run（`flow_explain`）另立 note，它动的是 `FlowService`。活跃 session 列表、按 IP 找 session、`cache_subpaths` 通配下的缓存条目：身份不可枚举，不做。插件 JS storage 读取：key 由插件私定。任何写路径：版本提供者刷新、配置重载、普查 refresh 不进 MCP。challenge 点查不进 MCP。

## Alternatives considered

**在进程内为普查另留一份 `CensusReport` 快照。** 落选：`CensusReport` 只有 errors / warnings 两组字符串，细节全在存储里的 `VersionFileView`，且 (资源, 路径) 可从配置枚举；再留一份是重复状态。

**`version_census` 带 `refresh`。** 落选：MCP 不写出站探测、不写普查视图；等后台任务。

**用 SCAN 实现全量问题。** 落选：枚举源在配置里，扇出有界；SCAN 给生产存储加负载且暴露 key 布局。

**`metrics_snapshot` 改为结构化 JSON。** 落选：Prometheus 文本格式 agent 直接能读，结构化是第二套 schema 要维护。

**`challenge(sid)`。** 落选：exists/type 没有排障场景；载荷含期望答案。

**`cache_entries` 返回内容字节以便与多数派比对。** 落选：与现有 `cache_entry` 一致只返回元数据；比对用 `etag` 与普查哈希，口径不一致时由 agent 下载对比。

**`resolve_paths` 与 `geoip` 通过管理端点转发。** 落选：进程内直接调同一函数，不需要管理 token，也不多一跳。

## Verification

| 判据 | 结果 |
|---|---|
| `geoip` 地理字符串与 `get_ip_location_data` 逐字相同；`egress_ip` 未配置返回 `configured: false` | PASS：`geoip_matches_flow_geo_string_and_egress_unset_is_explicit` |
| `resolve_paths` 各节点路径与 `version_path_for_resource` 一致，`version_files` 与 `resolved_version_file_paths` 一致 | PASS：`resolve_paths_matches_resource_helpers` |
| `metrics_snapshot` 文本可按 Prometheus 文本行解析，且含 `dfs_active_sessions`；Grafana 已配时不在工具列表中 | PASS：`metrics_snapshot_is_prometheus_text_with_active_sessions`、`grafana_tool_present_when_configured` |
| `runtime_info` JSON 不含 `REDIS_URL`、归档 URL、token 字面量 | PASS：`runtime_info_omits_secret_env_literals` |
| 两资源三路径 fixture 返回六条视图，每条带每个节点判定；按 resid 筛选只返回该资源 | PASS：`version_census_reads_six_views` |
| `server_health()` 的 `unchecked` 恰为没有 `health_check_path` 的节点集合 | PASS：`server_health_lists_unchecked_without_path` |
| `bandwidth_recent` 省略 `server_id` 时条目数等于配置节点数；`minutes` 超过环长度被截到环长度 | PASS：`bandwidth_recent_fans_out_and_clamps_minutes` |
| `bandwidth_today()` 无参返回资源、节点、全局三组 | PASS：`bandwidth_today_all_has_three_groups` |
| `cache_entries` 在 `cache_enabled=false` 或无 `version_files` 时返回空列表；返回项含 `src` | PASS：`cache_entries_empty_without_cache_or_version_files_and_includes_src` |
| 无 `version_provider` 的资源缓存字段为空且不报错 | PASS：`resource_versions_without_provider_has_empty_cache_fields` |
| `override_ticket` 对不存在、已过期返回 `found: false`；有效票返回剩余 TTL | PASS：`override_ticket_found_expired_and_missing` |
| `session` 含 `download_counts` 与 `cdn_records`，URL 去掉 query | PASS：`session_includes_download_counts_and_strips_signed_query` |
| 扩展后的运行时工具在 `MockDataStore` 上不触发 SCAN | PASS：`runtime_tools_do_not_scan` |
| `cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test` | PASS：`cargo fmt --check`、`cargo clippy --offline --tests -- -D warnings`、`cargo test --offline` 367 通过（本机 `dev` profile） |

## Consequences

扇出类工具的单次调用成本随配置规模增长。节点与资源都是几十量级，每元素一次 GET，可接受；配置规模若上一个量级，要改成 MGET 或 pipeline，接口不变。

`cache_entries` 的 `etag` 是带引号的十进制 `xxh3_64`（`generate_etag`），普查的 `majority_hash` 是十六进制 16 位（`hash_content`）。同一内容的两个字符串不可直接比对，agent 需下载缓存内容自行计算。

`metrics_snapshot` 把本进程全部指标交给 agent，其中含按节点与资源的标签值。配了 Grafana 时不注册。

`session` 扩展后返回的 `cdn_records` 去掉 query，不含活签名。

`bandwidth_recent` 读的是分钟环，分钟边界上的写入可能尚未 flush，读数比真值略低；响应带读取时刻，agent 据此判断。
