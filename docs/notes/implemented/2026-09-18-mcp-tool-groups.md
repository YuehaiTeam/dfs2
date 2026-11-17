# MCP 工具组开关

Status: implemented

## Problem

[排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md) 挂载后多组工具一起出现：日志 presign、脱敏配置、运行时点查、指标转发、签发节点 URL。暴露面不同——有的部署只想给运行时点查，不能签发归档或节点下载 URL，也不能把配置镜像地址交给 agent。没有组级开关时，只能整端点开或关。

## Decision

`MCP_TOOL_GROUPS` 是逗号分隔的组名 allowlist。未设或空字符串全部组开；设了只注册列出的组。路由仍按 `MCP_TOKEN` 与 `MCP_PREFIX` 挂载，裁剪的是工具列表，不是路径。

组名与 [排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md) 的工具面对齐：

| 组 | 工具 |
|---|---|
| `log` | `log_objects`、`log_objects_for_sid` |
| `config` | `config`、`config_mirror` |
| `runtime` | `server_health`、`session`、`cache_entry`、`cache_entries`、`bandwidth_today`、`bandwidth_recent`、`override_binding`、`override_ticket`、`geoip`、`resolve_paths`、`metrics_snapshot`、`runtime_info`、`version_census`、`resource_versions` |
| `metrics` | `grafana_query` |
| `sign` | `sign_url` |

[MCP 查询扩展](./2026-09-15-mcp-query-expansion.md) 的工具落在 `runtime`。`metrics_snapshot` 是进程内 registry，不进 `metrics`；三项 Grafana 配置齐全时不注册，避免被当成全池数据。`grafana_query` 仍要三项齐全；组开了但三项不齐则该工具不注册。`sign_url` 见 [MCP 签发节点下载链接](./2026-09-21-mcp-sign-url.md)。方法论两个 resource 不按组开关。

未知组名、或设了却只有空白与逗号，`dfs2 validate` 与 `serve` 都失败。MCP 未启用时同样校验该变量。重复组名合并。

## Alternatives considered

**按工具名 allowlist。** 落选：工具会继续加，部署配置要跟着每个名字改。组是能力边界（日志 presign / 配置快照 / 运行时点查 / 指标转发 / 签发节点 URL），一份部署意图能稳住。

**denylist。** 落选：未设即全开已经覆盖默认；denylist 在新增工具时会把新能力自动暴露给本想收窄的实例。

**按组各发一套 token。** 落选：同一端点多身份要改鉴权与接入方配置；先用一组 token 加工具列表裁剪。

## Verification

| 判据 | 结果 |
|---|---|
| 未设 `MCP_TOOL_GROUPS` 时全部组开（`grafana_query` 仍受三项配置约束；配齐 Grafana 时不注册 `metrics_snapshot`） | PASS：`tool_groups_unset_is_all`、`grafana_tool_absent_when_unset`、`grafana_tool_present_when_configured` |
| `MCP_TOOL_GROUPS=runtime, log, runtime` 解析为 `{runtime, log}`，`config` 不开 | PASS：`tool_groups_allowlist_parses` |
| 只开 `runtime` 时列表只有该组工具，不含 `config` / `log_objects` / `grafana_query` / `sign_url`；Grafana 已配时也不含 `metrics_snapshot` | PASS：`tool_groups_allowlist_lists_only_those_groups` |
| 只开 `metrics` 但 Grafana 未配时列表为空 | PASS：`tool_groups_metrics_still_requires_grafana` |
| 只开 `sign` 时列表只有 `sign_url` | PASS：`tool_groups_sign_lists_only_sign_url` |
| 每个已注册工具都有组 | PASS：`every_listed_tool_has_a_group` |
| 未知组名或只有空白逗号时 `dfs2 validate` 失败；MCP 未启用时未知组名同样失败 | PASS：`tool_groups_unknown_is_error`、`tool_groups_empty_is_error`、`tool_groups_unknown_errors_when_mcp_disabled` |

## Consequences

新加工具必须归入上表一组，否则只开 allowlist 的实例看不到它。`every_listed_tool_has_a_group` 卡住遗漏。新加组时，已经写了 allowlist 的部署不会自动获得该组。

只开 `metrics` 且 Grafana 未配时，端点挂着但工具列表为空；这是配置组合的结果，不另报错。
