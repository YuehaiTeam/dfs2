# 归档对象存在探测

Status: implemented

## Problem

Session log 的切桶宽度会变。历史上按天归档，当前按小时。`log_objects` 若只按进程此刻的 `SESSION_LOG_ROTATE_HOURS` 推 object key，历史日桶不会出现在候选里。

presign 不检查对象是否存在。agent 拿到一串看起来合法的 URL，进沙箱下载才 404。空窗口与「算错了文件名」在它那边无法区分。

## Decision

`log_objects` 与 `log_objects_for_sid` 先对窗口生成候选 key，再对每个 key 做存在探测，只给确认存在的对象签 GET presign。

候选覆盖日桶（24）与小时桶（1），以及当前 `SESSION_LOG_ROTATE_HOURS` 若不是这两者之一。不列举 bucket，不解析 ListObjects XML。key 算法仍是 [Session log 自管理切桶与归档](./2026-09-11-session-log-rotate.md) 的 stem 规则。

探测用带 `Range: bytes=0-0` 的 GET，权限与 agent 随后的下载同为 `GetObject`。200 / 206 视为存在，404 / 403 视为不存在，其余状态或传输失败整次工具报错。并发上限 16。错误文本不含签名 URL。

响应在原有字段之外给出 `rotate_hours_probed`、`probed`、`missing`。空 `objects` 表示探测过的候选里没有现存对象。当前桶若已同步仍会返回，并继续标 `current` 与 `current_may_be_partial`。

[排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md) 的日志工具按本篇返回现存对象。

## Alternatives considered

**只探测当前 `SESSION_LOG_ROTATE_HOURS` 推出的 key。** 落选：历史是日桶时，小时候选里根本没有那些对象，探测也救不回来。

**S3 ListObjects 按 prefix 列举。** 落选：要解析 XML、处理截断，且列出的 key 仍要对照时间窗口；候选点查足够覆盖日 / 小时两种已知文件名。

**继续把不存在的 URL 交给 agent。** 落选：沙箱下载 404 浪费一轮，且与「窗口内没有日志」无法区分。

**HEAD。** 落选：部分只读凭据只有 `GetObject`；Range GET 用同一权限。

## Verification

| 判据 | 结果 |
|---|---|
| 跨日窗口的候选同时含日桶与小时桶文件名 | PASS：`archive_keys_union_includes_daily_and_hourly`、`log_object_candidates_cover_daily_and_hourly` |
| `archive_probe_hours` 始终含 1 与 24 | PASS：`archive_probe_hours_always_covers_daily_and_hourly` |
| 200 / 206 为存在，404 / 403 为不存在，其余为错误 | PASS：`existence_from_status_maps_common_codes` |
| 探测请求签的是带 Range 的 GET，错误不含 URL | PASS：`existence_probe_signs_range_get`；传输错误字符串写死、不含签名 |
| 只对存在的对象签发 TTL 内的 GET presign | PASS：`presign_window` 先 `object_exists` 再 `generate_presigned_get_url_for_expires`；`presign_uses_configured_ttl` |

## Consequences

每次 `log_objects` 对窗口内每个候选发一次短 GET。跨度按天放大时，探测次数约是「天数 + 小时数」乘 prefix 数；16 路并发，单次超时 10s。对象存储不可达时整次工具失败，不再返回一批注定 404 的 URL。

403 与 404 都当不存在。凭据被拒时会得到空列表，与「窗口内没有归档」同形；`probed` / `missing` 能看出探过多少。

当前小时桶若还没做分钟同步，探测为不存在，响应里不会出现它。这比返回一个 404 URL 更接近事实。
