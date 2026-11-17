# 服务端 sid 携带创建时间

Status: implemented

## Problem

排障反馈里最常见的输入是一串 sid，没有时间。session log 按本地时间切桶归档，见 [Session log 自管理切桶与归档](./2026-09-11-session-log-rotate.md)；要找到这个 sid 的记录，只能猜它落在哪些桶里，逐个下载 grep。切桶越细，猜的范围越大。

客户端自带的 sid 与 legacy 路径的 sid 本身不携带可用于定位的信息。JSON 里的 `start` 字段记着创建时间，但它在文件里面，要先打开文件才看得到，而定位文件正是问题所在。

## Decision

服务端生成的 sid 前 8 位 hex 是创建时刻的 unix 秒（`u32` 大端），后 24 位 hex 是 12 字节随机数。总长仍是 32 位 hex，字符集不变。`generate_session_id` 走这一条。

改动范围只有 `handle_create_session_unified` 中 `req.sid` 为空时那一条路径，即 session + chunk 协议。客户端自带的 sid 原样沿用，不检查、不改写。legacy 路径的 sid 是客户端解出的 md5 challenge 响应值，服务端没有插前缀的机会，不动。

`sid_created_at(sid) -> Option<u64>`：长度为 32、全部 hex、前 8 位解出的秒数落在编译期常量 `SID_CREATED_AT_FLOOR`（2026-01-01T00:00:00Z）与「当前时间 + 5 分钟」之间时返回该秒数，否则返回 `None`。`None` 覆盖客户端自带 sid、legacy sid 与旧格式 sid，调用方退回按时间窗口查找。

sid 给出的是创建时间，session log 记录写在 session 结束时，落在结束时刻所在的桶。查找窗口从创建时刻所在的桶开始，到创建时刻加 `SESSION_TIMEOUT_HOURS` 再加 `SESSION_CLEANUP_INTERVAL_MIN` 所在的桶结束；超时 session 由清理任务写出，同样落在这个窗口内。窗口换算由 [排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md) 的 `log_objects_for_sid` 承担，agent 不自己算。

`SessionLog.sid`、存储 key、challenge 关联方式都不变。`dfs2 analyze` 不受影响。

## Alternatives considered

**人可读前缀 `YYYYMMDDHH-`。** 落选：文件名用本地时间，sid 若也编码本地时间就与服务端时区耦合；unix 秒与 JSON 里 `start` / `end` / `ts` 同一口径，换算放在服务端一处。

**毫秒精度、12 位 hex 时间。** 落选：定位小时桶用秒足够，多出的 4 位只压缩随机部分。

**改总长或改成 UUIDv7 文本形态。** 落选：线上安装器与网页客户端对 sid 长度和字符集的假设不可见，保持 32 位 hex 是最稳的兼容策略。

**同时给客户端自带 sid 与 legacy sid 加前缀。** 落选：前者是客户端的标识符，服务端改写会破坏免认证模式下的跨文件复用；后者是哈希输出，无法携带前缀。

**建 sid 到桶的索引。** 落选：多一份要维护的存储，而前缀本身已把查找收敛到三四个桶。

**在 session log 里为 legacy 记录补写 challenge 下发时间。** 落选于本篇：那是日志格式的事，且 legacy `Direct` session 的 TTL 只有 `DIRECT_TTL_SECONDS`，窗口本来就短。

## Verification

| 判据 | 结果 |
|---|---|
| `generate_session_id` 输出 32 位小写 hex；前 8 位解出的秒数与生成时刻相差不超过 1 秒；连续两次生成的后 24 位不同 | PASS：`test_session_id_generation` |
| `sid_created_at` 对新格式 sid 返回创建秒数；对下限之前的 32 位 hex、长度不为 32、含非 hex、未来 5 分钟之外的输入返回 `None` | PASS：`sid_created_at_rejects_non_prefix`、`test_session_id_generation` |
| `handle_create_session_unified` 在 `req.sid` 非空时沿用原值 | PASS：`test_reuse_sid_reauths_and_keeps_penalty_records` 等既有会话测试 |
| legacy 路径 `generate_legacy_challenge` 存储的 session key 仍为 challenge 期望响应值 | PASS：`test_legacy_challenge_generation`、`test_legacy_challenge_with_range` |
| `cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test` | PASS：`cargo test --offline` 350 通过（本机 `dev` profile） |

## Consequences

随机部分从 128 位降到 96 位。sid 是存储 key 与 challenge 关联键，不是密钥材料，96 位对唯一性与不可猜测性足够。

sid 向客户端泄露创建时刻。session log 的 `start` 已记录同一信息，且 sid 只回给创建它的客户端。

`u32` 秒在 2106 年溢出。届时改 12 位 hex 即可，与本篇同等的兼容性讨论。

客户端若对 sid 做了服务端看不到的格式校验（例如要求「看起来随机」），长度与字符集不变的前提下仍可能有极端假设失败；没有已知的这类客户端。

前缀只覆盖服务端生成的 sid。免认证复用与 legacy 路径的记录仍靠 IP 或时间窗口查找，这是范围而不是缺陷，排障说明里写明 `sid_created_at` 返回 `None` 时退回 `log_objects`。
