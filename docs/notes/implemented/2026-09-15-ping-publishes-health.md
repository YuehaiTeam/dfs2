# 周期 ping 发布节点健康结果

Status: implemented

## Problem

[排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md) 的 `server_health` 按 `health:{server_id}:{server.health_check_path}` 读健康缓存，线上返回全空。这把 key 从未被写过。

健康缓存有三条写入路径，没有一条用 `ServerConfig::health_check_path` 作 key 的 path 段。调度时的 `FlowService` 传给 `is_alive` 的是 `get_version_path` 解出的资源文件路径；版本文件普查按 (节点, 解析后的版本文件路径) 写；`ping_selected_servers` 是唯一用 `health_check_path` 探测的地方，但探测结果只留在返回值里。

于是存储里存在的健康条目全部按「用户最近下过的文件」或「版本文件」的路径分布，身份不可从配置枚举；而唯一可枚举的 key（按配置的健康检查路径）没有数据。舰队级的「哪些节点挂了」没有可读的数据源，尽管每三分钟的普查前置 ping 已经在对全部节点实测。

## Decision

`ping_selected_servers` 接受 `store: Option<&DataStore>`。探测仍不读缓存（走 `probe_liveness`）；探测完成后若 `store` 为 `Some`，对每个 `probed` 节点写 `set_health_info(server_id, health_check_path, HealthInfo)`，带上 `is_alive`、`file_size`、`observed_cert_hash`。key 即 `health:{server_id}:{health_check_path}`，与 MCP 现有读法一致。

`VersionFileService::ping_and_census_all` 传 `Some(data_store)`。`dfs2 validate` 的 `validate_server_connectivity` 走 `ping_servers`，不写生产存储。`ping_servers` 是无存储的便捷形态。

探测不读健康信息缓存；`store` 为 `Some` 时只写不读。写入是发布探测结论，不改变普查跳过节点的判定来源。

MCP `server_health` 的每条 `checked` 附 `age_seconds`（当前时刻减 `last_check`）。节点身份用配置里的 servers 键，不用 `ServerConfig.id`。`server_health` 回答的是按 `health_check_path` 测到的连通性，不是「能服务某资源」。

`FlowService` 里指向 `get_version_path` 结果的局部变量叫 `resource_path`。调度对健康缓存的读法、普查按版本文件路径写健康条目、以及 TTL 都不改。

## Alternatives considered

**MCP 改读普查按版本文件路径写的条目。** 落选于替代方案：那些条目只覆盖参与了带 `version_files` 资源的节点，且反映的是「对这个版本文件能否服务」而不是节点连通性；作为补充视图归 [MCP 查询扩展](./2026-09-15-mcp-query-expansion.md) 的 `version_census`，不替代本篇。

**ping 改为 `is_alive(…, Some(store))` 读写都走缓存。** 落选：`is_alive` 命中缓存即返回不探测，TTL 300 秒长于普查间隔 180 秒，隔轮就会用陈旧结论决定普查跳过哪些节点；注释里记录的多数派风险正是为此。

**在 `ping_and_census_all` 里循环写，不改 `ping_selected_servers` 签名。** 落选：写入与探测并发控制应在同一处；且 `is_alive` 的返回值只有 `bool`，`file_size` 与证书哈希会丢。

**MCP `server_health` 自己发探测。** 落选：MCP 工具只读；探测由普查任务统一节流与并发控制。

**缩短 TTL 或加长间隔以对齐。** 落选：TTL 与间隔各有自己的理由，本篇只需要「间隔小于 TTL」成立。

## Verification

| 判据 | 结果 |
|---|---|
| `ping_selected_servers(..., Some(store))` 对每个 `probed` 节点写 `health:{id}:{health_check_path}`；传 `None` 不写 | PASS：`ping_writes_health_only_when_store_is_some` |
| 预先放 `is_alive=false` 的同 key 条目，探测仍按实测覆盖 | PASS：`ping_overwrites_cached_dead_without_reading_it` |
| `dfs2 validate` 跑完后 store 中没有新增健康条目 | PASS：`validate_does_not_publish_health_entries` |
| 两带路径、一不带的 fixture，普查一轮后 `checked` 恰为前两个且各带 `age_seconds`，`unchecked` 恰为后一个 | PASS：`server_health_after_census_ping_has_age_and_unchecked` |
| `flow_service.rs` 生产代码不再用 `health_check_path` 指资源路径；`cargo test services::flow_service` 通过 | PASS：`resource_path_is_not_named_health_check_path` |
| `cargo fmt --check`、`cargo clippy -- -D warnings`、`cargo test` | PASS：`cargo fmt --check`、`cargo clippy --offline --tests -- -D warnings`、`cargo test --offline` 372 通过（本机 `dev` profile）；`cargo test --offline services::flow_service` 61 通过 |

## Consequences

普查任务是按 `health_check_path` 写入健康条目的周期来源。它因配置为空或异常停止时，MCP 看到的是条目缺失而非陈旧值；`age_seconds` 只能报告存在的条目，缺失要靠 `checked` 里 `health` 为空或条目没有 `age_seconds`。

每轮 ping 多 N 次存储写入，N 为带 `health_check_path` 的节点数，几十量级，每三分钟一轮。

按 `health_check_path` 探测的结论与调度按资源路径探测的结论可能不一致：节点通但某资源的文件缺失。`server_health` 回答连通性，不回答「能服务某资源」。
