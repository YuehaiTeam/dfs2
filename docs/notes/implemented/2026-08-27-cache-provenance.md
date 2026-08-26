# 缓存条目记录供出节点

Status: implemented

## Problem

线上反复出现缓存内容不正确的情况，而缓存条目只保存内容与基本元数据，无法回答"这份字节是哪个节点供出的"。排查只能逐节点手工拉取同一路径做比对，在多节点、多 PoP 的情况下代价高且结论不确定。

节点间版本文件不一致的结论此前写入 session log。多数派判定是集群在某一时刻的时序事实，不是单次会话的事实：按会话粒度记录既无法在监控侧按节点聚合，也让会话日志承担了与会话无关的语义，日志体积随资源与路径数膨胀。

## Decision

`CacheMetadata` 带 `src` 字段，记录供出这份字节的节点 ID。字段用 `serde(default)` 加 `skip_serializing_if`，因此存量条目仍可反序列化，且不会在序列化时凭空补出空值。

两条写入路径都传入来源节点：客户端请求触发的回源回填走 `download_and_cache`，版本文件普查确认多数派后的回填走 `write_majority_cache`。

缓存响应带两个头。`x-dfs-cache-status` 取 `hit` 或 `miss`，区分本次响应的字节是取自缓存层，还是本次刚从源节点拉取并顺手回填——它描述本次请求的经历，不是条目的年龄。`x-dfs-cache-from` 给出 `src`，存量条目没有该字段时整个头省略，而不是输出空值或占位符。

缓存命中在所有 `download` 策略下都记入 session log，写入一条合成的 `CdnRecord`：`mode` 为 `cache`、`rsn` 为 `cache_hit`、`srv` 为来源节点、`size` 为文件大小。命中记录带 sid，因此同一会话内的缓存命中与真实回源记录可以串在一起看。

节点一致性通过两个 Gauge 上报：`dfs_version_file_mismatch_files{server_id, resource_id}` 是该节点与多数派不一致的版本文件数，`dfs_version_file_no_majority{resource_id}` 是该资源当前无严格多数派的版本文件数。两者每轮普查全量重算，普查开始前先 `reset`，否则节点恢复一致或从配置中移除后会永远停在上一轮的数值。普查在 CLI 校验路径下没有 registry，因此 `VersionFileService` 持有的是 `Option<Arc<Metrics>>`，该路径传 `None`。

## Alternatives considered

**把多数派结论写 session log。** 落选：多数派是集群时序事实而非会话事实，写进会话日志后监控侧无法按节点聚合，只能靠离线解析全量日志反推，且日志量随资源数与路径数膨胀。

**沿用 `x-cache` 头名。** 落选：各家 CDN 对 `x-cache` 的取值约定不统一（`HIT`/`Hit from cloudfront`/`TCP_MEM_HIT` 等），中间层与客户端容易按自家习惯误读；且该头无法承载来源节点。统一收进 `x-dfs-` 前缀，两个头各管一件事。

**把来源节点并进缓存 key。** 落选：同一份内容会按来源拆成多份条目，命中率下降；来源节点变化时还会触发无意义的回源。

**`src` 设为必填字段。** 落选：存量条目没有该字段，反序列化失败会让缓存全量击穿。兼容性由一条专门的测试钉住。

## Verification

| 判据 | 结果 |
|---|---|
| 无 `src` 的存量条目仍可读，且回写时不产生该字段 | PASS：`legacy_metadata_without_src_still_parses` |
| 缓存命中输出 `hit` 与来源节点，且不输出 `x-cache` | PASS：`cache_hit_exposes_source_node` |
| 本次拉取并回填的响应输出 `miss` 与来源节点 | PASS：`freshly_filled_cache_reports_miss` |
| 缺 `src` 的条目省略 `x-dfs-cache-from` 而非输出空值 | PASS：`entry_without_source_omits_from_header` |
| 全量测试无新增失败 | PASS：253 passed / 6 failed，6 个失败全部位于 `src/commands/analyze/stats/`，该目录本次未改动 |

## Consequences

排查一份可疑缓存现在只需一次请求：`x-dfs-cache-status` 说明字节来自缓存还是本次回源，`x-dfs-cache-from` 直接点出节点，不必再逐节点比对。节点级不一致有了可聚合的指标，监控侧能看出是某个节点持续落后，还是集群整体分裂。

代价有三处。`src` 记录的是写入该条目时的供出节点，条目被覆盖前不更新，因此它回答"这份字节从哪来"，不回答"该路径当前应该是什么"。`x-dfs-cache-from` 把内部节点 ID 暴露给客户端；节点 ID 不含地址与凭据，但确实泄露了节点命名与数量的下界。缓存命中现在对所有策略都写日志，会话日志条数随缓存命中率上升。
