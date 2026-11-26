# 重试硬剔除与复用降权分离

Status: implemented

## Problem

客户端拿到一个下载 URL 后失败会再要一个，调度必须避开刚给过的节点，否则客户端在同一个坏节点上原地打转。此前的实现把该会话签发过的所有节点一律硬剔除出候选池，惩罚状态按 range 字符串索引。

两个后果。并发多 chunk 下载时，每个 chunk 各签发一次就把签过的节点全部剔除，池子可以被清空，此后的请求直接失败——而这些节点并没有出错，只是正在被同一个客户端正常使用。prefix 资源下多个文件共用 `0-` 这一个 range 字符串作为 key，A 文件的签发历史会作用到 B 文件的调度上，跨文件互相污染。

## Decision

调度惩罚由 `FlowPenalties` 表达，分 `banned` 与 `demoted` 两档。`banned` 节点照常入池但最低优先：poolize 先把候选池分成非 banned 与 banned 两段，第一阶段只在非 banned 节点中按层选点，行为与硬剔除完全一致（确定性避开失败节点）；仅当非 banned 节点全部不可用时才进入第二阶段兜底，按层回退尝试 banned 节点。兜底仍须通过健康检查与传输能力校验，`first_range_unsatisfiable`（416）依旧不跨协议降级，重试总次数仍由 `MAX_CHUNK_DOWNLOADS` 封顶。`demoted` 仍然进池，权重减半，下限 1。

兜底是本设计后来修正的一处失误：最初 `banned` 在加池时直接跳过，单节点或小节点池拓扑下重试会把全部候选剔空，调度直接报 `NO_RES_AVAILABLE`——而这些节点往往并没有真坏，只是被同一会话的并发 chunk 占用或刚被换过一次。入池门禁（`server_passes_admission_gates`）因此只保留传输能力校验，不再丢弃 banned 节点。

分档依据是"这个节点是被换掉的，还是正在被使用的"。本次请求的 chunk 上签发过的节点全部进 `banned`——客户端就这个 chunk 又来要 URL，意味着上一个不好用。其它 chunk 上，除最近一次签发的节点外都进 `banned`（它们在那个 chunk 上已经被换掉了），最近一次签发的那个进 `demoted`（它正在服务，只是不该被再叠一份负载）。两个列表取交集时归入 `banned`，硬约束优先。

下载计数与惩罚状态的 key 由 `scoped_download_key(sub_path, range)` 生成，`sub_path` 非空时形如 `path:range`，否则退化为裸 range。prefix 资源下每个文件因此各有独立的计数与惩罚状态。

## Alternatives considered

**保持全部硬剔除。** 落选：正是并发多 chunk 场景清空候选池的原因。区分不了"节点失败"与"节点正在被同一客户端使用"这两件事。初版实现仍采用了"入池即剔除"的硬剔除形式，单节点拓扑下重试直接无资源可用，后修正为池内分段兜底。

**全部改为降权，不再硬剔除。** 落选：同一个 chunk 重试时仍有概率再选到刚失败的节点，客户端可能连续几次拿到同一个坏 URL。重试路径需要的是确定性排除，不是降低概率。

**给惩罚状态加 TTL 让其自然过期。** 落选：并发 chunk 是同时占用而非先后占用，缩短过期时间不改变同时刻被清空的事实；同时引入了与客户端下载速度耦合的时间参数。

**惩罚状态按 sid 全局共享一份。** 落选：这正是 prefix 资源跨文件污染的成因之一。

**降权改为按失败次数递进。** 落选：`demoted` 描述的是"正在被使用"，不是"失败了 n 次"，递进没有对应的语义。递进惩罚需要区分失败原因，属于另一件事。

## Verification

| 判据 | 结果 |
|---|---|
| 同一 chunk 重试时签过的节点被硬剔除 | PASS：`test_penalty_servers_retrieval` |
| 跨文件复用同一 sid 时惩罚状态互不影响 | PASS：`test_scoped_download_key_isolates_files`、`test_sticky_penalty_servers_across_files`、`test_free_prefix_sid_reused_across_files` |
| `demoted` 节点仍在池中且权重减半、下限 1 | PASS：`test_apply_penalty_to_pool` |
| 带 `skip_penalty` 的记录不参与惩罚计算 | PASS：`skip_penalty_records_are_ignored` |
| 复用 sid 重新验证后惩罚记录保留 | PASS：`test_reuse_sid_reauths_and_keeps_penalty_records` |
| 能力门控与惩罚叠加时行为正确 | PASS：`test_h3_only_with_penalty_interaction` |
| 单节点被 banned 后兜底回退成功而非 NO_RES_AVAILABLE | PASS：`banned_single_server_falls_back_instead_of_emptying_pool` |
| 全部节点被 banned 后兜底回退成功 | PASS：`banned_all_servers_fall_back` |
| 存在健康非 banned 节点时仍确定性避开 banned | PASS：`non_banned_candidate_is_preferred_over_banned` |
| 兜底阶段仍拒绝传输能力不满足的节点 | PASS：`fallback_still_rejects_transport_incompatible_servers` |
| 全量测试无新增失败 | PASS：253 passed / 6 failed，6 个失败全部位于 `src/commands/analyze/stats/`，该目录本次未改动 |

## Consequences

重试路径严格避开失败节点，而正常并发下载不会把池子用空：被同一客户端复用的节点只是权重减半，负载摊到其余节点上。prefix 资源的每个文件有独立的惩罚与计数状态，一个文件的重试不影响其它文件的选点。

代价与已知缺口有两处。`demoted` 的减半是固定策略，与该节点当前实际负载无关，因此它调节的是"同一客户端内部的分摊"，不是全局负载均衡。惩罚判定依赖会话里 `CdnRecord` 的顺序，而 Redis 上这批记录的读改写不是原子操作，高并发下可能丢记录，进而漏掉一次惩罚；该缺口尚未修复。
