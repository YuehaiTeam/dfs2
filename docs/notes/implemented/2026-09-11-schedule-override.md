# 强制调度 override

Status: implemented

## Problem

排障与定向验证需要把某个客户端在一段时间内送到指定节点。现有调度只认资源上的 flow、会话惩罚和传输能力头，没有按客户端身份钉住节点的路径。改 YAML 或重载配置会作用于所有人；`X-DFS-Override` 只改 H3 / WebRTC / WebTransport 等能力探测，不选点。

没有这条路径时，管理员无法在不扰动全局规则的前提下验证「这个 IP 或这个 sid 走这个节点」。链接生成（脚本或独立服务）不在本篇范围；本篇只规定 DFS2 认领与调度如何消费一张已写入存储的票。

## Decision

可复用的 override 票加认领后的绑定。票是能力：谁出示都能把自己的主体绑到票上的节点，不独占、不核销。聊天软件预览或反馈帖上的他人打开，只会多写一把属于打开者的绑定；真实用户再认领仍然生效。删除票阻止新认领；已写下的绑定靠自身 TTL 消失。

过期只认 key 的 TTL。票必须带 TTL；Redis `TTL` 为 -1（或文件后端等价的「未设过期」）时拒绝认领。认领时读取票的剩余秒数，原样设到绑定 key。查找时 key 还在即有效。载荷里不放 `expires_at`。DFS2 不写票，只读票、写绑定。

### 票

管理员（或写票服务）写入，DFS2 只读。值为 CSV，便于 `SET` 手打。`resid` 只由管理员写在票上，认领 URL 与 session 都不提供。节点 id 与资源 id 不含逗号；字段 trim。第二段省略表示所有资源。

```text
SET {REDIS_PREFIX}:override:{uuid} node EX 300
SET {REDIS_PREFIX}:override:{uuid} node,resid EX 300
```

key 走现有 `redis_key`：namespace `override`，key 为 uuid。`REDIS_PREFIX` 为空时是 `override:{uuid}`。文件后端与 `MockDataStore` 用同一逻辑名，TTL 由已有的 `StoredValue` 模拟。

### 认领

`GET /override?req={uuid}&sid={optional}`。用现有客户端 IP 提取。读票，校验节点仍在当前配置中，按票是否带 `resid` 决定绑定 key 的后缀。不校验 session 是否已存在。成功返回 `ApiResponse`，带目标节点、剩余 TTL、以及写了 IP 绑定还是 sid 绑定。

GET 有写副作用。预览请求会绑定爬虫 IP；这不是抢占，只是多余的短 TTL 键。

### 绑定

仅 DFS2 在认领时写，不是手写契约。匹配维度全部在 key 上：谁（sid / ip）以及票上的 `resid`。不同 sid、同一 sid 下不同 `resid`，各是一把 key，并存。再次认领只覆盖完全相同的那一把。

```text
{prefix}:override:bind:sid:{sid}
{prefix}:override:bind:sid:{sid}:{resid}
{prefix}:override:bind:ip:{ip}
{prefix}:override:bind:ip:{ip}:{resid}
```

JSON 只留机器字段，不含 `sid`、`ip`、`resource_id`：

```json
{
  "target_node": "node_name",
  "ticket": "uuid"
}
```

uuid 不以 `bind:` 开头，与票的 key 不撞。

### 调度

`FlowService::execute_flow` 在走 YAML 之前按 key 查找。`FlowContext.internal` 不查。命中则跳过 flow 项与 `banned` / `demoted`，直接走现有健康检查、URL 签发与传输改写。`FlowResult.selected_tier` 为 `None`。节点不在配置中或不健康时返回已有错误，不回落普通 flow。

查找顺序：

1. `bind:sid:{sid}:{resid}`（本次 `FlowTarget.resource_id`）
2. `bind:sid:{sid}`
3. `bind:ip:{ip}:{resid}`
4. `bind:ip:{ip}`

票为 `node,resid` 时认领只写带后缀的 key，其它资源不受影响。

本篇不包含：链接生成、写票服务、短链、HMAC 签名 query、单次认领、按 UA 过滤爬虫、改 YAML flow 语法、改 `X-DFS-Override`。

## Alternatives considered

**HMAC 签名 query（`expires` / `target_node` / `sign`）。** 落选：参数出现在 URL 里，短链不好做；认领之后仍要落绑定，省掉的只是点开之前写存储。生产已有 Redis，手打 `SET` 即可发票。

**单次认领。** 落选：聊天软件预览、模拟浏览器打开页面、反馈帖抢领，都会让真实用户无法再绑。票按能力而不是按核销。

**session `extras` 加 YAML 规则。** 落选：每个要钉的节点都要在资源 flow 里预埋规则，且绑定期限、按 IP 认领都不在 extras 模型里。

**用惩罚把其它节点 `banned`。** 落选：必须知道全集，插件字面 URL 对不上，且惩罚本义是重试避让，不是强制选点。

**票与绑定都用 JSON，或都用 CSV。** 落选：票要给人手打，CSV 一行即可；绑定由 DFS2 写，与 session / challenge 一样用 JSON。绑定不是手写契约。

**载荷里再写 `expires_at`。** 落选：与 key 的 TTL 是两套时钟，认领本来就要用剩余 TTL 去设绑定。

**`resid` 只写在绑定 JSON 里、查找后再过滤。** 落选：匹配维度不在 key 上，同一 sid 下不同资源无法并存，查找也无法只靠 GET。

**管理员直写绑定 key。** 落选：已知 sid 走认领 `sid=`，避免两套写入约定。

## Verification

条件：本地 `cargo test override` 与 `cargo test services::flow_service`，`test` profile，未连 Redis。

| 判据 | 结果 |
|---|---|
| 有效票认领后按 IP 写绑定；带 `sid=` 时另写 sid 绑定 | PASS：`claim_writes_ip_and_optional_sid_bindings`、`claim_route_binds_request_ip` |
| 票不存在、已过期、无 TTL、或节点不在配置中时认领失败 | PASS：`claim_rejects_missing_expired_untimed_and_unknown_node` |
| 第二人从另一 IP 或另一 sid 认领同一张票，各自得到绑定 | PASS：`second_subject_claim_does_not_drop_the_first` |
| `execute_flow` 跳过 YAML 与惩罚，签发目标节点 | PASS：`schedule_override_skips_yaml_and_penalties` |
| 不同 sid 可同时指向不同节点 | PASS：`distinct_sids_keep_distinct_nodes` |
| 同一 sid 下不同 `resid` 是不同 key | PASS：`resid_scoped_ticket_writes_suffixed_keys_only`、`schedule_override_resid_specific_key_does_not_apply_to_other_resources` |
| 查找按 sid+resid → sid → ip+resid → ip | PASS：`sid_lookup_wins_over_conflicting_ip` |
| `FlowContext.internal` 不命中绑定 | PASS：`schedule_override_ignores_internal_fetches` |
| 目标不健康时失败且不改选其它节点 | PASS：`schedule_override_does_not_fallback_when_target_is_unhealthy` |
| 文件后端与 Mock 同等读写、测试不依赖 Redis | PASS：上述测试走 `MockDataStore`；`FileDataStore` / `RedisDataStore` 实现同一 trait 方法 |

## Consequences

共享出口或 CGNAT 下，IP 绑定会作用到同一出口后的其他人，直到 TTL 结束。sid 绑定更窄，但要用户或前端带上 `sid`。

票的 uuid 等同能力口令。泄露后任何人都能把自己绑到该节点；缓解是短 TTL 和删票。

强制选点在节点不健康时硬失败。排障期这是意图；节点恰好故障时，被绑客户端没有自动退路。

节点 id 或资源 id 若含逗号，CSV 会切错字段。两者在本项目里都是配置标识符，约定不含逗号。

每次客户端调度在走 YAML 之前最多多 4 次存储 GET。绑定未命中时这条路径是空读。
