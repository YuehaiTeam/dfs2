# 内部取件的调度上下文

Status: implemented

## Problem

服务端自己发起的取件（解析 KachinaInstaller 元数据）借用了给客户端准备的那套调度上下文，把不知道的字段一律填空：`client_ip: None`、`capabilities: Default::default()`。这带来两个错误。

**能力面被填成"什么都不支持"。** `ClientCapabilities::default()` 全为 false，而选点前有一道能力门：`h3_only`、`dfs_sftp`、`ssh_only`、`dfs_webtransport` 类型的节点在客户端不具备对应能力时被剔出池子。内部取件因此永远选不到这些节点——但本进程的 fetch 客户端挂着 H3、SSH、SFTP 三个 middleware，这三类节点它明明能用。结果是内部取件的可用节点集被无谓地缩到只剩普通 HTTP 节点，而这些节点未必是离服务端最近的。

**"没有客户端"与"没取到客户端 IP"混为一谈。** 两者在配置上应当分开：前者要按服务端自身的网络位置选点，后者是客户端信息缺失，通常仍应按面向客户端的规则兜底。仅凭 `client_ip.is_none()` 无法区分，而调度规则里也没有任何写法能够表达"这层不服务内部取件"。这在有了 `not` 之后更要紧：`not geoip <地区>` 对内部取件恒为真（见[调度条件的取反](2026-08-27-flow-not-condition.md)），依赖 `not` 的层会不声不响地把内部取件也收进来。

## Decision

**`ClientCapabilities::internal_fetcher()` 声明本进程 fetch 客户端的能力面**：h3、ssh、sftp 为真，wt、wrtc 为假。取值依据是 `FETCH_CLIENT` 实际挂载的 middleware 栈；WebTransport 与 WebRTC 是浏览器侧协议，本进程作为客户端不具备。它与 `Default` 的区别是语义上的：`Default` 表示"未从请求中识别出任何能力"，这个构造表示"已知支持这些"。

**`FlowContext.internal: bool` 单独标记发起方**，而不从 `client_ip` 推断。`FlowContext::internal()` 一次性组装内部取件的上下文，内部调用方不再手工拼字段——手工拼是上一处错误的来源。该字段随 `FlowContext` 一并序列化进插件上下文，插件也能据此分支。上下文中的 `client_ip` 取配置的调度器出口 IP，让地理条件按服务端自身位置对内部取件求值，见[内部取件携带调度器出口 IP](2026-08-28-internal-egress-ip.md)。

**新增条件 `internal {true|false}`**，使调度规则能显式区分两类取件。它与 `not` 组合可写 `not internal true`。

## Alternatives considered

**内部取件的能力面填全 true。** 落选：`dfs_webtransport` 与 `dfs_rtc` 节点会被选中，而本进程无法作为这两种协议的客户端发起请求，取件必然失败，且失败发生在选点之后，表现为一次无谓的重试。能力声明应当反映实际支持面。

**从 `client_ip.is_none()` 推断内部取件。** 落选：客户端 IP 也会因反向代理未透传等原因缺失，两种情况该走的调度并不相同。用同一个信号表达两件事，正是当前这处缺陷的成因。

**给内部取件单独一份 flow 配置。** 落选（暂）：这确实更彻底，但会要求每个资源多维护一份配置，而多数资源的内部取件与客户端取件本可共用同一批节点。先给出条件，让配置按需分流；若之后证明分流规则普遍复杂，再考虑独立配置。

**在能力门处特判 `internal`，绕过门禁。** 落选：绕过意味着 `dfs_webtransport` 节点也会进池，等于上面"全 true"方案的隐式版本，且把发起方判断散进门禁逻辑，比声明能力面更难读。

## Verification

| 判据 | 结果 |
|---|---|
| 内部取件可选中 `h3_only` 节点 | PASS：`internal_fetch_can_use_h3_only_servers` |
| 内部取件不声明 WebTransport 能力 | PASS：同一测试断言 `capabilities.wt` 为假 |
| `internal` 条件区分发起方而非 IP 有无 | PASS：`internal_condition_distinguishes_the_originator` 断言"无 IP 的客户端请求"仍判为非内部 |
| `internal` 可解析、可与 `not` 组合 | PASS：`internal_condition_round_trips` |
| `internal` 参数非法或缺失为错误 | PASS：`internal maybe` 被拒；`internal` 收进 `truncated_conditions_are_errors_not_panics` |
| 内部取件实际选到 H3 节点后能取成功 | 未实测：需线上观察一次 KachinaInstaller 解析落在 H3 节点上的取件结果 |

## Consequences

内部取件的可用节点集扩大到包含 H3、SSH、SFTP 类节点。这多半是改善——服务端与这些节点之间的链路通常比与普通 CDN 之间更短——但它也让内部取件第一次真正走上 H3 路径，该路径的失败模式（证书校验、QUIC 握手）此前只在客户端侧和普查探测里出现过。上面留了一条未实测判据正是为此。

调度规则从此能区分发起方。代价是这成了写规则时要多想一层的事：任何依赖客户端信息的层，都需要考虑内部取件落进来是否可接受。`not` 让这件事更容易被忽略，因为它把"信息缺失"翻成了"匹配"。

`FlowContext` 多了一个字段，所有构造点都必须显式给出 `internal`。这是刻意的：默认值会让新的内部调用方重复犯同一个错误。
