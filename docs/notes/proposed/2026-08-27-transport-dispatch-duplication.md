# 传输方式分派的三份副本

Status: proposed

## Problem

"哪种节点要求哪种传输、哪种传输对应哪个 scheme、哪个 scheme 需要哪项客户端能力"这一张表，在 `modules/network/capabilities.rs` 里被写了三遍。

`server_transport_is_usable` 按 `ServerConfig` 分派到能力位：`ssh_only` 看 `ssh`，`dfs_sftp` 看 `sftp`，`h3_only` 且 `dfs_webtransport` 的双模看 `h3 || wt`，`h3_only` 看 `h3`，`dfs_rtc` 看 `wrtc`，`dfs_webtransport` 看 `wt`，其余放行。`rewrite_url` 按同一顺序、同一批判据分派到 scheme。`url_transport_is_usable` 则按 scheme 反查能力位。

三者的一致性靠注释维持——`server_transport_is_usable` 的 rustdoc 明写它的分派顺序镜像 `rewrite_url`，理由是门禁放行的节点才会被重写，两者对同一个 `ServerConfig` 必须得出同一种传输方式。这个约束是真的，见[插件返回条目的能力门禁](../implemented/2026-08-27-plugin-url-capability-gate.md)；问题在于它目前只由相邻放置和注释保证，编译器不参与。加一种节点类型要同时改三处，漏一处的表现是客户端拿到自己打不开的 scheme。

## Proposal

引入一个 `Transport` 枚举承载这张表，配三个映射：`ServerConfig -> Transport`、`Transport -> scheme 前缀`、`Transport -> 能力位`。`server_transport_is_usable`、`url_transport_is_usable`、`rewrite_url` 都从它派生，三处分派收敛为一处。

双模节点（`h3_only` 且 `dfs_webtransport`）的择优需要在映射里表达：`ServerConfig -> Transport` 吃一份 `ClientCapabilities`，按 h3 优先、wt 兜底给出确定的一种，门禁则以"映射得出的传输是否可用"为判据。

## Alternatives considered

**保持三处，靠注释与相邻放置。** 落选：这正是当前状态，它的代价在加节点类型时才显现，而那时三处已经不再相邻可见。

**让门禁直接调用 `rewrite_url`，看它是否产出可用 scheme。** 落选：重写要签好的 URL 与 `HealthInfo`，而门禁跑在选点之前，两样都还没有。

**只收敛门禁那两处，`rewrite_url` 不动。** 落选：漏改风险最大的恰恰是重写与门禁之间的那一对，收敛门禁内部解决不了它。

## Acceptance criteria

节点类型到传输方式的判据在 `capabilities.rs` 里只出现一处。`each_restricted_transport_admits_only_its_own_capability`、`a_dual_mode_server_needs_either_h3_or_wt`、`each_custom_scheme_admits_only_its_own_capability` 及 `rewrite_url` 的现有测试不变通过。

## Risks

`url_transport_is_usable` 对未知 scheme 放行（插件可以返回第三方 URL），这条不能被枚举化吃掉——`Transport` 的反查必须保留"认不出就放行"的出口，否则插件返回的普通 URL 会被误杀。
