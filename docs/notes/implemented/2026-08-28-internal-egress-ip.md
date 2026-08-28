# 内部取件携带调度器出口 IP

Status: implemented

## Problem

内部取件的上下文没有网络位置：`FlowContext::internal()` 的 `client_ip` 为空，而 `cnip` 在无 IP 时两个方向都求值 false，`geoip`、`cidr`、`ipversion` 同样全部不命中（见[内部取件的调度上下文](2026-08-27-internal-flow-context.md)）。于是内部调度只能命中不带这些条件的 flow 项。

这在两个层面造成损失。资源的 flow 若所有项都带地理条件——脱敏镜像中确有这样的资源——内部回填永远选不出节点，该资源除版本文件外的可缓存路径实际上没有缓存，唯一的痕迹是每次未命中留下的一条 warn（回填机制见[缓存回填改走内部调度](2026-08-27-cache-fill-internal-scheduling.md)）。即便 flow 里有无条件项兜底，内部取件也享受不到既有的地理分层：调度器明明有自己的网络位置，却只能从"对谁都一样"的兜底节点取件，取件方向未必是对本机最近的。

调度器的网络位置是一个既存事实，缺的只是把它交给条件求值器的通道。

## Decision

配置有一个可选的 `internal` 段，由运维写入调度器的出口 IP，按惯例抹掉末段作脱敏（v4 抹末字节、v6 抹接口段），程序不做二次处理——geoip 库的粒度在 /24 及以上，抹零不影响国家、ISP 判定：

```yaml
internal:
  ip4: "203.0.113.0"
  ip6: "2001:db8:1234::"
```

`FlowContext::internal()` 接收 `InternalConfig::egress_ip()` 给出的 IP 填入 `client_ip`，优先 ip4，ip4 缺失时用 ip6。此后 `cnip`、`geoip`、`cidr` 对内部取件按调度器自身的位置求值，现有 flow 的地理分层自动对内部调度生效，缓存回填与 KachinaInstaller 两条内部路径同时受益。

**`ipversion` 按配置的出口栈判定，不经过单 IP 挑选。** 它问的是"调度器有没有这个栈的出口"：`ipversion 4` 看 `ip4` 是否配置，`ipversion 6` 看 `ip6`。双栈调度器因此两个版本的层都可达——若拿 `client_ip` 里为地理求值挑出的 v4 去判，v6-only 层会对双栈调度器也关掉，而从 v6 节点取缓存本是可行的。

其余语义不动：`internal` 标志仍为 true，`internal true/false` 条件继续按标志判定，与 IP 无关——要把某一层挡在内部取件之外（例如省 CDN 配额），在该层加 `internal false` 规则，机制已经存在。能力面仍取 `ClientCapabilities::internal_fetcher()`。

不配置该段时 `client_ip` 保持为空，行为与配置引入前完全一致；现有配置不需要任何改动。IP 由 serde 直接解析为 `Ipv4Addr`/`Ipv6Addr`，写错即配置加载失败，`dfs2 validate` 在部署前就能拦下。

## Alternatives considered

**逐资源添加 `internal true` 项。** 落选：要把 flow 里已有的地理知识为内部取件再抄一遍，且每个资源都得迁移，漏一个就静默失效——地理条件全覆盖的资源正是这样漏掉的。

**启动时自动探测出口 IP。** 落选：需要请求外部"我的 IP"服务，引入启动依赖与时序问题；多出口、NAT 场景下探测结果不可靠。配置是确定的，且随热重载生效。

**只加一个"内部视为国内/海外"的布尔配置。** 落选：表达力不够，丢掉 `cidr`、省份、ISP 级的匹配；而这些条件在 flow 里已经写好，给个 IP 就能全部复用。

**地理条件对 ip4 与 ip6 任一命中即算命中。** 暂缓：`FlowContext.client_ip` 是单个 `IpAddr`，双 IP 求值要改动条件求值器的形状。`ipversion` 已按配置栈单独判定；`cidr`、`cnip`、`geoip` 仍按单 IP 求值，v6-only 的 cidr 层（如教育网段）对内部取件的可达性留给后续评估。

## Verification

| 判据 | 结果 |
|---|---|
| 不配置 `internal` 段时内部上下文无 IP，地理条件不命中 | PASS：`a_config_without_an_internal_section_has_no_egress_ip`；`an_egress_ip_lets_geo_conditions_route_internal_fetches` 断言无 IP 时 `cnip false` 不命中 |
| 配置 ip4 后地理条件按该 IP 求值 | PASS：同测试断言带 IP 后 `cnip false` 与匹配的 `cidr` 均命中；`geoip` 关键词依赖 IPDB，测试环境无库，未单测 |
| 仅配 ip6 时内部上下文携带 ip6 | PASS：`egress_ip_prefers_ip4_and_falls_back_to_ip6` 与 `an_invalid_egress_ip_fails_at_config_parse` 的 v6-only 分支 |
| `internal` 条件只看标志、与 IP 无关 | PASS：`an_egress_ip_lets_geo_conditions_route_internal_fetches` 对带 IP 与不带 IP 两个上下文同断言 |
| 两条内部路径都携带配置的 IP | PASS（结构性）：缓存回填与 KachinaInstaller 的 `FlowContext::internal` 调用都传 `config.internal.egress_ip()` |
| 非法 IP 在配置加载期报错 | PASS：`an_invalid_egress_ip_fails_at_config_parse` |
| `ipversion` 按出口栈判定：双栈两个版本都命中，仅 v4 不命中 `ipversion 6`，未配置全不命中 | PASS：`internal_ipversion_follows_the_configured_egress_stacks` |

## Consequences

配置的 IP 与实际出口不符（迁移后忘改、多出口只写了一个）时，内部取件按错误位置调度。失效是软的——仍能选出节点，只是方向次优——且没有任何告警能发现它。

调度器出口多为机房 IP，`geoip 电信/移动/联通` 这类消费级 ISP 关键词大概率不命中，对应分层对内部取件呈中性。这是预期行为，不是缺陷，但排查"为什么内部没走某层"时容易忘记。

末段抹零在少数细于 /24 的分配上可能改变 ISP 判定，概率低，后果限于选向次优。

地理条件按单 IP 求值：配了 ip4 时，v6-only 的 `cidr` 层对内部取件不可达；`ipversion 6` 的层不受此限，按 `ip6` 是否配置判定。

线上要享受此能力需在配置写入 `internal` 段，迁移在部署侧进行；写入前内部调度行为与配置引入前一致。
