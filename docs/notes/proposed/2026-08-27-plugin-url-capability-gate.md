# 插件返回条目的能力门禁

Status: proposed

## Problem

flow 插件可以整体替换节点池，它返回的条目直接进池参与加权随机，选中后原样成为发给客户端的 URL。

客户端的传输能力逐请求从请求头识别，`ClientCapabilities` 的五个字段分别对应 HTTP/3、WebTransport、WebRTC、SSH 隧道与 SFTP。配置里写死的节点在 `FlowUse::Server` 分支逐项过一遍门禁：客户端不具备该节点要求的能力时跳过，不入池。插件返回的条目没有等效约束。

`FlowUse::Plugin` 分支里确实有一段针对插件条目的门禁，但它以 `plugin_server_mapping` 里记录的 `server_id` 为前提——只有插件在 metadata 中声明了 `server_id`，才能查到 `ServerConfig` 去判断 `h3_only`、`ssh_only` 这些要求。而 `PluginMetadata.server_id` 是 `Option`，旧格式的返回值里连 metadata 这一层都没有；插件不声明归属时，那段的模式匹配整个落空，条目无条件保留。能力体系晚于插件体系引入，这段门禁因此只覆盖了声明了归属的那一半条目，另一半不受任何检查。

后果是不具备某传输能力的客户端可能拿到该传输的 URL。失败推迟到客户端实际下载时才暴露，而那时已经错过了在池内换一个节点的机会。

## Proposal

判据取 URL 自身的 scheme。`rewrite_url` 与 `DfsSftpSigner` 产出的五个自定义 scheme 与能力位一一对应，插件返回的 URL 带着 `http3://` 前缀就意味着这一项要求 HTTP/3，不需要查任何表也不需要插件配合：

| URL 前缀 | 要求的能力 |
|---|---|
| `http3://` | `h3` |
| `h3wt://` | `wt` |
| `wrtc://` | `wrtc` |
| `ssh+http://` | `ssh` |
| `sftp://` | `sftp` |

匹配到其中之一就查对应能力位，为假则丢弃该条目。`http://`、`https://` 以及表外的任何 scheme 一律放行：插件返回不属于任何已配置节点的第三方 URL 是合法用法，拦下来就成了误杀。

**判在条目进池之前，不在选点之后。** 门禁若放在把 URL 交给客户端前兜底，选中一个不可用条目时只能报错；在进池前丢弃则池里剩下的都是客户端能用的，加权随机的分母也才是对的。增强格式与旧格式两条解析分支都要逐条判过再 push，否则不带 metadata 的返回值绕过门禁。

**按 `server_id` 的门禁保留，与按 scheme 的门禁分工互补。** 插件用内置签名函数生成的 URL 是 `http(s)://`，没经过 `rewrite_url`，scheme 上看不出传输要求；此时若条目声明了 `server_id` 且该节点已定义，仍按 `ServerConfig` 判定，这是比 scheme 更精确的信息。两者都不适用时放行。现有那段以 `server_id` 为前提的判定逻辑与 `FlowUse::Server` 分支的判定逻辑完全重复，抽成一个以 `ServerConfig` 和 `ClientCapabilities` 为输入的函数供两处共用。

**声明了 `server_id` 但该节点未在 `servers` 中定义的条目一并丢弃。** 它无法解析成任何真实节点，留在池里只会占着权重份额等健康检查剔除。配置里同类的死引用由[未定义节点引用的校验与摘除](../implemented/2026-08-27-undefined-flow-server-refs.md)在加载时静态处理，而插件的返回值是运行时产物，静态检查覆盖不到，只能在这里挡。

两个函数都放进 `capabilities.rs`：scheme 门禁判的正是 `rewrite_url` 产出的那五个 scheme，新增传输类型时必然同时触及两者，相邻放置才不至于只改一边。

门禁在条目进池前生效，因此被丢弃的条目也不会拿到层归属——层是在压入池子时记录的，见[调度流分层选点](../implemented/2026-08-27-flow-tiering.md)。缓存回填等调度器自身发起的取回同样受门禁约束，判据是服务器自己的能力面而非客户端的，见[内部取件的调度上下文](../implemented/2026-08-27-internal-flow-context.md)。

## Alternatives considered

**拿 URL 反查节点：遍历 `servers` 按 `ServerConfig.url` 前缀匹配，命中就按 `ServerConfig` 判定。** 落选：匹配不上时只能放行，于是 scheme 差异、base url 尾斜杠、显式端口与默认端口、host 大小写这些归一化疏漏都会让门禁静默失效，而"匹配不上"与"这个 URL 本来就是外部的"在代码里无法区分。scheme 本身已经是明确声明，用前缀匹配去猜归属是把确定的信息换成了启发式的。

**扩展 `PluginMetadata`，让插件自报传输要求。** 落选：要插件配合才生效，且与 scheme 携带的信息重复。插件声明与 URL 实际 scheme 不一致时还多出一种需要裁决的矛盾。

**只等插件开始声明 `server_id`，不动现有门禁。** 落选：门禁是否生效取决于插件是否自愿声明归属，成了可选项而不是强制约束。

**在 URL 交给客户端之前统一兜一道，不在插件返回处判。** 落选：见上，那时只能报错而不能换节点。作为额外的防御层可以叠加，但替代不了进池前的丢弃。

## Acceptance criteria

- 五个 scheme 逐个验证：客户端不具备对应能力时条目被丢弃，具备时保留。
- `http://`、`https://` 与表外 scheme 放行。
- 旧格式返回值（无 metadata 层）同样受 scheme 门禁约束。
- 声明了 `server_id` 且该节点已定义时，按 `ServerConfig` 判定；`h3_only` 节点对不支持 h3 的客户端被丢弃，即使 URL 是 `https://`。
- 声明了 `server_id` 但该节点未定义时条目被丢弃。
- 门禁把池子清空时报 `NO_RES_AVAILABLE`，不把任何条目当 URL 返回给客户端。
- `FlowUse::Server` 分支与插件条目走同一个 `ServerConfig` 判定函数，两处行为一致。

## Risks

scheme 字符串在 `rewrite_url` 与门禁两处各存一份。新增传输类型时只改一处会让门禁漏掉新 scheme，且漏掉的表现是放行而非报错。缓解手段只有同模块相邻放置，没有编译期约束。

表外 scheme 放行是 fail-open。插件返回一个客户端不支持、scheme 又不在表内的传输时，门禁无声通过，失败仍推迟到下载时。

丢弃是静默的。插件的返回值是运行时产物，静态校验查不到，若某插件稳定返回不可用条目，观察到的现象是池子比预期小或 `NO_RES_AVAILABLE`，而不是一条指向插件的错误。要把这种情况与"节点确实都不健康"区分开需要额外的计数指标，本次不做。

进池前丢弃会改变加权随机的分母。这是意图本身，但若有插件依赖"我返回的条目必定都在池中"的假设来控制流量配比，其配比会随客户端能力变化。
