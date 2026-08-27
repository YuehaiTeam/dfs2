# 未定义节点引用的校验与摘除

Status: implemented

## Problem

flow 里 `use` 下的 `server <名字>` 引用不受任何检查。名字没有在 `servers` 中定义时，`execute_flow_item` 取配置的那句 `if let Some(server_config) = config.servers.get(id)` 整个落空，能力门被跳过，而紧接着的 `pool.push` 照样执行——这个不存在的名字进了节点池。

它不会污染流量配比。抽中它之后 `is_server_healthy` 因为查不到实现和配置直接判为不健康，条目被就地剔除，再在剩余节点里重抽；重抽是在剩余权重上重新归一化的，最终分布与一开始就不含它等价。

代价落在诊断信号上。层归属是在 `pool.push` 前一行记录的，死引用会把自己所在的层一并带进选点时的层列表。于是某一层若只写了死引用，那层必然选不出节点，日志上出现的是"该层无可用节点，降级"——这与"这层节点真的全挂了"在日志上完全无法区分，而后者是需要立刻处理的事件。同理，一整个资源的 flow 全是死引用时报出的是 `NO_RES_AVAILABLE`，读起来像是节点集体故障。分层机制把这个问题放大了：分层的价值正在于降级 warn 是个可信的信号，见[调度流分层选点](2026-08-27-flow-tiering.md)。

而没有任何一处会把"这个名字不存在"说出来。配置校验查了 `resource.server` 与 `resource.tries` 两处的节点引用，唯独 flow 里的没查。

## Decision

`AppConfig::load()` 在 `server_impl` 建好、`servers` 定型之后扫描各资源的 `flow`，把 `FlowUse::Server` 指向的未定义名字从 `use` 列表中摘除，并把摘掉的 `(资源 id, 节点 id)` 排序去重后存入 `pruned_flow_server_refs`。热重载走 `reload_from_file()`，其内部就是 `AppConfig::load()`，因此同一条路径覆盖首次加载与热重载。

**判定只发生一次，校验读取结果而不重新扫描。** 校验拿到的是已经摘除过的配置，重新扫描 `flow` 必然一无所获，所以判定结果必须由配置对象自己携带。`pruned_flow_server_refs` 因此和 `plugin_code`、`server_impl` 一样标注 `#[serde(default, skip)]`，是加载期构造的字段。这比让两处共用一个判定函数更强：校验与运行时不可能对同一份配置给出不同结论。

**校验只报 warning，不动 `config_valid`。** 配置经校验通过后才热重载，报 error 会让存量配置立刻无法部署，而清理死引用需要先逐个确认每处引用的本意。`ValidationReport::is_valid` 只看六个分量布尔、不看 `warnings`，因此死引用出现在报告的警告区块而退出码不变。这与"节点连接失败只记 warning 不算错误"是同一处既有的取舍。warning 文案点明"该引用已被忽略"——摘除已经发生，读报告的人不应据此以为线上正在受影响。

**摘引用，不删整项。** `FlowItem` 的 `use` 列表里除了 `server` 还可能有 `poolize`、`clear`、`break`、`continue`，删掉整项会改变控制流；引用被摘空的项保留下来，其余命令照原样执行。

摘除本身不打日志。报告职责归 `dfs2 validate`，而配置加载在每次热重载时都会发生，在那里打 warn 只会重复同一条已经被报告过的事实。

插件在运行时返回未定义 `server_id` 的同类问题不在本篇范围内——那是运行时产物，静态检查覆盖不到，见[插件返回条目的能力门禁](2026-08-27-plugin-url-capability-gate.md)。

## Alternatives considered

**报 error 阻断部署。** 落选：存量配置里已有的死引用会让配置立刻无法部署，而每处引用是笔误、是已下线节点的残留、还是为即将上线的节点留的占位，需要逐个确认。等清理完再考虑收紧。

**只报 warning，不在加载时摘除。** 落选：假降级信号仍然存在，本篇的主要动机没有解决。校验只在部署链路上跑，而误导性的降级 warn 出现在每一次选点里。

**只在加载时摘除，不报 warning。** 落选：死引用被静默吃掉，配置里的错字可以永久存在而无人知晓。

**在 flow 执行时逐请求摘除。** 落选：每请求路径上不能打 warn，只能降级成 debug 或计数指标，发现能力反而更弱。配置在两次加载之间不变，加载时摘一次就够。

**校验侧自行扫描 flow，与加载侧共用判定函数。** 落选：校验看到的配置已经摘除过，扫描结果恒为空。判定必须在摘除之前完成并把结果带出来。

**把整个 `FlowItem` 删掉而不只摘引用。** 落选：见上，项里可能还有控制命令。

## Verification

| 判据 | 结果 |
|---|---|
| 校验报出 flow 中指向未定义节点的引用，指明资源与节点名并说明已被忽略 | PASS：`pruned_flow_refs_are_reported_without_failing_validation` |
| 该 warning 不影响 `is_valid()`，存在死引用时退出码仍为 0 | PASS：同一测试断言 `config_valid` 与 `is_valid()` 均为真 |
| 加载完成后的配置中不再含有这些引用 | PASS：`undefined_server_refs_are_pruned_and_returned` |
| 引用被摘空但仍带控制命令的项保留，控制流一致 | PASS：`pruning_keeps_the_item_and_its_control_commands` 断言项仍在且 `poolize`、`break` 原样保留 |
| 同一个未定义名字多处出现时报告去重、摘除仍覆盖每一处 | PASS：`one_undefined_name_used_repeatedly_is_reported_once_per_resource` |
| 配置中全部引用都有定义时行为不变 | PASS：`a_fully_defined_flow_is_left_untouched` 与 `a_config_without_dead_refs_reports_no_such_warning` |
| 热重载后同样不含这些引用 | PASS：`reload_from_file()` 内部即 `AppConfig::load()`，不存在独立的加载路径可供单独测试 |
| 只写了死引用的层不再产生该层的降级 warn | 未单独覆盖：这是"引用不再进池、因而不记层归属"的直接推论，进池行为本身已被上述摘除测试覆盖 |

## Consequences

死引用不阻断部署，因此可以长期留存。这项检查的实际清理效果取决于有人去看校验报告——它换来的是存量配置不会因为历史遗留的引用而无法部署。

摘除在加载时静默完成，校验之外的加载路径不产生任何提示。绕过校验直接触发热重载时，死引用被摘掉而没有任何记录。有权限这样操作的人同样有权限停服务，所以这里不设额外防护。

`pruned_flow_server_refs` 是个容易被误用的字段：后续若要在校验中新增同类的 flow 静态检查，必须同样采用"加载时判定、把结果带出来"的形式，直接扫描 `flow` 会因为摘除已经发生而得到空结果。字段的 rustdoc 里写明了这一点。

某处引用若本意是为尚未上线的节点占位，摘除后该项可能只剩控制命令，选点结果随之变化。不过这与该引用当前的实际效果一致——它本来也选不出节点。

`FlowUse` 增加了 `PartialEq` 与 `Eq` 派生，使测试能直接比较摘除前后的 `use` 列表。
