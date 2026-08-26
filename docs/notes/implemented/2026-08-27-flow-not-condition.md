# 调度条件的取反

Status: implemented

## Problem

调度规则里没有取反。要表达"非俄罗斯用户"只能靠两种绕法：把 `mode: and` 的层拆成把补集逐个列出（`geoip` 关键词的补集列不完），或者靠层的先后顺序——先让目标层匹配并 `break`，让后面的层承接剩余流量。后者把"取反"编码进了层序，读配置时看不出某层实际服务的是哪部分流量，插入一层就会静默改变前后各层的覆盖面。

`extras` 类条件尤其吃紧：它判定的是某个标志存在，而"标志不存在"没有写法。

顺带一个健壮性问题：条件解析按空格切分后直接索引 `parts[1]`、`parts[2]`，`cnip`、`size >` 这类写漏参数的条件会 panic。它发生在配置加载阶段，表现为进程带着 panic 退出，看不到"哪条规则写错了"。

## Decision

新增 `FlowCond::Not(Box<FlowCond>)`，写法 `not {cond}`，内层是任意条件，包括 `not` 自身。

**取反的对象是内层的求值结果，不是"内层为真的补集"。** 多数条件在信息缺失时返回 false：没有客户端 IP 时 `cnip true` 与 `cnip false` 同为 false，`not` 因此把两者都翻成 true。这不是缺陷而是定义——判定不出来时不匹配，取反后就匹配。落在配置上的后果是：调度器自身发起的取件没有客户端 IP，`not geoip ru` 这类条件对它恒为真。依赖 `not` 的层若不希望承接内部取件，需要另外把内部取件排除掉。求值出错（`Err`）不参与取反，照原样上抛。

解析与序列化重构为 `FromStr` 与 `Display`，`Deserialize`/`Serialize` 只做委托。`not` 因此能直接递归复用整套条件语法，不需要为它单独维护一份解析。同时补齐参数缺失的检查：写漏参数的条件现在报"condition requires format: ..."，不再 panic。

## Alternatives considered

**给每个条件各加一个取反形式**（如 `cnip` 已有的 `true`/`false` 参数推广到其它条件）。落选：`geoip`、`extras`、`cidr` 各自都要加参数，语法面积随条件数增长，且组合条件（`size`、`bw_daily`）加在哪一侧含义不清。

**加 `mode: nand` / `mode: nor` 之类的层级取反。** 落选：粒度是整层，无法表达"这层要 A 且非 B"，而这正是常见形态。层级取反与条件取反可以共存，但后者更基本。

**用插件表达取反。** 落选：插件的入口是节点池而不是条件，它改的是选点结果而非匹配判定；把一个布尔取反放进 JavaScript 运行时，代价和可读性都不合适。

**让 `not` 在内层信息缺失时也返回 false**（即"三值逻辑"，未知取反仍为未知）。落选：这会让 `cond` 与 `not cond` 同时为假，读规则的人无法再假定两者互补；而真正需要区分"未知"的场景应当显式判定那个信息是否存在，而不是靠取反的语义变体。

## Verification

| 判据 | 结果 |
|---|---|
| `not {cond}` 可解析，内层为任意条件 | PASS：`not_wraps_any_condition_and_round_trips` 覆盖单参数、多词参数（`not size > 100MB`）与嵌套（`not not geoip telecom`） |
| 多词条件的参数不被 `not` 的切分吃掉 | PASS：同一测试断言 `not size > 100MB` 的内层是 `Size(Gt, 100MB)` |
| 求值为内层结果取反 | PASS：`not_inverts_the_evaluated_result_including_missing_information` |
| 信息缺失时的取反语义被钉住 | PASS：同一测试断言无客户端 IP 时 `cnip true` 与 `cnip false` 同为 false，而两者取反同为 true |
| 嵌套取反回到原值 | PASS：同一测试 |
| `not` 缺内层、内层非法均为错误 | PASS：`not`、`not bogus_cond` 都返回错误 |
| 写漏参数的条件不再 panic | PASS：`truncated_conditions_are_errors_not_panics` 覆盖 7 种截断写法 |

## Consequences

条件层面从此可以直接写出补集，不必再借层序表达。层的覆盖面变成可以逐层读懂的东西，这是后续做分层选点（见[调度流分层与内部取件](../proposed/2026-08-27-flow-tiering.md)）的前提：层若不自明，分层只是把顺序依赖换个地方藏。

`not` 与"信息缺失"的交互是这次引入的新坑，需要在写配置时记住：对调度器自身发起的取件，一切依赖客户端信息的条件都为假，取反后都为真。这个坑的根源是各条件把"判定不出来"和"判定为否"合并成了同一个返回值，取反只是让它显形。

解析重构顺带发现一处无害缺陷：`Display` 对 `size`、`bw_daily` 的输出经过 `Size` 的单位归一化（`100MB` 变成 `95.4 MiB`），而该输出再按空格切分时会丢掉单位词，解析回来是 95.4 字节。它目前不可达——配置从不回写，`Serialize` 只被自身的测试调用——所以本次未动。若将来需要导出配置，`Size` 的往返必须先修。
