# flow 配置文本形态的重复表

Status: proposed

## Problem

`FlowComp` 的六个比较符在 `modules/flow/config.rs` 里各写了四遍：`FromStr`、`Display`、`Deserialize`、`Serialize` 每一份都持有一张 `==`/`!=`/`>`/`>=`/`<`/`<=` 的对照表。同一个文件里 `FlowCond` 已经收敛成一份——`Deserialize` 调 `FromStr`，`Serialize` 调 `Display`，两份 impl 各只有三行。四份副本之间没有推导关系，加一个符号要改四处，漏改则解析与序列化对不上。

`FlowUse` 的两份副本已经对不上了。`Deserialize` 接受 `server example 2`（空格分隔权重），`Serialize` 产出 `server example[2]`（方括号）；把后者喂回前者会得到一个 id 为 `example[2]`、权重为 0 的条目，`plugin` 命令同理。`test_flow_use_deserialize` 只对 `break` 与 `continue` 断言了往返，而这两个不带参数的命令恰好是仅有的两个往返成立的变体。

序列化眼下没有生产消费者：配置只读入不写回，`AppConfig` 的 `IntoJs` 不导出 `flow`，仓库里序列化 `FlowUse` 的只有测试。但 `AppConfig` 派生了 `Serialize`，整条链上的 impl 不能简单删除。

## Proposal

`FlowComp` 按 `FlowCond` 的形状收敛：留下 `FromStr` 与 `Display` 两张表，`Deserialize` 与 `Serialize` 改为委托，删掉它们各自的 match。

`FlowUse` 补一个 `Display`，产出与 `Deserialize` 接受的完全相同的文本（`server <id> <weight>`、`plugin <id> <indirect>`），`Serialize` 改为委托。`test_flow_use_deserialize` 扩为对每个变体断言 serialize→deserialize 往返。

## Alternatives considered

**保留四份副本，只补往返测试。** 落选：测试能挡住漂移，但"改一处要改四处"的成本还在，而这正是 `FlowCond` 那一轮已经付过一次的成本。

**删掉 `Serialize` 而不是让它委托。** 落选：`AppConfig` 派生 `Serialize`，`ResourceConfig`、`FlowItem`、`FlowUse` 整条链都要跟着摘，动静远大于收益。

**保留方括号形态，改 `Deserialize` 去接受它。** 落选：线上配置写的是空格形态，改解析方向等于要求配置迁移。

## Acceptance criteria

`FlowComp` 的符号表在文件里只剩两处。每个 `FlowUse` 变体都有往返断言且通过。线上脱敏配置照常加载，flow 项的解析结果与改动前逐条相同。

## Risks

序列化文本形态从 `server a[2]` 变成 `server a 2`。当前没有生产消费者读它，风险落在未来有人依赖旧形态；旧形态本来就无法被自己解析，不构成契约。
