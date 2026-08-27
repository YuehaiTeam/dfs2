# continue 命令没有表达力

Status: proposed

## Problem

`FlowUse::Continue` 在 `execute_flow_item` 里的效果是跳出 `use` 的遍历且不置截断标志。遍历自然走完时的效果与此完全相同，因此 `use: [server a 5, continue, poolize]` 与 `use: [server a 5]` 对调度的作用逐字一致——配置是静态的，把 `continue` 之后的命令删掉就得到同样的结果。它不能表达任何"写不出来的"东西。

它曾经有表达力，来源是当时并存的 `FlowItem` 的 `break` 字段：那个字段在项末尾无条件截断，`continue` 用来覆盖它。字段随[调度流的截断命令](../implemented/2026-08-27-flow-control-commands.md)一并移除后，这份表达力没有了。

那篇 note 给 `continue` 记的用途是"一层可以先无条件补几个节点，再按条件决定是否放行到下一层"。这个用法要求同一项内的命令各带各的条件，而规则是按项求值的，`use` 里的所有命令共享同一个判定结果。该用途在当前语义下写不出来。

## Proposal

删除 `FlowUse::Continue` 及其解析、序列化与测试，`execute_flow_item` 的 match 少一臂。更新[调度流的截断命令](../implemented/2026-08-27-flow-control-commands.md)：Decision 里只留 `break`，Consequences 里那段关于 `continue` 与分层配合的说明随之删除。

## Alternatives considered

**留着，等将来支持按命令带条件。** 落选：没有产品主张要这个能力；真要做，形态是一条带条件的 `if`，而不是一个无条件的 `continue`——届时 `continue` 仍然是多余的。

**留着当作文档性的"本项到此为止"标记。** 落选：一个不改变行为的命令会让读配置的人以为它改变了行为，这与它当初要修的缺陷是同一类。

## Acceptance criteria

`continue` 不再是合法的 `use` 命令。线上脱敏配置照常加载——其 flow 里没有 `continue`，也没有 `break`。`break_and_continue_commands_stop_at_their_position` 收缩为只覆盖 `break`。

## Risks

某份未经检视的配置若写了 `continue`，加载会报 `Invalid FlowUse` 而失败，并连带热重载失败。已检视的线上配置没有这个词；这条风险的实际范围就是"是否存在别的在用配置"。
