# 调度流的截断命令

Status: implemented

## Problem

`FlowItem` 的 `break: bool` 字段写在规则判定之外：

```rust
if should_exec {
    for operation in &item.r#use { /* ... */ }
}
Ok(item.r#break)
```

规则不命中时，这一项的 `use` 一条都不执行，但 `break` 照样返回真，整条 flow 到此为止。一个本意是"符合这些条件的客户端走这批节点，且不必再往下看"的层，在客户端不符合条件时变成了"到此为止"——后续各层被静默跳过。表现出来是节点池比配置写的少，而配置读起来完全正常。

这个缺陷的隐蔽程度取决于层序：带 `break` 的层越靠前，被它吃掉的层越多。它也与调度的另一个方向冲突——想在某层之后停止，唯一的写法是给那层加字段，无法表达"这层执行到某个命令为止"，更没有"结束本层但继续往下"的写法。

## Decision

`break` 与 `continue` 成为 `use` 列表里的命令，与 `clear`、`poolize`、`server`、`plugin` 同权：

- `break`：停止执行后续 flow 项。本项 `use` 中它之后的命令也不执行——它在命令序列里就是这个意思。
- `continue`：结束本项的 `use`，继续执行后续 flow 项。

命令位于 `use` 内，因此天然只在规则命中时执行。旧的 `break: true` 字段保留，语义修正为等价于"在 `use` 末尾放一条 `break` 命令"，即同样只在规则命中时生效。

## Alternatives considered

**只修字段的条件性，不加命令。** 落选：修掉了错误，但"这层执行到某处为止"和"结束本层继续往下"仍然无法表达。而这两种写法在分层选点里是必需的——分层要求每层能明确交代它是否放行到下一层。

**移除字段，只保留命令，要求配置迁移。** 落选（暂）：字段修正后与命令语义一致，现有配置不必改动即可获得正确行为。强制迁移会在这次改动里额外引入一次配置变更风险，而收益只是少一种写法。字段可以在后续单独清理。

**让 `break` 命令只截断后续 flow 项，不影响本项剩余命令。** 落选：那样 `break` 的位置就不再有意义，等于字段的另一种写法。命令的价值正在于位置可控。

**用 `mode` 或新字段表达"独占层"（命中即终止）。** 落选：这把控制流塞进了条件语义，且无法表达 `continue`。

## Verification

| 判据 | 结果 |
|---|---|
| 规则不命中的项不截断 flow | PASS：`break_field_only_applies_when_the_rules_match`；把返回改回 `item.r#break` 时该断言失败 |
| 规则命中时 `break: true` 照常截断 | PASS：同一测试 |
| 未被截断的后续项仍贡献节点 | PASS：同一测试 |
| `break` 命令截断 flow，且本项后续命令不执行 | PASS：`break_and_continue_commands_stop_at_their_position` |
| `continue` 命令结束本项但不截断 flow | PASS：同一测试 |
| 规则不命中时控制命令不执行 | PASS：`control_commands_do_not_run_when_rules_miss` |
| `break` / `continue` 可解析并序列化回原文本 | PASS：`test_flow_use_deserialize` |

## Consequences

带 `break: true` 且有规则的层，行为会改变：此前它对所有请求都截断，现在只对命中规则的请求截断。对不命中的请求，后续各层重新参与选点，节点池因此变大——这是配置本来的意思。线上若有配置依赖了错误行为（靠一个不命中的 `break` 层来屏蔽后续层），那些层会重新生效。这个方向的风险无法从代码判断，需要在部署后核对各资源的实际选点分布。

`continue` 是新增能力，暂无配置使用。它的用处在分层选点（见[调度流分层与内部取件](../proposed/2026-08-27-flow-tiering.md)）里：一层可以先无条件补几个节点，再按条件决定是否放行到下一层。

字段与命令两种写法并存。它们语义等价，但字段只能表达"末尾 break"。后续若清理，应当先把配置迁到命令写法。
