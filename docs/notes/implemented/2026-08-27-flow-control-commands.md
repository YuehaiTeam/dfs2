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

命令位于 `use` 内，因此只在规则命中时执行；规则不命中的项一条命令都不执行，也就无从截断。`FlowItem` 不再有 `break` 字段，截断只有命令这一条路径。

## Alternatives considered

**只修字段的条件性，不加命令。** 落选：修掉了错误，但"这层执行到某处为止"和"结束本层继续往下"仍然无法表达。而这两种写法在分层选点里是必需的——分层要求每层能明确交代它是否放行到下一层。

**保留字段，加载时改写成 `use` 末尾的 `break` 命令。** 落选：线上配置一处都没有用过这个字段（flow 项只出现 `rules`、`mode`、`use` 三种键），兼容层没有要兼容的对象，只会把两种写法的并存从运行时挪到加载期。

**给 `FlowItem` 加 `deny_unknown_fields`，让残留的 `break: true` 在加载期报错。** 落选：判据是现有配置必须照常跑起来。那样任何多写一个键的配置都会加载失败并连带热重载失败，为了一个线上不存在的写法去冒这个险不划算。

**让 `break` 命令只截断后续 flow 项，不影响本项剩余命令。** 落选：那样 `break` 的位置就不再有意义，等于字段的另一种写法。命令的价值正在于位置可控。

**用 `mode` 或新字段表达"独占层"（命中即终止）。** 落选：这把控制流塞进了条件语义，且无法表达 `continue`。

## Verification

| 判据 | 结果 |
|---|---|
| 规则不命中的项不执行控制命令，也不截断 flow | PASS：`control_commands_do_not_run_when_rules_miss` |
| `break` 命令截断 flow，且本项后续命令不执行 | PASS：`break_and_continue_commands_stop_at_their_position` |
| `continue` 命令结束本项但不截断 flow | PASS：同一测试 |
| `break` / `continue` 可解析并序列化回原文本 | PASS：`test_flow_use_deserialize` |
| 线上配置的 flow 项不使用 `break` 字段 | PASS：脱敏镜像里 flow 项只出现 `rules`、`mode`、`use` 三种键 |

## Consequences

`break: true` 现在是个未知键，serde 静默忽略它，写了它的项因此不再截断 flow。线上配置一处都没有，但这个方向的错误不会有任何提示——真要用到截断，得写成 `use` 里的 `break` 命令。

`continue` 是新增能力，暂无配置使用。它的用处在分层选点（见[调度流分层选点](2026-08-27-flow-tiering.md)）里：一层可以先无条件补几个节点，再按条件决定是否放行到下一层。
