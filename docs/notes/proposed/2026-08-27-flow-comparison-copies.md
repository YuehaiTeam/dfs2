# 比较符求值的六份副本

Status: proposed

## Problem

`FlowComp` 的求值在 `flow_service.rs` 的 `evaluate_condition` 里出现了六次，每次都是同一段六臂 match：`size`、`bw_daily`、`server_bw_daily` 的缓存命中分支、`server_bw_daily` 的缓存缺失分支、`server_bw_daily` 的兜底分支，以及 `time`。前五处比的是 `u64`，最后一处比的是 `NaiveTime`，除了被比的两个值，六份代码逐字相同。

副本已经在漂移。`server_bw_daily` 缓存缺失时那一份把左值写成了字面量 `0`，于是整段读作 `0 == limit_bytes`、`0 > limit_bytes`——语义上没错（用量按 0 计），但它是唯一一处不能靠比对上下文看出左值是什么的副本。新增一个比较符或改一处语义要同步六处，而这六处分散在一个近两百行的 match 里。

## Proposal

给 `FlowComp` 加一个求值方法，形如 `fn matches<T: PartialOrd>(&self, lhs: T, rhs: T) -> bool`，六处调用点各收敛成一行。方法放在 `modules/flow/config.rs`，与符号表同处。

## Alternatives considered

**只把 `u64` 那五处收敛，`time` 保持原样。** 落选：泛型边界 `PartialOrd` 对 `NaiveTime` 同样成立，特意留一处例外反而要解释为什么。

**用宏展开代替泛型方法。** 落选：这里没有类型之外的差异，泛型足够，宏会让调用点更难读。

## Acceptance criteria

`FlowComp::Eq =>` 在 `flow_service.rs` 里不再出现。六个条件的求值结果与改动前一致，现有的 `size`、`bw_daily`、`server_bw_daily`、`time` 测试不变通过。

## Risks

`server_bw_daily` 缓存缺失分支的左值从字面量 `0` 变成一个具名的 0 值，行为不变但这份漂移会被固定下来——如果它原本是笔误（本意是读某个别的值），收敛会让笔误更难被发现。实施前应确认该分支的语义确实是"用量按 0 计"。
