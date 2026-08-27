# 会话选点落库的两条并行路径

Status: proposed

## Problem

`SessionService` 上有两个执行 flow 并记录结果的入口，后半段逐字相同：算 `scoped_download_key`、取 `get_schedule_penalties`、调 `execute_flow`、URL 非空则组一条 `CdnRecord` 交给 `record_final_cdn_selection`。`run_flow_for_session` 服务 `download: enabled` 的会话，自己拼 `FlowTarget` 与 `FlowContext` 并按 `session.chunks` 校验区间；`run_flow_for_sticky_download` 服务 free 粘滞下载，两者都由调用方传入。

于是 `CdnRecord` 的字段组装有两份。`size` 一处取 `file_size` 参数、一处取 `target.file_size`，眼下同源（都是 `downloads.rs` 里的 `request_file_size`），但这一点要读三个文件才能确认。惩罚口径、`skip_penalty` 的取值、记录时机同理，各有两份。

同一个文件里的 `get_penalty_servers` 没有生产调用者，只有两个测试在用。它自己拼一个单键 map 再调 `schedule_penalties_from_records` 取 `.banned`，是 `get_schedule_penalties` 的一个特例；惩罚拆分（见[调度惩罚的封禁与降权](../implemented/2026-08-27-schedule-penalty-split.md)）改写了它的实现，但没有恢复它的调用者。

## Proposal

抽一个私有方法承担共同的后半段：吃 `session_id`、`chunk_key`、`target`、`context`，执行 flow 并落库，返回 `FlowResult`。两个入口各自只保留前半段的差异——`run_flow_for_session` 拼 target/context 并校验区间，`run_flow_for_sticky_download` 直接转交。

删除 `get_penalty_servers`，两个测试改为断言 `get_schedule_penalties` 的 `banned`。

## Alternatives considered

**合并成一个公开函数，由调用方统一构造 target 与 context。** 落选：`run_flow_for_session` 的区间校验依赖 `session.chunks`，挪到调用方会把校验散进路由层，而路由层已经在做一次形态不同的 chunk 校验。

**保留 `get_penalty_servers` 作为便捷入口。** 落选：没有生产调用者，它现在只是给测试提供了一条与生产不同的取惩罚路径——测试因此测不到生产实际走的那条。

## Acceptance criteria

`CdnRecord` 的组装在 `session_service.rs` 里只出现一处。`get_penalty_servers` 不再存在。会话相关测试通过，且惩罚断言走的是生产路径上的那个方法。

## Risks

两条路径的 `CdnRecord.size` 取值来源不同，合并时要先确认它们等价；若不等价，合并会静默改变其中一条路径记录的字节数，而这个字段进的是分成对账用的会话日志。
