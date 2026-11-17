# 排障说明

方法论以部署平台打包的 `dfs-diagnosis` skill 为准（含产品形态、判据、工具箱）。本 resource 仅保留 MCP 入口提示；多数 agent 读不到 resource，应直接加载该 skill。

工具列表以当场注册为准；未出现的工具不当故障。凭据不进模型上下文。presign、`sign_url` 与 `config_mirror` 返回值不写进回复。`config` 返回当前加载的 config.yaml（凭据已打星），建议 diff 对这份文本。

先按时间窗口或 sid 拉日志再在沙箱处理。`log_objects` / `log_objects_for_sid` 同时探测日桶与小时桶，只返回已存在的 key；空列表表示窗口内没有归档。`log_objects_for_sid` 只对服务端生成的前缀 sid 有效，解不出创建时间时退回 `log_objects`。

运行时点查只反映仍在存储里的状态；过期 session 从日志恢复。`server_health` 读的是周期 ping 连通性，`unchecked` 是没配健康检查路径。`sign_url` 从调用方测到节点，不是用户到节点。客户端错误不算服务器错误率。产出是证据和建议，不改配置、不重载、不写存储。
