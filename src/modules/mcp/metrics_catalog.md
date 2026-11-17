# 指标语义目录

完整语义与口径见部署平台打包的 `dfs-diagnosis` skill（`references/domain.md`）。本 resource 仅作短索引；多数 agent 读不到 resource。

对象存储桶 API 流量指标里，`received` 是下行（用户下载），`sent` 是上行。节点 id 落在 `server` label（部分导出用 `instance`）。序列缺失表示该节点没上报，不表示流量为零——先做新鲜度盘点。容量看分钟级分位，不看小时均值。分成口径用存储侧实测字节，不用调度器估算。
