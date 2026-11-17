# MCP 签发节点下载链接

Status: implemented

## Problem

排障需要一条指向指定节点、指定资源文件的短时效 GET，给人在本机测连通、首字节和吞吐，也给 agent 在沙箱里做同样的事。以前没有这条路径：`server_health` 读的是周期 ping 缓存；`resolve_paths` 只给路径不签名；override 票把真实用户钉到节点，测的是用户出口。人要签一条链接只能走调度或手搓凭据。

## Decision

`sign_url(server_id, resid, version?, sub_path?, max_bytes?)` 落在工具组 `sign`。路径与 `resolve_paths` 同一套模板；任意 path 拒绝。前缀资源必须带 `sub_path`。TTL 用 `MCP_PRESIGN_TTL_SECONDS`。dfs_node / wt / sftp 的 uuid 用全零，与健康检查一致。

`max_bytes` 默认 32MiB，没有另行截断。健康检查缓存里若有 `file_size`，Range 再截到文件大小。单段 Range 的 end 是 u32，一次最多签 4GiB。s3 / dfs_node / dfs_webtransport / dfs_sftp 把 `bytes=0-(cap-1)` 写进签名，客户端必须带同一 Range。direct 与 git_lfs 签不了 Range，响应 `capped: false`，仍给出建议 Range。

返回 `url`、必须携带的 `headers`、`range`、`expires_at`、`transport`（type、`h3_only`、`ssh_only`、证书策略）、已知的 `file_size`，以及三条说明：测的是调用方到节点；不写 session、不计入当日带宽；传输字节算节点配额。ssh_only 节点的 URL 走现有改写，带上指纹片段。

不写存储、不代测、不批量、不 PUT。用户视角的验证仍是 override 票加真实客户端。

## Alternatives considered

**DFS2 代测吞吐。** 落选：烧调度器出口，测点固定；人需要自己能打开的链接。

**接受任意 path。** 落选：签名面大于配置能推出的对象。

**放进 `runtime` 组。** 落选：这是签发节点 URL，与运行时点查不是同一能力边界；只开 `runtime` 的部署不该自动获得。

**由调度器健康检查时延代替带签首字节。** 落选：那是调度器到节点，不是人/agent 到节点；两者都要。

## Verification

| 判据 | 结果 |
|---|---|
| direct 节点 `capped` 为 false，URL 为配置 host + 模板路径；有 `file_size` 时 Range 跟文件走，没有时按请求的 `max_bytes`；超过单段 Range 可编码长度为工具错误；前缀资源不带 `sub_path` 为工具错误 | PASS：`sign_url_direct_uses_file_size_or_requested_range` |
| s3 节点 `capped` 为 true，presign 含 Range 签名与配置的 TTL | PASS：`sign_url_s3_signs_range_header` |
| 只开 `sign` 时列表只有 `sign_url` | PASS：`tool_groups_sign_lists_only_sign_url` |
| 不触发 SCAN | PASS：`runtime_tools_do_not_scan` |

## Consequences

持有 MCP token 的人可以按 `max_bytes` 拉节点流量（direct 的 Range 只是建议）。URL 在 TTL 内对任何持有者有效，与日志 presign 同一前提。

测速结论只对调用方出口成立。direct / git_lfs 的 Range 只是建议，拉整文件会烧配额。

已写 allowlist 且未列入 `sign` 的部署看不到该工具。
