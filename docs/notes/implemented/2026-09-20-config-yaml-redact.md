# 配置原文脱敏

Status: implemented

## Problem

排障要看节点注释、键顺序和真实 YAML 才能写出能直接 apply 的 diff。进程里若只给反序列化后再投影的 JSON，注释没了，模型也会按 JSON 改配置。配置仓库的历史脱敏和进程内当前文件必须是同一套改写，不能各写各的。

## Decision

`dfs2 redact <输入目录> <输出目录>` 做文本改写。输入目录的每个子目录是一棵文件树（CI 按 first-parent 顺序用 `git archive` 展开）。程序先从全部 YAML 收集凭据值（URL userinfo 里的用户名与密码；键名含 password / passwd / secret / token / authorization / license / access_key / secret_key / api_key / private_key / credential 的行值），再逐树改写并写出到输出目录的同名子目录。写出前核对：输出文本不得再出现任一已收集的值，也不得留下未打星的 `user:pass@`。命中则退出码 2，并打印 `子目录/相对路径`。凭据值只留在内存。

改写规则：URL userinfo 取 `://` 之后、主机前最后一个 `@` 之前的那段（密码可以含 `/`），换成 `*:*@`；YAML 敏感键的值换成 `'*'`，行尾注释保留。长度不足 6 或落在白名单（含 `dfsuser`、`trust`、`true`/`false` 等）的值不收集、不打星。非 YAML 文本只改 URL userinfo，但仍按已收集的值核对。二进制只做子串核对。

`AppConfig::load` 留下配置文件原文（`config_yaml`），热重载走同一路径。MCP `config` 对这份原文走同一组函数，通过后第一块返回 YAML，第二块是 `loaded_at` 与加载时摘掉的 flow 节点引用。建议 diff 对第一块。

CI 只做 git：展开每个 commit、调用 `dfs2 redact`、按顺序把输出树 commit 进镜像仓库（作者、日期、说明照抄，末尾加 `Source-Commit:`），成功才 `push --force`。脚本在 `tools/secrets-mirror/mirror.sh`，流水线片段在同目录 `cnb-mirror-job.yml`。`DFS2` 指向二进制，默认 `dfs2`。

## Alternatives considered

**只返回反序列化后的 JSON。** 落选：注释与格式丢失，模型会按 JSON 出 diff。

**把注释抽成结构化字段。** 落选：注释位置不固定，抽不干净。

**两遍之间把收集到的值写成文件。** 落选：多一份全历史凭据的落盘副本。

**MCP 与镜像各写一套改写。** 落选：规则会漂。

**独立进程再读一遍配置做 MCP。** 落选：日志 presign 与运行时点查仍要进程内句柄；见 [排障 MCP 端点](./2026-09-15-troubleshooting-mcp.md)。

## Verification

| 判据 | 结果 |
|---|---|
| URL userinfo 打星；`webhook_token` / `authorization` / `secret_key` 打星；中文注释保留；`access_key: dfsuser` 不动 | PASS：`redacts_urls_keys_keeps_comments_and_benign` |
| 密码含 `/` 的 userinfo 整段打星 | PASS：`slash_inside_url_password_is_starred` |
| 前一棵树 YAML 里出现过的值，后一棵树非 YAML 里再出现则退出码语义为泄露，且不写输出 | PASS：`two_trees_harvest_then_catch_leak_in_later_tree` |
| 正常树写出后注释与打星结果与规则一致 | PASS：`run_writes_redacted_trees` |
| MCP `config` 第一块是打星后的 YAML，含注释，不含 fixture 密钥 | PASS：`config_returns_redacted_yaml` |

## Consequences

键名不匹配上述模式的新密钥字段会原样出现在输出里；注释里若写了从未出现在 URL userinfo 或敏感键上的值，也核对不到。与镜像公开发布面相同，新增一种密钥键名时要改正则。

CI 镜像仓库需要能执行 `dfs2`。规则升级后对真实历史 dry-run 一次、逐 commit 比对文件树，再 force push。
