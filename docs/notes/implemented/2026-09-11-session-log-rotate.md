# Session log 自管理切桶与归档

Status: implemented

## Problem

Session log 是分析用 JSONL，由 `SessionLogger` 追加写入；程序 log 是 tracing 打到 stdout。两条管道必须分开。若进程不自己切桶、不压缩已离开的文件、也不把副本送到对象存储，小于一天的切片和 zstd 只能靠目录外的脚本；脚本与正在追加的 writer 抢同一文件时，会压到半截、在 Windows 上删不掉，或把仍在写的当前文件收走。

带宽日切和 flow 的 `time` 规则认 `chrono::Local`。按 UTC 日界切文件会和本地业务日错位。没有对象存储上的当前桶副本时，进程所在磁盘丢失就丢掉整个未切走周期。`dfs2 analyze` 若只认明文，压缩后的文件读不了。

## Decision

进程按本地时钟切桶，确认离开一个文件之后再压缩，并按需把 `.zst` 放到配置的 S3。Session log 不进入 tracing，程序 log 仍只走 stdout。不引入 rotate 框架；压缩用 `zstd` crate。切桶靠文件名，不把正在写的文件 rename 成 `CURRENT`。逻辑在 `session_log_rotate`，`SessionLogger::write_log` 只负责序列化后交给它追加。

### 切桶

文件名用 `chrono::Local`（OS / `TZ`），与带宽日切、flow `time` 同一时区。JSON 里的 `start` / `end` / `ts` 仍是 unix 秒。

`SESSION_LOG_ROTATE_HOURS` 取 `1..=24`，默认 `24`。桶起点是 `hour - (hour % n)`。`n == 24` 时文件名是 `sessions.YYYY-MM-DD.log`；更短周期带桶起点小时，例如 n=6 为 `sessions.YYYY-MM-DD-00.log` 起每六小时一个。n 不必整除 24，最后一段可以短于 n。

下一笔写入落到新文件名即完成切桶。模块内记下本进程实际写过的当前 stem。只有这个 stem 已不是当前桶时，才压缩那一个文件。不 `read_dir`，不补压目录里其他明文；历史补压由独立脚本负责。进程启动时 stem 为空，磁盘上已有的昨天文件也不压。长时间无写入时，`SessionCleanupTask` 只检查 remembered stem 是否过期，仍然不扫目录。

`SessionLogger` 仍按调用点构造。算 stem、追加、压缩上一文件、做分钟快照，共用一把异步互斥。序列化 JSON 在锁外。

### 压缩

`SESSION_LOG_COMPRESS` 为 `zstd`（默认）或 `none`。`zstd` 时关闭文件写成 `*.log.zst`（先临时文件再 rename），成功后删明文；目标 `.zst` 已在则只删对应 `.log`。压失败或磁盘满则明文留下。`none` 时本地不落 `.zst`、不删明文。

关闭文件用 `SESSION_LOG_ZSTD_LEVEL`，默认 `3`。zstd 的 `0` 表示实现默认级别，不是关闭压缩；关闭压缩用 `COMPRESS=none`。压缩在 `spawn_blocking` 里跑。不按保留天数删除本地文件。

### S3 归档

`SESSION_LOG_ARCHIVE_S3` 为空则不上传、也不做分钟同步。有值时用现有 S3 server URL 方言，不引用下载节点 id。`SESSION_LOG_ARCHIVE_PREFIX` 可选。object key 为 `{prefix}{stem}.log.zst`。S3 上始终是 `.zst`。

关闭文件要上传时，用 `SESSION_LOG_ZSTD_LEVEL` 得到一份 `.zst`：`COMPRESS=zstd` 用本地那份并在上传后保留；`COMPRESS=none` 打临时包，上传后删临时文件，本地明文不动。`S3Signer` 签 SigV4 PUT（`UNSIGNED-PAYLOAD`，带 `Content-Length`），用 `reqwest` 上传。失败只打 error，不扫目录补传。日志不打印带 secret 的归档 URL。`dfs2 analyze` 不从 S3 拉对象。

同一 `SESSION_LOG_PATH` 与同一归档 key 按单进程写。多实例要并存时把 prefix 写成带实例名。单对象 PUT，不分片。

### 当前文件同步

`SESSION_LOG_SYNC_MINUTES` 大于 0 且归档 URL 有效时，独立 ticker 每隔该分钟数把当前桶明文复制到临时文件，用 `SESSION_LOG_SYNC_ZSTD_LEVEL`（默认 `1`）压缩，覆盖同一 object key。本地当前 `.log` 不被替换。空文件或长度为 0 则跳过。复制可能截到半行 JSON。

remembered stem 为空则 ticker 空转：本进程还没写出第一行之前，即使磁盘上已有当前桶文件也不上传。PUT 前再读当前 stem，桶已切走则丢掉这帧。rotate 的终稿 PUT 不受这条拦截。

同步是整文件重压重传。优雅退出不额外刷一帧；S3 上当前桶最多落后一轮间隔。

两档 level 都是 zstd 的 `i32`（允许负值）。非法值回落到各自默认并 warn。归档 URL 解析失败则禁用上传并打 error，本地写入与压缩不受影响。只设了分钟、没设 S3 则 warn 且不启动 ticker。

### 分析

`dfs2 analyze` 在路径以 `.zst` / `.zstd` 结尾时用 `zstd::Decoder` 再按 JSONL 解析。分析算法不变，仍只读本地路径。

## Alternatives considered

**把 session 记录打成 tracing event，用 `tracing-appender` 切文件。** 落选：appender 只有整点 hourly / daily / minutely，无 zstd，且会和程序 log 共用一条管道。

**`file-rotate`。** 落选：时间切分是整点 `Hourly` 等，压缩只有 flate2 gzip，API 是同步 `Write`。

**`flexi_logger`。** 落选：另一套程序日志框架，和现有 tracing 冲突，压缩是 gzip，没有按 n 小时的切分。

**`wattle-appender`。** 落选：0.1.0，面向 tracing，不能按 n 小时切，不适合作为生产依赖。

**UTC 切桶。** 落选：带宽日切和 flow `time` 已经认本地时区，UTC 日界上的文件名和本地业务日错位。

**`CURRENT` 加 rename。** 落选：`dfs2 analyze` 和现有目录都按日期文件名消费；rename 正在写的文件会和追加抢同一 inode。

**启动或 cleanup 时扫目录，压缩所有非当前 `.log`。** 落选：会把部署前留下的历史明文一并纳入进程职责，补压交给独立脚本。

**`aws-sdk-s3`。** 落选：项目已有 SigV4 与 `reqwest`；归档只需要 PUT 一个对象。

**重启后、本进程尚未写入时同步磁盘上已有的当前桶。** 落选：与「不碰本进程没写过的文件」同一条线；崩溃恢复靠上一进程已传到 S3 的最后一帧，以及本机明文。

**`COMPRESS=none` 时关闭文件不上传。** 落选：只开归档、不开分钟同步时 S3 上不会出现该周期；本地不压和对象存储上是否有 `.zst` 是两件事。

## Verification

| 判据 | 结果 |
|---|---|
| `ROTATE_HOURS=24` 无小时后缀；n=6 在本地 07:00 落到 `-06` | PASS：`daily_stem_has_no_hour`、`six_hour_stem_floors_to_bucket_start` |
| 只压本进程写过的上一文件；目录里另放的明文不动 | PASS：`rotate_compresses_only_remembered_previous_file` |
| 启动后第一笔写入不压磁盘上已有的旧文件 | PASS：`first_write_does_not_compress_preexisting_file` |
| 并发两行追加不交错 | PASS：`concurrent_appends_are_whole_lines` |
| `COMPRESS=zstd` 关闭后明文消失；`none` 保留明文且归档仍 PUT `.zst` | PASS：`rotate_compresses_only_remembered_previous_file`、`compress_none_keeps_plaintext`、`compress_none_with_archive_puts_zst_and_keeps_plain` |
| 归档失败不删本地 `.zst` | PASS：`failed_archive_keeps_local_zst` |
| 分钟同步不改本地明文；未 remembered 不同步；stem 已变不 PUT | PASS：`sync_leaves_local_plaintext_and_skips_without_remembered`、`sync_put_aborts_when_stem_changes` |
| `dfs2 analyze` 明文与 `.zst` 解析一致 | PASS：`test_parse_zstd_log_file_matches_plaintext` |
| PUT 签名稳定且错误文本不含 URL | PASS：`presigned_put_is_put_with_unsigned_payload_and_stable_signature`、`put_object_error_omits_url` |

## Consequences

同一路径或同一归档 key 上跑两个进程会交错追加并互相覆盖对象。UNSIGNED-PAYLOAD PUT 可能被严格的 S3 实现拒绝。单对象 PUT 没有分片，关闭文件极大时可能超过实现限制。

分钟同步整文件重传，CPU 与上行按「当前文件体积 × 每天次数」增长。优雅退出不刷最后一帧。重启后到本进程第一笔写入之前，S3 上的当前桶不会更新。快照可能截到半行，分析端会看到一条解析失败。

夏令时日界与带宽日切承担同一类偏差。时钟回拨可能让写入落到一个已经压缩并删掉明文的 stem 上，该文件被重新创建且不会再次被本进程压缩。
