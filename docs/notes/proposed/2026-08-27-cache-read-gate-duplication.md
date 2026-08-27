# 缓存读写两侧的闸门不是同一份

Status: proposed

## Problem

"这个资源的这个子路径在不在缓存范围内"有两份实现。写侧是 `modules/storage/cache.rs` 的 `cache_eligible`：`cache_enabled` 关着就不缓存，非 prefix 资源直接放行，prefix 资源要求子路径存在且匹配 `cache_subpaths` 之一。读侧是 `routes/resource/downloads.rs` 里手写的一段：`cache_enabled` 关着就不查，有子路径就 glob 匹配 `cache_subpaths`，没有子路径就直接查。

两者对 prefix 资源不带子路径的请求给出相反结论。这类请求是可达的——路由同时注册了 `/{resid}` 与带子路径的形式，而资源类型校验只拒绝"非 prefix 资源带子路径"的反向组合。于是每个这类请求都会去数据存储查一次键，而写侧永远不会写入它，查询必然落空。

`cache_eligible` 是缓存回填改走内部调度时抽出来的（见[缓存回填走内部调度](../implemented/2026-08-27-cache-fill-internal-scheduling.md)），当时只接管了写侧，读侧的手写判据留在原处。

## Proposal

读侧改调 `cache_eligible`，传 `sub_path.as_deref()`。删掉 `downloads.rs` 里的 `should_check_cache` 分支与它对 `glob_match` 的直接调用。

## Alternatives considered

**反过来，让 `cache_eligible` 采纳读侧的判据（无子路径即放行）。** 落选：写侧判据才是对的。prefix 资源的裸路径不是一个内容路径，缓存它没有意义。

**两侧都保留，加一条测试断言它们一致。** 落选：断言一致的测试无法在两份实现之间挑出哪一份是权威的，而这里权威方是明确的。

## Acceptance criteria

`downloads.rs` 不再直接调用 `glob_match`。prefix 资源不带子路径的请求不再产生缓存查询。带匹配子路径的 prefix 请求与普通资源请求的缓存命中行为不变。

## Risks

若线上 Redis 里存在 prefix 资源裸路径的缓存条目（早期写侧判据与今天不同时留下的），改判后这些条目再也读不到，等同于提前失效。实施前应确认这类键是否存在；即便存在，它们也会按 `max_age` 自然过期。
