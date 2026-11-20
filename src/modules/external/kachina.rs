use bytes::Bytes;
use serde_json::{Value, json};

use crate::config::SharedConfig;
use crate::container::FETCH_CLIENT;
use crate::error::{DfsError, DfsResult};
use crate::models::{FlowContext, FlowOptions, FlowTarget};
use crate::services::FlowService;

/// KachinaInstaller 解析结果
#[derive(Debug)]
pub struct KachinaMetadata {
    pub index: Value,
    pub metadata: Value,
    pub installer_end: u32,
}

/// 错误码常量定义
const E_READ_RESPONSE_FAILED: &str = "E_READ_RESPONSE_FAILED";

/// 在字节数组中搜索指定的模式
///
/// # Arguments
/// * `haystack` - 要搜索的字节数组
/// * `needle` - 要查找的模式
///
/// # Returns
/// 返回找到的位置，如果没找到则返回None
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }

    (0..=(haystack.len() - needle.len())).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// 解析文件头部信息，查找 KachinaInstaller 标识符并提取索引信息
///
/// # Arguments
/// * `data` - 文件的前256字节数据
///
/// # Returns
/// 返回 Result<serde_json::Value, String>，成功时包含解析后的头部信息
pub fn parse_file_header(data: &[u8]) -> Result<Value, String> {
    // 直接在字节数组中搜索标识符，避免UTF-8转换问题
    let header_marker = b"!KachinaInstaller!";
    let header_offset = match find_bytes(data, header_marker) {
        Some(offset) => offset,
        None => {
            return Ok(json!({
                "type": "unknown",
                "message": "Not a KachinaInstaller file"
            }));
        }
    };

    let index_offset = header_offset + header_marker.len();

    // 确保有足够的字节来读取索引信息（至少需要20字节：5个uint32）
    if index_offset + 20 > data.len() {
        return Err("Insufficient data to read index information".to_string());
    }

    // 读取索引信息（大端序）
    let index_start = u32::from_be_bytes([
        data[index_offset],
        data[index_offset + 1],
        data[index_offset + 2],
        data[index_offset + 3],
    ]);

    let config_sz = u32::from_be_bytes([
        data[index_offset + 4],
        data[index_offset + 5],
        data[index_offset + 6],
        data[index_offset + 7],
    ]);

    let theme_sz = u32::from_be_bytes([
        data[index_offset + 8],
        data[index_offset + 9],
        data[index_offset + 10],
        data[index_offset + 11],
    ]);

    let index_sz = u32::from_be_bytes([
        data[index_offset + 12],
        data[index_offset + 13],
        data[index_offset + 14],
        data[index_offset + 15],
    ]);

    let metadata_sz = u32::from_be_bytes([
        data[index_offset + 16],
        data[index_offset + 17],
        data[index_offset + 18],
        data[index_offset + 19],
    ]);

    // 验证读取到的大小值是否合理（避免读取到损坏的数据）
    const MAX_REASONABLE_SIZE: u32 = 100 * 1024 * 1024; // 100MB
    if index_sz > MAX_REASONABLE_SIZE
        || config_sz > MAX_REASONABLE_SIZE
        || theme_sz > MAX_REASONABLE_SIZE
        || metadata_sz > MAX_REASONABLE_SIZE
    {
        return Err(format!(
            "Unreasonable size values detected: index_sz={index_sz}, config_sz={config_sz}, theme_sz={theme_sz}, metadata_sz={metadata_sz}"
        ));
    }

    // 使用 checked_add 防止溢出
    let data_end = index_start
        .checked_add(index_sz)
        .and_then(|sum| sum.checked_add(config_sz))
        .and_then(|sum| sum.checked_add(theme_sz))
        .and_then(|sum| sum.checked_add(metadata_sz))
        .ok_or_else(|| format!(
            "Integer overflow when calculating data_end: index_start={index_start}, index_sz={index_sz}, config_sz={config_sz}, theme_sz={theme_sz}, metadata_sz={metadata_sz}"
        ))?;

    Ok(json!({
        "type": "kachina_installer",
        "header_offset": header_offset,
        "index_offset": index_offset,
        "index_start": index_start,
        "config_size": config_sz,
        "theme_size": theme_sz,
        "index_size": index_sz,
        "metadata_size": metadata_sz,
        "data_end": data_end,
        "installer_end": index_start
            .checked_add(config_sz)
            .and_then(|sum| sum.checked_add(theme_sz))
            .ok_or_else(|| "Integer overflow when calculating installer_end".to_string())?
    }))
}

/// 获取文件指定范围的内容
///
/// # Arguments
/// * `config` - 应用配置
/// * `runner` - Flow运行器
/// * `resid` - 资源ID
/// * `version` - 版本（可选，默认使用latest）
/// * `ranges` - 字节范围，格式如 Some(vec![(0, 255)])
///
/// # Returns
/// 返回 Result<Bytes, String>，成功时包含文件字节数据，失败时包含错误信息
pub async fn fetch_file_range(
    shared_config: &SharedConfig,
    flow_service: &FlowService,
    resid: &str,
    version: &str,
    sub_path: Option<String>,
    ranges: Option<Vec<(u32, u32)>>,
) -> DfsResult<Bytes> {
    // 读锁访问配置
    let config_guard = shared_config.load();

    // 检查资源是否存在
    let resource_config = match config_guard.get_resource(resid) {
        Some(rc) => rc,
        None => return Err(DfsError::resource_not_found(resid.to_string())),
    };

    // 使用 FlowService 获取文件的下载 URL
    let flow_list = &resource_config.flow;
    // 根据range计算文件大小
    let request_file_size = ranges.as_ref().map(|ranges| {
        ranges
            .iter()
            .map(|(start, end)| (end - start + 1) as u64)
            .sum()
    });

    // 构建新的Flow参数结构
    let target = FlowTarget {
        resource_id: resid.to_string(),
        version: version.to_string(),
        sub_path,
        ranges: ranges.clone(),
        file_size: request_file_size,
    };

    // 元数据解析由服务端自己取件，不代表任何客户端
    let context = FlowContext::internal(config_guard.internal.egress_ip());

    let options = FlowOptions {
        cdn_full_range: false, // Kachina解析不使用全范围模式
    };

    // 执行Flow获取URL
    let flow_result = flow_service
        .execute_flow(
            &target,
            &context,
            &options,
            flow_list,
            crate::models::FlowPenalties::default(),
            None,
        )
        .await?;
    let cdn_url = flow_result.url;

    // 构建 Range 头部（若 map: 下发了 #range= 则按物理区间或整文件请求）
    let mut expected_range_start: Option<u64> = None;
    let range_header = match crate::modules::extent_map::extract_range_fragment(&cdn_url) {
        Some("0-") => String::new(),
        Some(phys_range) => {
            expected_range_start = phys_range
                .split_once('-')
                .and_then(|(s, _)| s.parse::<u64>().ok());
            format!("bytes={phys_range}")
        }
        None => {
            if let Some(ranges) = &ranges {
                if ranges.len() == 1 {
                    expected_range_start = Some(u64::from(ranges[0].0));
                    format!("bytes={}-{}", ranges[0].0, ranges[0].1)
                } else {
                    let range_parts: Vec<String> = ranges
                        .iter()
                        .map(|(start, end)| format!("{start}-{end}"))
                        .collect();
                    format!("bytes={}", range_parts.join(","))
                }
            } else {
                String::new()
            }
        }
    };

    // 使用全局 HTTP 客户端下载文件
    let mut request = FETCH_CLIENT.get(&cdn_url);

    if !range_header.is_empty() {
        request = request.header("Range", &range_header);
    }

    let response = match request.send().await {
        Ok(resp) => Ok(resp),
        Err(e) => Err(DfsError::NetworkError {
            reason: e.to_string(),
        }),
    }?;

    let status = response.status();
    if status == axum::http::StatusCode::RANGE_NOT_SATISFIABLE {
        let is_initial_header_probe = matches!(ranges.as_deref(), Some([(0, 255)]));
        if is_initial_header_probe
            && let Some(total) = parse_unsatisfied_content_range_total(response.headers())
            && total < 256
        {
            return Ok(Bytes::new());
        }
        return Err(DfsError::NetworkError {
            reason: format!("{E_READ_RESPONSE_FAILED}: {status}"),
        });
    }

    if !range_header.is_empty() {
        if status != axum::http::StatusCode::PARTIAL_CONTENT {
            return Err(DfsError::NetworkError {
                reason: format!(
                    "{E_READ_RESPONSE_FAILED}: expected 206 Partial Content for Range '{range_header}', got {status}"
                ),
            });
        }
        if let Some(expected_start) = expected_range_start
            && let Some(actual_start) = parse_partial_content_range_start(response.headers())
            && actual_start != expected_start
        {
            return Err(DfsError::NetworkError {
                reason: format!(
                    "{E_READ_RESPONSE_FAILED}: Content-Range start {actual_start} does not match requested start {expected_start}"
                ),
            });
        }
    } else if !status.is_success() {
        return Err(DfsError::NetworkError {
            reason: format!("{E_READ_RESPONSE_FAILED}: {status}"),
        });
    }

    match response.bytes().await {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(DfsError::NetworkError {
            reason: e.to_string(),
        }),
    }
}

fn parse_unsatisfied_content_range_total(headers: &axum::http::HeaderMap) -> Option<u64> {
    let raw = headers
        .get(axum::http::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .trim();
    let rest = raw.strip_prefix("bytes")?.trim();
    let total_str = rest.strip_prefix("*/")?.trim();
    total_str.parse::<u64>().ok()
}

fn parse_partial_content_range_start(headers: &axum::http::HeaderMap) -> Option<u64> {
    let raw = headers
        .get(axum::http::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .trim();
    let rest = raw.strip_prefix("bytes")?.trim();
    let (span, _) = rest.split_once('/')?;
    let (start_str, _) = span.trim().split_once('-')?;
    start_str.trim().parse::<u64>().ok()
}

/// 解析 KachinaInstaller 索引数据
///
/// # Arguments
/// * `index_data` - 索引区的字节数据
/// * `index_start` - 索引区的起始偏移量
///
/// # Returns
/// 返回解析后的段数据
pub fn parse_index_data(index_data: &[u8], index_start: u32) -> Value {
    let mut segments = json!({});
    let mut offset = 0;

    while offset < index_data.len() {
        // 查找段标识符 "!IN\0"
        if offset + 4 > index_data.len() {
            break;
        }

        let magic = &index_data[offset..offset + 4];
        if magic != b"!IN\0" {
            offset += 1;
            continue;
        }

        // 找到段，开始解析
        offset += 4; // 跳过魔术字节

        if offset + 2 > index_data.len() {
            break;
        }

        // 读取名称长度 (大端序)
        let name_len = u16::from_be_bytes([index_data[offset], index_data[offset + 1]]) as usize;
        offset += 2;

        if offset + name_len > index_data.len() {
            break;
        }

        // 读取名称
        let name = String::from_utf8_lossy(&index_data[offset..offset + name_len]).to_string();
        offset += name_len;

        if offset + 4 > index_data.len() {
            break;
        }

        // 读取数据大小 (大端序)
        let size = u32::from_be_bytes([
            index_data[offset],
            index_data[offset + 1],
            index_data[offset + 2],
            index_data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + size > index_data.len() {
            break;
        }

        // 读取数据
        let data = &index_data[offset..offset + size];
        offset += size;

        match name.as_str() {
            "\0CONFIG" => {
                if let Ok(config_str) = String::from_utf8(data.to_vec())
                    && let Ok(config_json) = serde_json::from_str::<Value>(&config_str)
                {
                    segments["config"] = config_json;
                }
            }
            "\0META" => {
                if let Ok(meta_str) = String::from_utf8(data.to_vec())
                    && let Ok(meta_json) = serde_json::from_str::<Value>(&meta_str)
                {
                    segments["metadata"] = meta_json;
                }
            }
            "\0THEME" => {
                if let Ok(theme_str) = String::from_utf8(data.to_vec()) {
                    segments["theme"] = json!(theme_str);
                }
            }
            "\0INDEX" => {
                let mut index_map = json!({});
                let mut idx_offset = 0;

                while idx_offset < data.len() {
                    if idx_offset + 1 > data.len() {
                        break;
                    }

                    let file_name_len = data[idx_offset] as usize;
                    idx_offset += 1;

                    if idx_offset + file_name_len > data.len() {
                        break;
                    }

                    let file_name =
                        String::from_utf8_lossy(&data[idx_offset..idx_offset + file_name_len])
                            .to_string();
                    idx_offset += file_name_len;

                    if idx_offset + 8 > data.len() {
                        break;
                    }

                    let file_size = u32::from_be_bytes([
                        data[idx_offset],
                        data[idx_offset + 1],
                        data[idx_offset + 2],
                        data[idx_offset + 3],
                    ]);
                    idx_offset += 4;

                    let file_offset = u32::from_be_bytes([
                        data[idx_offset],
                        data[idx_offset + 1],
                        data[idx_offset + 2],
                        data[idx_offset + 3],
                    ]);
                    idx_offset += 4;

                    let abs_offset = index_start.saturating_add(file_offset);
                    let header_size = 10u32.saturating_add(file_name.len() as u32);
                    let raw_offset = abs_offset.saturating_sub(header_size);

                    index_map[&file_name] = json!({
                        "name": file_name,
                        "offset": abs_offset,
                        "raw_offset": raw_offset,
                        "size": file_size
                    });
                }
                segments["index"] = index_map;
            }
            _ => {
                // 未知段，忽略
            }
        }
    }

    segments
}

#[derive(serde::Deserialize)]
struct RootKachinaProjection {
    index: serde_json::Map<String, Value>,
    metadata: serde_json::Map<String, Value>,
    installer_end: u32,
    #[serde(default)]
    size: Option<u64>,
}

/// Projects `{ index, metadata, installer_end }` directly from a root JSON document,
/// ignoring any unrelated top-level keys that coexist in the same JSON object.
pub fn try_project_kachina_metadata(json_bytes: &[u8]) -> Option<KachinaMetadata> {
    let projected: RootKachinaProjection = serde_json::from_slice(json_bytes).ok()?;
    if projected.installer_end == 0 {
        return None;
    }
    if let Some(size) = projected.size
        && u64::from(projected.installer_end) > size
    {
        return None;
    }
    Some(KachinaMetadata {
        index: Value::Object(projected.index),
        metadata: Value::Object(projected.metadata),
        installer_end: projected.installer_end,
    })
}

/// 解析 KachinaInstaller 文件的元数据
///
/// # Arguments
/// * `config` - 应用配置
/// * `runner` - Flow运行器
/// * `resid` - 资源ID
/// * `version` - 版本（可选，默认使用latest）
///
/// # Returns
/// 返回 `Result<Option<KachinaMetadata>, DfsError>`，成功时返回解析结果，`None` 表示不是 KachinaInstaller 文件
pub async fn parse_kachina_metadata(
    shared_config: &SharedConfig,
    flow_service: &FlowService,
    resid: &str,
    version: &str,
    sub_path: Option<String>,
) -> DfsResult<Option<KachinaMetadata>> {
    let mut fetched_mapped_manifest = false;
    if sub_path.is_none()
        && let Some(manifest_bytes) = flow_service
            .try_fetch_mapped_manifest_bytes(resid, version, None)
            .await
    {
        fetched_mapped_manifest = true;
        if let Some(projected) = try_project_kachina_metadata(&manifest_bytes) {
            return Ok(Some(projected));
        }
    }

    // 获取文件的前256字节
    let header_bytes = match fetch_file_range(
        shared_config,
        flow_service,
        resid,
        version,
        sub_path.clone(),
        Some(vec![(0, 255)]),
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(DfsError::RangeNotSatisfiable { message }) => {
            if message.contains("exceeds virtual size") || fetched_mapped_manifest {
                tracing::warn!(
                    resid = %resid,
                    version = %version,
                    "Kachina header probe range 0-255 not satisfiable ({message}); returning null metadata"
                );
                return Ok(None);
            }
            return Err(DfsError::RangeNotSatisfiable { message });
        }
        Err(e) => return Err(e),
    };

    // 解析文件头部信息
    let parsed_header = parse_file_header(&header_bytes)?;

    // 检查是否为 KachinaInstaller 文件
    if parsed_header["type"] != "kachina_installer" {
        return Ok(None);
    }

    let index_start = parsed_header["index_start"]
        .as_u64()
        .ok_or_else(|| "Missing or invalid index_start in header".to_string())?
        as u32;
    let config_sz = parsed_header["config_size"]
        .as_u64()
        .ok_or_else(|| "Missing or invalid config_size in header".to_string())?
        as u32;
    let theme_sz = parsed_header["theme_size"]
        .as_u64()
        .ok_or_else(|| "Missing or invalid theme_size in header".to_string())?
        as u32;
    let index_sz = parsed_header["index_size"]
        .as_u64()
        .ok_or_else(|| "Missing or invalid index_size in header".to_string())?
        as u32;
    let metadata_sz = parsed_header["metadata_size"]
        .as_u64()
        .ok_or_else(|| "Missing or invalid metadata_size in header".to_string())?
        as u32;
    let data_end = index_start
        .checked_add(index_sz)
        .and_then(|sum| sum.checked_add(config_sz))
        .and_then(|sum| sum.checked_add(theme_sz))
        .and_then(|sum| sum.checked_add(metadata_sz))
        .ok_or_else(|| "Integer overflow when calculating data_end".to_string())?;
    let installer_end = index_start
        .checked_add(config_sz)
        .and_then(|sum| sum.checked_add(theme_sz))
        .ok_or_else(|| "Integer overflow when calculating installer_end".to_string())?;

    if data_end <= index_start {
        return Ok(None);
    }

    let expected_index_len = (data_end - index_start) as usize;

    // 下载索引数据
    let index_data = match fetch_file_range(
        shared_config,
        flow_service,
        resid,
        version,
        sub_path,
        Some(vec![(index_start, data_end - 1)]),
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(DfsError::RangeNotSatisfiable { message }) if fetched_mapped_manifest => {
            tracing::warn!(
                resid = %resid,
                version = %version,
                "Mapped manifest lacks root Kachina projection and byte-range fallback {index_start}..{} is not satisfiable ({message}); returning null metadata",
                data_end - 1
            );
            return Ok(None);
        }
        Err(e) => return Err(e),
    };

    if index_data.len() < expected_index_len {
        return Err(DfsError::NetworkError {
            reason: format!(
                "Truncated Kachina index range: expected {expected_index_len} bytes, got {}",
                index_data.len()
            ),
        });
    }

    // 解析索引数据
    let segments = parse_index_data(&index_data[..expected_index_len], index_start);

    if index_sz > 0 && segments.get("index").is_none() {
        return Err(DfsError::SerializationError {
            reason: "Kachina header declared non-empty index, but \\0INDEX segment is missing"
                .to_string(),
        });
    }
    if metadata_sz > 0 && segments.get("metadata").is_none() {
        return Err(DfsError::SerializationError {
            reason: "Kachina header declared non-empty metadata, but \\0META segment is missing"
                .to_string(),
        });
    }

    Ok(Some(KachinaMetadata {
        index: segments.get("index").cloned().unwrap_or_else(|| json!({})),
        metadata: segments
            .get("metadata")
            .cloned()
            .unwrap_or_else(|| json!({})),
        installer_end,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::mocks::TestEnvironment;
    use axum::{
        Router,
        extract::State,
        http::{HeaderMap, StatusCode, header},
        response::IntoResponse,
        routing::get,
    };
    use std::sync::Arc;

    fn build_tlv(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"!IN\0");
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn build_synthetic_pack() -> (Vec<u8>, u32) {
        let config_tlv = build_tlv("\0CONFIG", br#"{"appName":"Demo"}"#);
        let meta_tlv = build_tlv(
            "\0META",
            br#"{"tag_name":"0.68.0","hashed":[],"data_split_hint":[[0,128]]}"#,
        );

        // Build \0INDEX with one entry `abc` located right after \0META
        let entry_name = b"abc";
        let entry_header_len = 10 + entry_name.len() as u32;
        let pre_index_offset = (config_tlv.len() + meta_tlv.len()) as u32 + entry_header_len;
        let index_entry_len = 1 + entry_name.len() + 8;
        let index_tlv_len = (10 + "\0INDEX".len() + index_entry_len) as u32;
        let final_rel_offset = pre_index_offset + index_tlv_len;

        let mut index_payload = Vec::new();
        index_payload.push(entry_name.len() as u8);
        index_payload.extend_from_slice(entry_name);
        index_payload.extend_from_slice(&64u32.to_be_bytes());
        index_payload.extend_from_slice(&final_rel_offset.to_be_bytes());
        let index_tlv = build_tlv("\0INDEX", &index_payload);

        let base_end = 256u32;
        let mut base = vec![0u8; base_end as usize];
        let mut marker = b"!KachinaInstaller!".to_vec();
        marker.extend_from_slice(&base_end.to_be_bytes());
        marker.extend_from_slice(&(config_tlv.len() as u32).to_be_bytes());
        marker.extend_from_slice(&0u32.to_be_bytes());
        marker.extend_from_slice(&(index_tlv.len() as u32).to_be_bytes());
        marker.extend_from_slice(&(meta_tlv.len() as u32).to_be_bytes());
        base[64..64 + marker.len()].copy_from_slice(&marker);

        let mut pack = base;
        pack.extend_from_slice(&config_tlv);
        pack.extend_from_slice(&index_tlv);
        pack.extend_from_slice(&meta_tlv);
        pack.extend_from_slice(&build_tlv("abc", &[7u8; 64]));

        let expected_abs_offset = base_end + final_rel_offset;
        (pack, expected_abs_offset)
    }

    fn serve_range(headers: HeaderMap, data: &[u8]) -> axum::response::Response {
        if let Some(range_val) = headers.get(header::RANGE).and_then(|v| v.to_str().ok())
            && let Some(spec) = range_val.strip_prefix("bytes=")
            && let Some((s, e)) = spec.split_once('-')
            && let (Ok(start), Ok(end)) = (s.parse::<usize>(), e.parse::<usize>())
        {
            if start <= end && end < data.len() {
                let slice = data[start..=end].to_vec();
                return (
                    StatusCode::PARTIAL_CONTENT,
                    [(
                        header::CONTENT_RANGE,
                        format!("bytes {start}-{end}/{}", data.len()),
                    )],
                    slice,
                )
                    .into_response();
            }
            return StatusCode::RANGE_NOT_SATISFIABLE.into_response();
        }
        (StatusCode::OK, data.to_vec()).into_response()
    }

    #[tokio::test]
    async fn parse_kachina_metadata_reads_split_cas_pack_via_map_and_computes_raw_offset() {
        let (pack_bytes, expected_offset) = build_synthetic_pack();
        // Non-zero phys_offset=32 exercises physical Range header translation on internal fetches.
        let mut padded_blob = vec![0xEEu8; 32];
        padded_blob.extend_from_slice(&pack_bytes);
        let manifest = serde_json::json!({
            "size": pack_bytes.len() + 4096,
            "extents": [
                {
                    "offset": 0,
                    "len": pack_bytes.len(),
                    "phys_offset": 32,
                    "path": "cas/pack_blob"
                }
            ]
        })
        .to_string();

        let state = Arc::new((padded_blob, manifest));
        let app = Router::new()
            .route(
                "/bgi/app.json",
                get(|State(st): State<Arc<(Vec<u8>, String)>>| async move {
                    (StatusCode::OK, st.1.clone())
                }),
            )
            .route(
                "/bgi/cas/pack_blob",
                get(
                    |headers: HeaderMap, State(st): State<Arc<(Vec<u8>, String)>>| async move {
                        serve_range(headers, &st.0)
                    },
                ),
            )
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let yaml = format!(
            r#"
servers:
  map_srv:
    id: map_srv
    url: "http://{addr}"
    type: direct
plugins: {{}}
resources:
  bgi_split:
    latest: "0.68.0"
    resource_type: "file"
    download: "disabled"
    legacy_client_support: false
    legacy_client_full_range: false
    versions:
      default:
        default: "map:/bgi/app.json"
    tries: []
    server: ["map_srv"]
    flow:
      - use: ["server map_srv 10"]
"#
        );
        let mut config: crate::config::AppConfig = serde_yaml::from_str(&yaml).unwrap();
        for (id, scfg) in &config.servers {
            config.server_impl.insert(
                id.clone(),
                crate::modules::server::ServerImpl::new(scfg).unwrap(),
            );
        }
        let env = TestEnvironment::with_config(config).await;

        let parsed = parse_kachina_metadata(
            &env.shared_config,
            &env.services.flow_service,
            "bgi_split",
            "0.68.0",
            None,
        )
        .await
        .unwrap()
        .expect("kachina metadata parsed");

        assert_eq!(parsed.metadata["tag_name"], json!("0.68.0"));
        assert_eq!(parsed.metadata["data_split_hint"], json!([[0, 128]]));
        assert_eq!(parsed.index["abc"]["offset"], json!(expected_offset));
        assert_eq!(
            parsed.index["abc"]["raw_offset"],
            json!(expected_offset - 13)
        );
    }

    #[tokio::test]
    async fn parse_kachina_metadata_errors_on_416_instead_of_returning_none() {
        let app = Router::new().route(
            "/broken.exe",
            get(|| async { StatusCode::RANGE_NOT_SATISFIABLE }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let yaml = format!(
            r#"
servers:
  srv:
    id: srv
    url: "http://{addr}"
    type: direct
plugins: {{}}
resources:
  broken:
    latest: "1.0.0"
    versions:
      default:
        default: "/broken.exe"
    tries: []
    server: ["srv"]
    flow:
      - use: ["server srv 10"]
"#
        );
        let mut config: crate::config::AppConfig = serde_yaml::from_str(&yaml).unwrap();
        for (id, scfg) in &config.servers {
            config.server_impl.insert(
                id.clone(),
                crate::modules::server::ServerImpl::new(scfg).unwrap(),
            );
        }
        let env = TestEnvironment::with_config(config).await;
        env.data_store
            .set_health_info(
                "srv",
                "/broken.exe",
                &crate::modules::server::HealthInfo {
                    is_alive: true,
                    file_size: Some(1024),
                    last_check: chrono::Utc::now().timestamp() as u64,
                    observed_cert_hash: None,
                    content_hash: None,
                },
            )
            .await
            .unwrap();

        let res = parse_kachina_metadata(
            &env.shared_config,
            &env.services.flow_service,
            "broken",
            "1.0.0",
            None,
        )
        .await;
        assert!(res.is_err(), "416 must return Err rather than Ok(None)");
    }

    #[tokio::test]
    async fn parse_kachina_metadata_projects_root_fields_without_cas_range_requests() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let manifest_hits = Arc::new(AtomicUsize::new(0));
        let cas_hits = Arc::new(AtomicUsize::new(0));
        let manifest = json!({
            "size": 557344724u64,
            "extents": [
                { "offset": 0, "len": 1048576, "phys_offset": 0, "path": "cas/pack_head" }
            ],
            "installer_end": 9906541u32,
            "index": {
                "\u{0000}META": { "name": "\u{0000}META", "offset": 9906556, "raw_offset": 9906541, "size": 318303 },
                "Main.exe": { "name": "Main.exe", "offset": 10224877, "raw_offset": 10224859, "size": 65536 }
            },
            "metadata": {
                "repo_name": "BetterGI",
                "tag_name": "0.68.0",
                "data_split_hint": [[0, 60943141]]
            }
        })
        .to_string();

        let mh = Arc::clone(&manifest_hits);
        let ch = Arc::clone(&cas_hits);
        let app = Router::new()
            .route(
                "/bgi/0.68.0.json",
                get(move || {
                    let mh = Arc::clone(&mh);
                    let m = manifest.clone();
                    async move {
                        mh.fetch_add(1, Ordering::SeqCst);
                        (StatusCode::OK, m)
                    }
                }),
            )
            .route(
                "/bgi/cas/pack_head",
                get(move || {
                    let ch = Arc::clone(&ch);
                    async move {
                        ch.fetch_add(1, Ordering::SeqCst);
                        StatusCode::INTERNAL_SERVER_ERROR
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let yaml = format!(
            r#"
servers:
  map_srv:
    id: map_srv
    url: "http://{addr}"
    type: direct
plugins: {{}}
resources:
  bgi_split:
    latest: "0.68.0"
    resource_type: "file"
    download: "disabled"
    legacy_client_support: false
    legacy_client_full_range: false
    versions:
      default:
        default: "map:/bgi/0.68.0.json"
    tries: []
    server: ["map_srv"]
    flow:
      - use: ["server map_srv 10"]
"#
        );
        let mut config: crate::config::AppConfig = serde_yaml::from_str(&yaml).unwrap();
        for (id, scfg) in &config.servers {
            config.server_impl.insert(
                id.clone(),
                crate::modules::server::ServerImpl::new(scfg).unwrap(),
            );
        }
        let env = TestEnvironment::with_config(config).await;

        let parsed = parse_kachina_metadata(
            &env.shared_config,
            &env.services.flow_service,
            "bgi_split",
            "0.68.0",
            None,
        )
        .await
        .unwrap()
        .expect("projected metadata from root JSON");

        assert_eq!(parsed.installer_end, 9906541);
        assert_eq!(parsed.metadata["tag_name"], json!("0.68.0"));
        assert_eq!(parsed.metadata["data_split_hint"], json!([[0, 60943141]]));
        assert_eq!(parsed.index["Main.exe"]["raw_offset"], json!(10224859));
        assert_eq!(manifest_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            cas_hits.load(Ordering::SeqCst),
            0,
            "root-projected metadata must skip all CAS byte-range fetches"
        );

        // Bounds check: installer_end == 0 or installer_end > size must be rejected
        assert!(
            try_project_kachina_metadata(
                serde_json::json!({
                    "size": 1000,
                    "installer_end": 0,
                    "index": {},
                    "metadata": {}
                })
                .to_string()
                .as_bytes()
            )
            .is_none()
        );
        assert!(
            try_project_kachina_metadata(
                serde_json::json!({
                    "size": 1000,
                    "installer_end": 1001,
                    "index": {},
                    "metadata": {}
                })
                .to_string()
                .as_bytes()
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn parse_kachina_metadata_handles_tiny_416_and_rejects_range_ignoring_200() {
        let (pack_bytes, _) = build_synthetic_pack();
        let pack_arc = Arc::new(pack_bytes);
        let p_clone = Arc::clone(&pack_arc);
        let app = Router::new()
            .route(
                "/tiny.txt",
                get(|| async {
                    (
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        [(header::CONTENT_RANGE, "bytes */42")],
                    )
                }),
            )
            .route(
                "/ignore_range.exe",
                get(move || {
                    let b = (*p_clone).clone();
                    async move { (StatusCode::OK, b) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let yaml = format!(
            r#"
servers:
  srv:
    id: srv
    url: "http://{addr}"
    type: direct
plugins: {{}}
resources:
  tiny:
    latest: "1.0.0"
    versions:
      default:
        default: "/tiny.txt"
    tries: []
    server: ["srv"]
    flow:
      - use: ["server srv 10"]
  ignore_range:
    latest: "1.0.0"
    versions:
      default:
        default: "/ignore_range.exe"
    tries: []
    server: ["srv"]
    flow:
      - use: ["server srv 10"]
"#
        );
        let mut config: crate::config::AppConfig = serde_yaml::from_str(&yaml).unwrap();
        for (id, scfg) in &config.servers {
            config.server_impl.insert(
                id.clone(),
                crate::modules::server::ServerImpl::new(scfg).unwrap(),
            );
        }
        let env = TestEnvironment::with_config(config).await;
        let now = chrono::Utc::now().timestamp() as u64;
        for (path, sz) in [("/tiny.txt", 42u64), ("/ignore_range.exe", 4096u64)] {
            env.data_store
                .set_health_info(
                    "srv",
                    path,
                    &crate::modules::server::HealthInfo {
                        is_alive: true,
                        file_size: Some(sz),
                        last_check: now,
                        observed_cert_hash: None,
                        content_hash: None,
                    },
                )
                .await
                .unwrap();
        }

        let tiny_res = parse_kachina_metadata(
            &env.shared_config,
            &env.services.flow_service,
            "tiny",
            "1.0.0",
            None,
        )
        .await
        .expect("tiny <256B 416 with Content-Range must gracefully return Ok(None)");
        assert!(tiny_res.is_none());

        let ignore_res = parse_kachina_metadata(
            &env.shared_config,
            &env.services.flow_service,
            "ignore_range",
            "1.0.0",
            None,
        )
        .await;
        assert!(
            ignore_res.is_err(),
            "200 OK in response to Range header must be rejected instead of silently truncating from offset 0"
        );
    }
}
