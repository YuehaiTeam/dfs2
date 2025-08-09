use bytes::Bytes;
use serde_json::{Value, json};

use crate::config::SharedConfig;
use crate::container::REQWEST_CLIENT;
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

    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }

    None
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
            "Unreasonable size values detected: index_sz={}, config_sz={}, theme_sz={}, metadata_sz={}",
            index_sz, config_sz, theme_sz, metadata_sz
        ));
    }

    // 使用 checked_add 防止溢出
    let data_end = index_start
        .checked_add(index_sz)
        .and_then(|sum| sum.checked_add(config_sz))
        .and_then(|sum| sum.checked_add(theme_sz))
        .and_then(|sum| sum.checked_add(metadata_sz))
        .ok_or_else(|| format!(
            "Integer overflow when calculating data_end: index_start={}, index_sz={}, config_sz={}, theme_sz={}, metadata_sz={}",
            index_start, index_sz, config_sz, theme_sz, metadata_sz
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
    let request_file_size = if let Some(ref ranges) = ranges {
        Some(
            ranges
                .iter()
                .map(|(start, end)| (end - start + 1) as u64)
                .sum(),
        )
    } else {
        None // 没有range时不知道文件大小
    };

    // 构建新的Flow参数结构
    let target = FlowTarget {
        resource_id: resid.to_string(),
        version: version.to_string(),
        sub_path,
        ranges: ranges.clone(),
        file_size: request_file_size,
    };

    let context = FlowContext {
        client_ip: None, // Kachina解析通常不需要客户端IP信息
        session_id: None,
        extras: serde_json::json!({}),
    };

    let options = FlowOptions {
        cdn_full_range: false, // Kachina解析不使用全范围模式
    };

    // 执行Flow获取URL
    let flow_result = flow_service
        .execute_flow(&target, &context, &options, flow_list, vec![])
        .await?;
    let cdn_url = flow_result.url;

    // 构建 Range 头部
    let range_header = if let Some(ranges) = &ranges {
        if ranges.len() == 1 {
            format!("bytes={}-{}", ranges[0].0, ranges[0].1)
        } else {
            let range_parts: Vec<String> = ranges
                .iter()
                .map(|(start, end)| format!("{}-{}", start, end))
                .collect();
            format!("bytes={}", range_parts.join(","))
        }
    } else {
        // 如果没有指定范围，则获取整个文件
        "".to_string()
    };

    // 使用全局 HTTP 客户端下载文件
    let mut request = REQWEST_CLIENT.get(&cdn_url);

    if !range_header.is_empty() {
        request = request.header("Range", &range_header);
    }

    let response = match request.send().await {
        Ok(resp) => Ok(resp),
        Err(e) => Err(DfsError::NetworkError {
            reason: e.to_string(),
        }),
    }?;

    if !response.status().is_success()
        && response.status() != axum::http::StatusCode::PARTIAL_CONTENT
        && response.status() != axum::http::StatusCode::RANGE_NOT_SATISFIABLE
    {
        return Err(DfsError::NetworkError {
            reason: format!("{}: {}", E_READ_RESPONSE_FAILED, response.status()),
        });
    }

    match response.bytes().await {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(DfsError::NetworkError {
            reason: e.to_string(),
        }),
    }
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
                if let Ok(config_str) = String::from_utf8(data.to_vec()) {
                    if let Ok(config_json) = serde_json::from_str::<Value>(&config_str) {
                        segments["config"] = config_json;
                    }
                }
            }
            "\0META" => {
                if let Ok(meta_str) = String::from_utf8(data.to_vec()) {
                    if let Ok(meta_json) = serde_json::from_str::<Value>(&meta_str) {
                        segments["metadata"] = meta_json;
                    }
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

                    index_map[&file_name] = json!({
                        "name": file_name,
                        "offset": index_start + file_offset,
                        "raw_offset": 0,
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

/// 解析 KachinaInstaller 文件的元数据
///
/// # Arguments
/// * `config` - 应用配置
/// * `runner` - Flow运行器
/// * `resid` - 资源ID
/// * `version` - 版本（可选，默认使用latest）
///
/// # Returns
/// 返回 Result<Option<KachinaMetadata>, String>，成功时返回解析结果，None表示不是KachinaInstaller文件
pub async fn parse_kachina_metadata(
    shared_config: &SharedConfig,
    flow_service: &FlowService,
    resid: &str,
    version: &str,
    sub_path: Option<String>,
) -> DfsResult<Option<KachinaMetadata>> {
    // 获取文件的前256字节
    let header_bytes = fetch_file_range(
        shared_config,
        flow_service,
        resid,
        version,
        sub_path.clone(),
        Some(vec![(0, 255)]),
    )
    .await?;

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
    let data_end = index_start + index_sz + config_sz + theme_sz + metadata_sz;

    // 下载索引数据
    let index_data = fetch_file_range(
        shared_config,
        flow_service,
        resid,
        version,
        sub_path,
        Some(vec![(index_start, data_end - 1)]),
    )
    .await?;

    // 解析索引数据
    let segments = parse_index_data(&index_data, index_start);

    Ok(Some(KachinaMetadata {
        index: segments.get("index").cloned().unwrap_or_else(|| json!({})),
        metadata: segments
            .get("metadata")
            .cloned()
            .unwrap_or_else(|| json!({})),
        installer_end: index_start + config_sz + theme_sz,
    }))
}
