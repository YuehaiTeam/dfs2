use axum::{Router, routing::get};

pub mod batch;
pub mod chunk;
pub mod downloads;
pub mod metadata;
pub mod sessions;

// 解析range字符串为flowrunner的ranges格式
// "0-" 或整个文件 -> None
// "1024-2047" 等具体范围 -> Some(vec![(start, end)])
pub fn parse_range_for_flow(range_str: &str) -> Option<Vec<(u32, u32)>> {
    let parts: Vec<&str> = range_str.split('-').collect();
    if parts.len() != 2 {
        return None;
    }

    let start = parts[0].parse::<u32>().ok()?;

    // 如果是 "0-" 格式（从开头到结尾），返回 None 表示整个文件
    if parts[1].is_empty() && start == 0 {
        return None;
    }

    let end = if parts[1].is_empty() {
        // 其他 "X-" 格式，表示从X到文件末尾
        u32::MAX
    } else {
        parts[1].parse::<u32>().ok()?
    };

    Some(vec![(start, end)])
}

// 计算range覆盖的实际字节数
pub fn calculate_actual_bytes_from_range(range_str: Option<&str>, full_file_size: u64) -> u64 {
    if let Some(range_str) = range_str {
        if let Some(ranges) = parse_range_for_flow(range_str) {
            // 有具体range，计算range覆盖的字节数
            ranges
                .iter()
                .map(|(start, end)| {
                    if *end == u32::MAX {
                        // "X-" 格式，从start到文件结尾
                        full_file_size.saturating_sub(*start as u64)
                    } else {
                        // "X-Y" 格式，计算范围大小
                        (*end as u64).saturating_sub(*start as u64) + 1
                    }
                })
                .sum()
        } else {
            // parse_range_for_flow返回None表示整个文件("0-")
            full_file_size
        }
    } else {
        // 没有range参数，整个文件
        full_file_size
    }
}

// 宏用于记录请求指标
#[macro_export]
macro_rules! record_request_metrics {
    ($metrics:expr, $start_time:expr) => {
        $metrics.record_request();
        $metrics.record_request_duration($start_time.elapsed().as_secs_f64());
    };
}

// 宏用于记录流程执行指标
#[macro_export]
macro_rules! record_flow_metrics {
    ($metrics:expr, $success:expr) => {
        $metrics.record_flow_execution();
        if !$success {
            $metrics.record_flow_failure();
        }
    };
}

// 路由设置
pub fn routes() -> Router {
    Router::new()
        .route(
            "/resource/{resid}",
            get(metadata::get_metadata).post(sessions::create_session),
        )
        .route(
            "/resource/{resid}/{*sub_path}",
            get(metadata::get_prefix_metadata).post(sessions::create_prefix_session),
        )
        .route(
            "/session/{sessionid}/{resid}",
            get(chunk::get_cdn)
                .post(batch::post_batch_cdn)
                .delete(sessions::delete_session),
        )
        .route(
            "/download/{resid}",
            get(downloads::download_redirect).post(downloads::download_json),
        )
        .route(
            "/download/{resid}/{*sub_path}",
            get(downloads::download_prefix_redirect).post(downloads::download_prefix_json),
        )
}
