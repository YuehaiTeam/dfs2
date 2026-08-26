use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::{ResourceConfig, SharedConfig};
use crate::metrics::Metrics;
use crate::modules::server::{HealthInfo, ping_servers};
use crate::modules::storage::cache::generate_etag;
use crate::modules::storage::data_store::{CacheMetadata, DataStore};
use crate::modules::version_file::{
    CensusReport, PROBE_CONCURRENCY, VERSION_FILE_MAX_BYTES, VersionFileDecision,
    VersionFileObservation, VersionFileView, apply_observations, evaluate_server, hash_content,
    mismatched_servers, report_view, view_storage_key,
};
use crate::services::resource_service::{
    ResourceService, collect_resource_server_ids, version_file_path_for_resource,
};

const VIEW_TTL_SECONDS: u32 = 86400;
const CENSUS_INTERVAL_SECONDS: u64 = 180;

/// 单条版本文件路径的普查结果，供资源层汇总为指标。
#[derive(Default)]
struct PathCensus {
    report: CensusReport,
    /// 当前不存在严格多数派，含宽限期内的分裂
    no_majority: bool,
    /// 本轮没有任何节点返回内容
    no_responders: bool,
    /// 与多数派不一致的节点
    mismatched: Vec<String>,
}

#[derive(Clone)]
pub struct VersionFileService {
    shared_config: SharedConfig,
    data_store: DataStore,
    resource_service: ResourceService,
    /// CLI 校验路径没有 metrics registry，此时不上报
    metrics: Option<Arc<Metrics>>,
    /// 全服务共用，约束的是在飞探测总数。资源与路径两层都并发之后，若每条路径各建一个信号量，
    /// 实际并发会变成 PROBE_CONCURRENCY 乘以并发路径数。
    probe_semaphore: Arc<tokio::sync::Semaphore>,
}

impl VersionFileService {
    pub fn new(
        shared_config: SharedConfig,
        data_store: DataStore,
        resource_service: ResourceService,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            shared_config,
            data_store,
            resource_service,
            metrics,
            probe_semaphore: Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY)),
        }
    }

    /// 后台任务的首个 tick 立即触发，因此首轮普查由这里承担，启动路径不再等待它。
    pub async fn start_background_task(self: Arc<Self>) {
        info!("Starting version-file census background task");
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CENSUS_INTERVAL_SECONDS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                match self.ping_and_census_all(false).await {
                    Ok(report) => {
                        for error in &report.errors {
                            warn!("Version-file census: {}", error);
                        }
                        for warning in &report.warnings {
                            warn!("Version-file census: {}", warning);
                        }
                    }
                    Err(e) => warn!("Version-file census cycle failed: {}", e),
                }
            }
        });
    }

    pub async fn get_view(&self, resource_id: &str, path: &str) -> Option<VersionFileView> {
        let key = view_storage_key(resource_id, path);
        let raw = self.data_store.get_string(&key).await.ok().flatten()?;
        serde_json::from_str(&raw).ok()
    }

    pub async fn evaluate_path(
        &self,
        resource_id: &str,
        path: &str,
        server_id: &str,
    ) -> VersionFileDecision {
        match self.get_view(resource_id, path).await {
            Some(view) => evaluate_server(&view, server_id),
            None => VersionFileDecision::Unknown,
        }
    }

    pub async fn is_split_failed(&self, resource_id: &str, path: &str) -> bool {
        self.get_view(resource_id, path)
            .await
            .is_some_and(|view| view.failed)
    }

    pub async fn resolved_version_file_paths(
        &self,
        resource_id: &str,
        version: &str,
    ) -> Vec<String> {
        let config = self.shared_config.load();
        let Some(resource) = config.get_resource(resource_id) else {
            return Vec::new();
        };
        resource
            .version_files
            .iter()
            .filter_map(|version_file| {
                version_file_path_for_resource(resource, version, None, version_file)
            })
            .collect()
    }

    pub async fn is_version_file_request(
        &self,
        resource_id: &str,
        version: &str,
        path: &str,
    ) -> bool {
        self.resolved_version_file_paths(resource_id, version)
            .await
            .iter()
            .any(|candidate| candidate == path)
    }

    /// 先实测连通性，再普查，不可达的节点整轮跳过。
    ///
    /// 没有这一步时，一个不可达节点会在每条版本文件路径上各付一次连接超时，单轮耗时按
    /// 节点数乘路径数增长；ping 只按节点数付一次。
    pub async fn ping_and_census_all(
        &self,
        strict_split_fail: bool,
    ) -> Result<CensusReport, String> {
        let ping = {
            let config = self.shared_config.load();
            ping_servers(&config, PROBE_CONCURRENCY).await
        };

        for server_id in &ping.implementation_missing {
            warn!(
                "Version-file census: 服务器 '{}' 配置了健康检查路径但无法构造实现",
                server_id
            );
        }

        let unreachable = ping.unreachable();
        if !unreachable.is_empty() {
            let mut skipped: Vec<&str> = unreachable.iter().map(String::as_str).collect();
            skipped.sort_unstable();
            info!(
                "Version-file census skipping {} unreachable server(s): {} ({} alive)",
                skipped.len(),
                skipped.join(", "),
                ping.alive_count()
            );
        }

        self.census_all(strict_split_fail, &unreachable).await
    }

    pub async fn census_all(
        &self,
        strict_split_fail: bool,
        skip_server_ids: &HashSet<String>,
    ) -> Result<CensusReport, String> {
        let config = self.shared_config.load();

        if let Some(metrics) = &self.metrics {
            metrics.reset_version_file_consistency();
        }

        let resource_results = futures::future::join_all(
            config
                .resources
                .iter()
                .filter(|(_, resource)| !resource.version_files.is_empty())
                .map(|(resource_id, _)| {
                    self.census_resource(resource_id, strict_split_fail, skip_server_ids)
                }),
        )
        .await;

        let mut report = CensusReport::default();
        for resource_result in resource_results {
            match resource_result {
                Ok(resource_report) => report.extend(resource_report),
                Err(e) => report.errors.push(e),
            }
        }

        Ok(report)
    }

    pub async fn census_resource(
        &self,
        resource_id: &str,
        strict_split_fail: bool,
        skip_server_ids: &HashSet<String>,
    ) -> Result<CensusReport, String> {
        let config = self.shared_config.load();
        let resource = config
            .get_resource(resource_id)
            .ok_or_else(|| format!("resource '{resource_id}' not found"))?;

        if resource.version_files.is_empty() {
            return Ok(CensusReport::default());
        }

        let version = self
            .resource_service
            .get_effective_version(resource_id)
            .await
            .unwrap_or_else(|_| resource.latest.clone());
        let server_ids = collect_resource_server_ids(resource);
        let now = chrono::Utc::now().timestamp() as u64;

        let path_results =
            futures::future::join_all(resource.version_files.iter().map(|version_file| {
                self.census_path(
                    resource_id,
                    resource,
                    &version,
                    &server_ids,
                    version_file,
                    now,
                    strict_split_fail,
                    skip_server_ids,
                )
            }))
            .await;

        let mut report = CensusReport::default();
        let mut mismatch_counts: HashMap<String, u64> =
            server_ids.iter().map(|id| (id.clone(), 0)).collect();
        let mut no_majority_paths: u64 = 0;
        let mut no_responder_paths: u64 = 0;

        for path_result in path_results {
            report.extend(path_result.report);
            if path_result.no_majority {
                no_majority_paths += 1;
            }
            if path_result.no_responders {
                no_responder_paths += 1;
            }
            for server_id in path_result.mismatched {
                *mismatch_counts.entry(server_id).or_insert(0) += 1;
            }
        }

        if let Some(metrics) = &self.metrics {
            for (server_id, files) in &mismatch_counts {
                metrics.set_version_file_mismatch_files(server_id, resource_id, *files);
            }
            metrics.set_version_file_no_majority(resource_id, no_majority_paths);
            metrics.set_version_file_no_responders(resource_id, no_responder_paths);
        }

        Ok(report)
    }

    /// 普查单条版本文件路径。
    ///
    /// 路径之间没有共享状态，因此同资源下的多条路径并发执行，汇总由调用方做。
    #[allow(clippy::too_many_arguments)]
    async fn census_path(
        &self,
        resource_id: &str,
        resource: &ResourceConfig,
        version: &str,
        server_ids: &[String],
        version_file: &str,
        now: u64,
        strict_split_fail: bool,
        skip_server_ids: &HashSet<String>,
    ) -> PathCensus {
        let mut result = PathCensus::default();

        let Some(path) = version_file_path_for_resource(resource, version, None, version_file)
        else {
            result.report.errors.push(format!(
                "resource '{resource_id}' version file '{version_file}' could not be resolved"
            ));
            return result;
        };

        let observations = self
            .collect_observations(server_ids, &path, skip_server_ids)
            .await;

        let previous = self.get_view(resource_id, &path).await;
        let view = apply_observations(
            previous.as_ref(),
            &observations,
            now,
            resource.version_file_split_ttl,
            strict_split_fail,
        );

        if let Err(e) = self.store_view(resource_id, &path, &view).await {
            // 一条路径存储失败不应连带中断同资源下的其它路径
            result.report.errors.push(format!(
                "resource '{resource_id}' version file '{version_file}' view could not be stored: {e}"
            ));
        }
        self.update_server_health(&observations, &view, &path, now)
            .await;

        // split_since 只在当前不存在严格多数派时有值，宽限期内的分裂也算。无响应者时 split_since
        // 是从上一轮继承来的，不代表本轮观测到分歧，因此两个信号保持互斥，各自在看板上可直读。
        result.no_responders = view.responder_count == 0;
        result.no_majority = view.split_since.is_some() && !result.no_responders;
        result.mismatched = mismatched_servers(&view);
        result.report.extend(report_view(
            resource_id,
            version_file,
            &view,
            strict_split_fail,
        ));

        if !view.failed
            && resource.cache_enabled
            && let Some(majority_hash) = &view.majority_hash
            && let Some((source_server, content)) = observations.iter().find_map(|obs| {
                (obs.hash.as_deref() == Some(majority_hash.as_str()))
                    .then(|| obs.content.clone())
                    .flatten()
                    .map(|content| (obs.server_id.as_str(), content))
            })
        {
            self.write_majority_cache(
                resource_id,
                version,
                &path,
                resource.cache_max_age,
                &content,
                source_server,
            )
            .await;
        }

        debug!(
            "Version-file census {} {}: majority={:?} failed={} responders={}",
            resource_id, path, view.majority_hash, view.failed, view.responder_count
        );

        result
    }

    async fn collect_observations(
        &self,
        server_ids: &[String],
        path: &str,
        skip_server_ids: &HashSet<String>,
    ) -> Vec<VersionFileObservation> {
        let config = self.shared_config.load();
        let mut observations = Vec::new();
        let mut to_probe = Vec::new();

        for server_id in server_ids {
            if skip_server_ids.contains(server_id) {
                observations.push(empty_observation(server_id));
                continue;
            }
            match (config.get_server(server_id), config.servers.get(server_id)) {
                (Some(server_impl), Some(server_config)) => {
                    to_probe.push((
                        server_id.clone(),
                        server_impl.clone(),
                        server_config.clone(),
                    ));
                }
                _ => observations.push(empty_observation(server_id)),
            }
        }

        if to_probe.is_empty() {
            return observations;
        }

        let semaphore = self.probe_semaphore.clone();
        let path = path.to_string();
        let data_store = self.data_store.clone();
        let probed = futures::future::join_all(to_probe.into_iter().map(
            |(server_id, server_impl, server_config)| {
                let semaphore = semaphore.clone();
                let path = path.clone();
                let data_store = data_store.clone();
                async move {
                    let _permit = semaphore.acquire().await.ok();
                    let probe = server_impl
                        .fetch_small_file(
                            &server_config,
                            &path,
                            Some(&data_store),
                            VERSION_FILE_MAX_BYTES,
                        )
                        .await;
                    let (hash, content) = match probe.body {
                        Some(body) => {
                            let hash = hash_content(&body);
                            (Some(hash), Some(body))
                        }
                        None => (None, None),
                    };
                    VersionFileObservation {
                        server_id,
                        hash,
                        content,
                        file_size: probe.file_size,
                        observed_cert_hash: probe.observed_cert_hash,
                    }
                }
            },
        ))
        .await;
        observations.extend(probed);
        observations
    }

    async fn store_view(
        &self,
        resource_id: &str,
        path: &str,
        view: &VersionFileView,
    ) -> Result<(), String> {
        let key = view_storage_key(resource_id, path);
        let json = serde_json::to_string(view).map_err(|e| e.to_string())?;
        self.data_store
            .set_string(&key, &json, Some(VIEW_TTL_SECONDS))
            .await
    }

    async fn update_server_health(
        &self,
        observations: &[VersionFileObservation],
        view: &VersionFileView,
        path: &str,
        now: u64,
    ) {
        for obs in observations {
            let decision = evaluate_server(view, &obs.server_id);
            let is_alive = matches!(decision, VersionFileDecision::Match) && obs.hash.is_some();
            let health = HealthInfo {
                is_alive,
                file_size: obs.file_size,
                last_check: now,
                observed_cert_hash: obs.observed_cert_hash.clone(),
                content_hash: obs.hash.clone(),
            };
            let _ = self
                .data_store
                .set_health_info(&obs.server_id, path, &health)
                .await;
        }
    }

    async fn write_majority_cache(
        &self,
        resource_id: &str,
        version: &str,
        path: &str,
        max_age: u32,
        content: &[u8],
        source_server: &str,
    ) {
        let keys = self
            .data_store
            .generate_cache_keys(resource_id, version, path);
        let content_type = if path.ends_with(".json") {
            Some("application/json".to_string())
        } else {
            Some("application/octet-stream".to_string())
        };
        let metadata = CacheMetadata {
            cached_at: chrono::Utc::now().timestamp() as u64,
            max_age,
            content_length: content.len() as u64,
            content_type,
            etag: generate_etag(content),
            src: Some(source_server.to_string()),
        };
        if let Err(e) = self
            .data_store
            .set_cache_entry(&keys.metadata_key, &keys.content_key, &metadata, content)
            .await
        {
            warn!(
                "Failed to write majority version-file cache for {} {}: {}",
                resource_id, path, e
            );
        }
    }
}

fn empty_observation(server_id: &str) -> VersionFileObservation {
    VersionFileObservation {
        server_id: server_id.to_string(),
        hash: None,
        content: None,
        file_size: None,
        observed_cert_hash: None,
    }
}
