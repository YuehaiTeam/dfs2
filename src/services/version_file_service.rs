use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::SharedConfig;
use crate::metrics::Metrics;
use crate::modules::server::HealthInfo;
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

#[derive(Clone)]
pub struct VersionFileService {
    shared_config: SharedConfig,
    data_store: DataStore,
    resource_service: ResourceService,
    /// CLI 校验路径没有 metrics registry，此时不上报
    metrics: Option<Arc<Metrics>>,
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
        }
    }

    pub async fn start_background_task(self: Arc<Self>) {
        info!("Starting version-file census background task");
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CENSUS_INTERVAL_SECONDS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                match self.census_all(false, &HashSet::new()).await {
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

    pub async fn census_all(
        &self,
        strict_split_fail: bool,
        skip_server_ids: &HashSet<String>,
    ) -> Result<CensusReport, String> {
        let config = self.shared_config.load();
        let mut report = CensusReport::default();

        if let Some(metrics) = &self.metrics {
            metrics.reset_version_file_consistency();
        }

        for (resource_id, resource) in &config.resources {
            if resource.version_files.is_empty() {
                continue;
            }
            match self
                .census_resource(resource_id, strict_split_fail, skip_server_ids)
                .await
            {
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
        let mut report = CensusReport::default();
        let mut mismatch_counts: HashMap<String, u64> =
            server_ids.iter().map(|id| (id.clone(), 0)).collect();
        let mut no_majority_paths: u64 = 0;

        for version_file in &resource.version_files {
            let Some(path) = version_file_path_for_resource(resource, &version, None, version_file)
            else {
                report.errors.push(format!(
                    "resource '{resource_id}' version file '{version_file}' could not be resolved"
                ));
                continue;
            };

            let observations = self
                .collect_observations(&server_ids, &path, skip_server_ids)
                .await;

            let previous = self.get_view(resource_id, &path).await;
            let view = apply_observations(
                previous.as_ref(),
                &observations,
                now,
                resource.version_file_split_ttl,
                strict_split_fail,
            );

            self.store_view(resource_id, &path, &view).await?;
            self.update_server_health(&observations, &view, &path, now)
                .await;

            // split_since 只在当前不存在严格多数派时有值，宽限期内的分裂也算
            if view.split_since.is_some() {
                no_majority_paths += 1;
            }
            for server_id in mismatched_servers(&view) {
                *mismatch_counts.entry(server_id).or_insert(0) += 1;
            }

            report.extend(report_view(
                resource_id,
                version_file,
                &view,
                strict_split_fail,
            ));

            if !view.failed {
                if let Some(majority_hash) = &view.majority_hash {
                    if resource.cache_enabled {
                        if let Some((source_server, content)) =
                            observations.iter().find_map(|obs| {
                                (obs.hash.as_deref() == Some(majority_hash.as_str()))
                                    .then(|| obs.content.clone())
                                    .flatten()
                                    .map(|content| (obs.server_id.as_str(), content))
                            })
                        {
                            self.write_majority_cache(
                                resource_id,
                                &version,
                                &path,
                                resource.cache_max_age,
                                &content,
                                source_server,
                            )
                            .await;
                        }
                    }
                }
            }

            debug!(
                "Version-file census {} {}: majority={:?} failed={} responders={}",
                resource_id, path, view.majority_hash, view.failed, view.responder_count
            );
        }

        if let Some(metrics) = &self.metrics {
            for (server_id, files) in &mismatch_counts {
                metrics.set_version_file_mismatch_files(server_id, resource_id, *files);
            }
            metrics.set_version_file_no_majority(resource_id, no_majority_paths);
        }

        Ok(report)
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

        let semaphore = Arc::new(tokio::sync::Semaphore::new(PROBE_CONCURRENCY));
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
