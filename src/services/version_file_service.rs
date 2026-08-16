use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::config::SharedConfig;
use crate::modules::server::HealthInfo;
use crate::modules::storage::cache::generate_etag;
use crate::modules::storage::data_store::{CacheMetadata, DataStore};
use crate::modules::version_file::{
    VERSION_FILE_MAX_BYTES, VersionFileDecision, VersionFileObservation, VersionFileView,
    apply_observations, evaluate_server, hash_content, view_storage_key,
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
}

impl VersionFileService {
    pub fn new(
        shared_config: SharedConfig,
        data_store: DataStore,
        resource_service: ResourceService,
    ) -> Self {
        Self {
            shared_config,
            data_store,
            resource_service,
        }
    }

    pub async fn start_background_task(self: Arc<Self>) {
        info!("Starting version-file census background task");
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(CENSUS_INTERVAL_SECONDS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(e) = self.census_all(false).await {
                    warn!("Version-file census cycle failed: {}", e);
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

    pub async fn census_all(&self, strict_split_fail: bool) -> Result<Vec<String>, String> {
        let config = self.shared_config.load();
        let mut errors = Vec::new();

        for (resource_id, resource) in &config.resources {
            if resource.version_files.is_empty() {
                continue;
            }
            match self.census_resource(resource_id, strict_split_fail).await {
                Ok(resource_errors) => errors.extend(resource_errors),
                Err(e) => errors.push(e),
            }
        }

        if errors.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(errors)
        }
    }

    pub async fn census_resource(
        &self,
        resource_id: &str,
        strict_split_fail: bool,
    ) -> Result<Vec<String>, String> {
        let config = self.shared_config.load();
        let resource = config
            .get_resource(resource_id)
            .ok_or_else(|| format!("resource '{resource_id}' not found"))?;

        if resource.version_files.is_empty() {
            return Ok(Vec::new());
        }

        let version = self
            .resource_service
            .get_effective_version(resource_id)
            .await
            .unwrap_or_else(|_| resource.latest.clone());
        let server_ids = collect_resource_server_ids(resource);
        let now = chrono::Utc::now().timestamp() as u64;
        let mut errors = Vec::new();

        for version_file in &resource.version_files {
            let Some(path) = version_file_path_for_resource(resource, &version, None, version_file)
            else {
                errors.push(format!(
                    "resource '{resource_id}' version file '{version_file}' could not be resolved"
                ));
                continue;
            };

            let mut observations = Vec::new();

            for server_id in &server_ids {
                let Some(server_impl) = config.get_server(server_id) else {
                    observations.push(VersionFileObservation {
                        server_id: server_id.clone(),
                        hash: None,
                        content: None,
                        file_size: None,
                        observed_cert_hash: None,
                    });
                    continue;
                };
                let Some(server_config) = config.servers.get(server_id) else {
                    observations.push(VersionFileObservation {
                        server_id: server_id.clone(),
                        hash: None,
                        content: None,
                        file_size: None,
                        observed_cert_hash: None,
                    });
                    continue;
                };

                let probe = server_impl
                    .fetch_small_file(
                        server_config,
                        &path,
                        Some(&self.data_store),
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

                observations.push(VersionFileObservation {
                    server_id: server_id.clone(),
                    hash,
                    content,
                    file_size: probe.file_size,
                    observed_cert_hash: probe.observed_cert_hash.clone(),
                });
            }

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

            if view.failed {
                errors.push(format!(
                    "resource '{resource_id}' version file '{version_file}' has no strict majority (responders={}, groups={:?})",
                    view.responder_count, view.groups
                ));
            } else if let Some(majority_hash) = &view.majority_hash {
                if resource.cache_enabled {
                    if let Some(content) = observations.iter().find_map(|obs| {
                        (obs.hash.as_deref() == Some(majority_hash.as_str()))
                            .then(|| obs.content.clone())
                            .flatten()
                    }) {
                        self.write_majority_cache(
                            resource_id,
                            &version,
                            &path,
                            resource.cache_max_age,
                            &content,
                        )
                        .await;
                    }
                }
            }

            debug!(
                "Version-file census {} {}: majority={:?} failed={} responders={}",
                resource_id, path, view.majority_hash, view.failed, view.responder_count
            );
        }

        Ok(errors)
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
