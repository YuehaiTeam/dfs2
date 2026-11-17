use crate::modules::server::s3::S3Signer;
use std::collections::HashSet;

const DEFAULT_PRESIGN_TTL: u32 = 900;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ToolGroup {
    Log,
    Config,
    Runtime,
    Metrics,
    /// 签发指向节点的下载 URL。
    Sign,
}

impl ToolGroup {
    const ALL: [Self; 5] = [
        Self::Log,
        Self::Config,
        Self::Runtime,
        Self::Metrics,
        Self::Sign,
    ];

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "log" => Some(Self::Log),
            "config" => Some(Self::Config),
            "runtime" => Some(Self::Runtime),
            "metrics" => Some(Self::Metrics),
            "sign" => Some(Self::Sign),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Config => "config",
            Self::Runtime => "runtime",
            Self::Metrics => "metrics",
            Self::Sign => "sign",
        }
    }
}

/// `All` 为未设 `MCP_TOOL_GROUPS`：全部组开。`Only` 只开列出的组。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnabledToolGroups {
    All,
    Only(HashSet<ToolGroup>),
}

impl EnabledToolGroups {
    pub fn allows(&self, group: ToolGroup) -> bool {
        match self {
            Self::All => true,
            Self::Only(set) => set.contains(&group),
        }
    }
}

#[derive(Clone)]
pub struct GrafanaSettings {
    pub url: String,
    pub token: String,
    pub datasource_uid: String,
    pub client: reqwest::Client,
}

#[derive(Clone)]
pub struct McpSettings {
    pub tokens: Vec<String>,
    pub prefix: String,
    pub log_signer: Option<S3Signer>,
    pub log_prefixes: Vec<String>,
    pub presign_ttl_seconds: u32,
    pub grafana: Option<GrafanaSettings>,
    pub config_mirror_url: Option<String>,
    pub playbook_path: Option<String>,
    pub tool_groups: EnabledToolGroups,
    /// OAuth issuer 与元数据里的外部 origin；设了才挂 OAuth 路由，401 才带 `WWW-Authenticate`。
    pub public_url: Option<String>,
}

#[derive(Clone)]
pub enum McpEnv {
    Disabled,
    Enabled(Box<McpSettings>),
}

pub fn load() -> Result<McpEnv, Vec<String>> {
    let token_raw = nonempty_env("MCP_TOKEN");
    let prefix_raw = nonempty_env("MCP_PREFIX");
    match (token_raw, prefix_raw) {
        (None, None) => {
            validate_optional_fragments(&mut Vec::new())?;
            Ok(McpEnv::Disabled)
        }
        (Some(_), None) => Err(vec!["MCP_TOKEN 已设置但缺少 MCP_PREFIX".to_string()]),
        (None, Some(_)) => Err(vec!["MCP_PREFIX 已设置但缺少 MCP_TOKEN".to_string()]),
        (Some(token_raw), Some(prefix_raw)) => {
            let mut errors = Vec::new();
            let tokens = parse_tokens(&token_raw);
            if tokens.is_empty() {
                errors.push("MCP_TOKEN 没有可用值".to_string());
            }
            if !is_safe_prefix(&prefix_raw) {
                errors.push("MCP_PREFIX 只允许 URL 安全字符且不能包含 /".to_string());
            }
            let settings = match build_enabled(&token_raw, &prefix_raw, &mut errors) {
                Some(s) => s,
                None => return Err(errors),
            };
            if errors.is_empty() {
                Ok(McpEnv::Enabled(Box::new(settings)))
            } else {
                Err(errors)
            }
        }
    }
}

pub fn validate_env() -> Result<(), Vec<String>> {
    load().map(|_| ())
}

impl McpSettings {
    pub fn token_matches(&self, provided: &str) -> bool {
        self.tokens.iter().any(|t| t == provided)
    }
}

fn build_enabled(token_raw: &str, prefix: &str, errors: &mut Vec<String>) -> Option<McpSettings> {
    let tokens = parse_tokens(token_raw);
    let grafana = parse_grafana(errors).unwrap_or_default();
    let log_signer = parse_log_signer(errors);
    let log_prefixes = parse_log_prefixes();
    let presign_ttl_seconds = parse_presign_ttl(errors);
    if !errors.is_empty() && tokens.is_empty() {
        return None;
    }
    Some(McpSettings {
        tokens,
        prefix: prefix.to_string(),
        log_signer,
        log_prefixes,
        presign_ttl_seconds,
        grafana,
        config_mirror_url: nonempty_env("MCP_CONFIG_MIRROR_URL"),
        playbook_path: nonempty_env("MCP_PLAYBOOK_PATH"),
        tool_groups: parse_tool_groups(errors),
        public_url: parse_public_url(errors),
    })
}

fn validate_optional_fragments(errors: &mut Vec<String>) -> Result<(), Vec<String>> {
    if nonempty_env("MCP_LOG_S3").is_some() {
        parse_log_signer(errors);
    }
    let g = [
        nonempty_env("MCP_GRAFANA_URL").is_some(),
        nonempty_env("MCP_GRAFANA_TOKEN").is_some(),
        nonempty_env("MCP_GRAFANA_DATASOURCE_UID").is_some(),
    ];
    if g.iter().any(|&x| x) && !g.iter().all(|&x| x) {
        errors.push("MCP_GRAFANA_URL / MCP_GRAFANA_TOKEN / MCP_GRAFANA_DATASOURCE_UID 必须三项齐全或全部不设".to_string());
    }
    let _ = parse_tool_groups(errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.clone())
    }
}

fn parse_grafana(errors: &mut Vec<String>) -> Result<Option<GrafanaSettings>, ()> {
    let url = nonempty_env("MCP_GRAFANA_URL");
    let token = nonempty_env("MCP_GRAFANA_TOKEN");
    let uid = nonempty_env("MCP_GRAFANA_DATASOURCE_UID");
    match (url, token, uid) {
        (None, None, None) => Ok(None),
        (Some(url), Some(token), Some(datasource_uid)) => {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    errors.push(format!("无法建立指标查询客户端: {e}"));
                })?;
            Ok(Some(GrafanaSettings {
                url,
                token,
                datasource_uid,
                client,
            }))
        }
        _ => {
            errors.push(
                "MCP_GRAFANA_URL / MCP_GRAFANA_TOKEN / MCP_GRAFANA_DATASOURCE_UID 必须三项齐全或全部不设"
                    .to_string(),
            );
            Err(())
        }
    }
}

fn parse_log_signer(errors: &mut Vec<String>) -> Option<S3Signer> {
    let url = nonempty_env("MCP_LOG_S3").or_else(|| nonempty_env("SESSION_LOG_ARCHIVE_S3"));
    match url {
        None => None,
        Some(url) => match S3Signer::from_url(&url) {
            Ok(signer) => Some(signer),
            Err(e) => {
                errors.push(format!("MCP_LOG_S3 / SESSION_LOG_ARCHIVE_S3 无法解析: {e}"));
                None
            }
        },
    }
}

fn parse_log_prefixes() -> Vec<String> {
    let mut prefixes = Vec::new();
    if let Some(own) = nonempty_env("SESSION_LOG_ARCHIVE_PREFIX") {
        prefixes.push(own);
    }
    if let Some(raw) = nonempty_env("MCP_LOG_PREFIXES") {
        for part in raw.split(',') {
            let part = part.trim();
            if !part.is_empty() && !prefixes.iter().any(|p| p == part) {
                prefixes.push(part.to_string());
            }
        }
    }
    prefixes
}

fn parse_presign_ttl(errors: &mut Vec<String>) -> u32 {
    match nonempty_env("MCP_PRESIGN_TTL_SECONDS") {
        None => DEFAULT_PRESIGN_TTL,
        Some(raw) => match raw.parse::<u32>() {
            Ok(n) if n > 0 => n,
            _ => {
                errors.push("MCP_PRESIGN_TTL_SECONDS 必须是正整数".to_string());
                DEFAULT_PRESIGN_TTL
            }
        },
    }
}

fn parse_tool_groups(errors: &mut Vec<String>) -> EnabledToolGroups {
    let Some(raw) = nonempty_env("MCP_TOOL_GROUPS") else {
        return EnabledToolGroups::All;
    };
    let mut set = HashSet::new();
    let mut unknown = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match ToolGroup::parse(part) {
            Some(group) => {
                set.insert(group);
            }
            None => unknown.push(part.to_string()),
        }
    }
    if !unknown.is_empty() {
        errors.push(format!(
            "MCP_TOOL_GROUPS 含未知组: {}；可用: {}",
            unknown.join(", "),
            ToolGroup::ALL
                .iter()
                .map(|g| g.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    } else if set.is_empty() {
        errors.push("MCP_TOOL_GROUPS 没有可用值".to_string());
    }
    if set.is_empty() {
        EnabledToolGroups::All
    } else {
        EnabledToolGroups::Only(set)
    }
}

fn parse_public_url(errors: &mut Vec<String>) -> Option<String> {
    let raw = nonempty_env("MCP_PUBLIC_URL")?;
    match url::Url::parse(&raw) {
        Ok(u)
            if matches!(u.scheme(), "http" | "https")
                && u.host_str().is_some()
                && u.query().is_none()
                && u.fragment().is_none() =>
        {
            Some(raw.trim_end_matches('/').to_string())
        }
        _ => {
            errors.push("MCP_PUBLIC_URL 必须是不带 query 的 http(s) 地址".to_string());
            None
        }
    }
}

fn parse_tokens(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .take(2)
        .map(str::to_string)
        .collect()
}

fn is_safe_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn clear_mcp_env() {
        for key in [
            "MCP_TOKEN",
            "MCP_PREFIX",
            "MCP_LOG_S3",
            "MCP_LOG_PREFIXES",
            "MCP_PRESIGN_TTL_SECONDS",
            "MCP_GRAFANA_URL",
            "MCP_GRAFANA_TOKEN",
            "MCP_GRAFANA_DATASOURCE_UID",
            "MCP_CONFIG_MIRROR_URL",
            "MCP_PLAYBOOK_PATH",
            "MCP_TOOL_GROUPS",
            "MCP_PUBLIC_URL",
            "SESSION_LOG_ARCHIVE_S3",
            "SESSION_LOG_ARCHIVE_PREFIX",
            "SESSION_LOG_ROTATE_HOURS",
        ] {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn disabled_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        assert!(matches!(load().unwrap(), McpEnv::Disabled));
    }

    #[test]
    fn half_set_is_error() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe { std::env::set_var("MCP_TOKEN", "t") };
        assert!(load().is_err());
        unsafe { std::env::remove_var("MCP_TOKEN") };
        unsafe { std::env::set_var("MCP_PREFIX", "abc") };
        assert!(load().is_err());
        clear_mcp_env();
    }

    #[test]
    fn prefix_rejects_slash() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "a/b");
        }
        assert!(load().is_err());
        clear_mcp_env();
    }

    #[test]
    fn grafana_partial_errors() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
            std::env::set_var("MCP_GRAFANA_URL", "http://metrics.example");
        }
        assert!(load().is_err());
        clear_mcp_env();
    }

    #[test]
    fn two_tokens_match() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "old,new");
            std::env::set_var("MCP_PREFIX", "abc");
        }
        match load().unwrap() {
            McpEnv::Enabled(s) => {
                assert!(s.token_matches("old"));
                assert!(s.token_matches("new"));
                assert!(!s.token_matches("other"));
            }
            McpEnv::Disabled => panic!("expected enabled"),
        }
        clear_mcp_env();
    }

    #[test]
    fn unparsable_log_s3_is_error() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
            std::env::set_var("MCP_LOG_S3", "not-a-url");
        }
        assert!(load().is_err());
        clear_mcp_env();
    }

    #[test]
    fn tool_groups_unset_is_all() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
        }
        match load().unwrap() {
            McpEnv::Enabled(s) => assert_eq!(s.tool_groups, EnabledToolGroups::All),
            McpEnv::Disabled => panic!("expected enabled"),
        }
        clear_mcp_env();
    }

    #[test]
    fn tool_groups_allowlist_parses() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
            std::env::set_var("MCP_TOOL_GROUPS", "runtime, log, runtime");
        }
        match load().unwrap() {
            McpEnv::Enabled(s) => {
                assert_eq!(
                    s.tool_groups,
                    EnabledToolGroups::Only(HashSet::from([ToolGroup::Runtime, ToolGroup::Log]))
                );
                assert!(s.tool_groups.allows(ToolGroup::Runtime));
                assert!(!s.tool_groups.allows(ToolGroup::Config));
            }
            McpEnv::Disabled => panic!("expected enabled"),
        }
        clear_mcp_env();
    }

    #[test]
    fn tool_groups_unknown_is_error() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
            std::env::set_var("MCP_TOOL_GROUPS", "runtime,nope");
        }
        let Err(err) = load() else {
            panic!("expected error");
        };
        assert!(
            err.iter()
                .any(|e| e.contains("未知组") && e.contains("nope")),
            "{err:?}"
        );
        clear_mcp_env();
    }

    #[test]
    fn tool_groups_empty_is_error() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
            std::env::set_var("MCP_TOOL_GROUPS", " , , ");
        }
        let Err(err) = load() else {
            panic!("expected error");
        };
        assert!(err.iter().any(|e| e.contains("没有可用值")), "{err:?}");
        clear_mcp_env();
    }

    #[test]
    fn public_url_trims_slash_and_rejects_non_http() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe {
            std::env::set_var("MCP_TOKEN", "t");
            std::env::set_var("MCP_PREFIX", "abc");
            std::env::set_var("MCP_PUBLIC_URL", "https://dfs.example.com/");
        }
        match load().unwrap() {
            McpEnv::Enabled(s) => {
                assert_eq!(s.public_url.as_deref(), Some("https://dfs.example.com"))
            }
            McpEnv::Disabled => panic!("expected enabled"),
        }
        unsafe { std::env::set_var("MCP_PUBLIC_URL", "ftp://dfs.example.com") };
        let Err(err) = load() else {
            panic!("expected error");
        };
        assert!(err.iter().any(|e| e.contains("MCP_PUBLIC_URL")), "{err:?}");
        clear_mcp_env();
    }

    #[test]
    fn tool_groups_unknown_errors_when_mcp_disabled() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_mcp_env();
        unsafe { std::env::set_var("MCP_TOOL_GROUPS", "nope") };
        assert!(load().is_err());
        clear_mcp_env();
    }
}
