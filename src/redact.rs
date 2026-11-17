//! 文本级凭据脱敏：先从全部 YAML 收集值，再改写并核对输出里不再出现这些值。
//!
//! 规则与历史 Python 镜像脚本一致：URL userinfo 换成 `*:*@`；YAML 中键名含
//! password / secret / token 等的行值换成 `'*'`；长度不足 6 或在白名单里的值不动。
//! 凭据值只留在内存。

use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use thiserror::Error;

const MIN_SECRET_LEN: usize = 6;
const TEXT_MAX_BYTES: usize = 4 * 1024 * 1024;
const BENIGN: &[&str] = &[
    "", "*", "dfsuser", "trust", "true", "false", "null", "none", "main", "master", "enabled",
    "disabled", "free", "file", "prefix", "username", "password",
];

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Leak(String),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn is_leak(&self) -> bool {
        matches!(self, Self::Leak(_))
    }
}

fn sensitive_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)^(?P<head>\s*(?:-\s+)?['"]?(?P<key>\w*(?:password|passwd|secret|token|authorization|license|access_key|secret_key|api_key|private_key|credential)\w*)['"]?\s*:\s*)(?P<val>.+?)(?P<tail>\s*(?:#.*)?)$"#,
        )
        .expect("sensitive key regex")
    })
}

fn url_hits(text: &str) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    let bytes = text.as_bytes();
    let mut search = 0;
    while let Some(rel) = text[search..].find("://") {
        let sep = search + rel;
        let mut scheme = sep;
        while scheme > 0 {
            let ch = bytes[scheme - 1];
            if ch.is_ascii_alphanumeric() || ch == b'+' || ch == b'.' || ch == b'-' {
                scheme -= 1;
            } else {
                break;
            }
        }
        if scheme == sep || !bytes[scheme].is_ascii_alphabetic() {
            search = sep + 3;
            continue;
        }
        let after = sep + 3;
        let rest = &text[after..];
        let rest_end = rest
            .find(['?', '#', '\'', '"', '\n', '\r', '\t', ' '])
            .unwrap_or(rest.len());
        let before = &rest[..rest_end];
        if let Some(at) = before.rfind('@') {
            hits.push((after, after + at));
        }
        search = after;
    }
    hits
}

fn strip_value(raw: &str) -> String {
    let mut v = raw.trim().to_string();
    let bytes = v.as_bytes();
    if bytes.len() >= 2
        && bytes[0] == bytes[bytes.len() - 1]
        && (bytes[0] == b'\'' || bytes[0] == b'"')
    {
        v = v[1..v.len() - 1].to_string();
        v = v.trim().to_string();
    }
    v
}

fn is_secret_value(v: &str) -> bool {
    v.len() >= MIN_SECRET_LEN && !BENIGN.contains(&v.to_ascii_lowercase().as_str())
}

fn is_yaml_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
}

fn looks_text(data: &[u8]) -> bool {
    data.len() <= TEXT_MAX_BYTES && !data[..data.len().min(8192)].contains(&0)
}

/// 从 YAML 文本收集凭据值（URL userinfo 与敏感键）。
pub fn harvest(text: &str, values: &mut HashSet<String>) {
    for (start, end) in url_hits(text) {
        let userinfo = &text[start..end];
        let (user, pwd) = match userinfo.split_once(':') {
            Some((u, p)) => (u, p),
            None => (userinfo, ""),
        };
        for v in [user, pwd] {
            if is_secret_value(v) {
                values.insert(v.to_string());
            }
        }
    }
    for line in text.split('\n') {
        let body = line.strip_suffix('\r').unwrap_or(line);
        if let Some(caps) = sensitive_key_re().captures(body) {
            let v = strip_value(&caps["val"]);
            if is_secret_value(&v) {
                values.insert(v);
            }
        }
    }
}

/// 打星 URL userinfo；`is_yaml` 时再打星敏感键的值。注释与换行原样保留。
pub fn redact_text(text: &str, is_yaml: bool) -> String {
    let mut starred = text.to_string();
    for (start, end) in url_hits(text).into_iter().rev() {
        starred.replace_range(start..end, "*:*");
    }
    if !is_yaml {
        return starred;
    }
    let mut out = String::with_capacity(starred.len());
    for line in starred.split_inclusive('\n') {
        let (body, eol) = if let Some(b) = line.strip_suffix("\r\n") {
            (b, "\r\n")
        } else if let Some(b) = line.strip_suffix('\n') {
            (b, "\n")
        } else {
            (line, "")
        };
        if let Some(caps) = sensitive_key_re().captures(body)
            && is_secret_value(&strip_value(&caps["val"]))
        {
            out.push_str(&caps["head"]);
            out.push_str("'*'");
            out.push_str(&caps["tail"]);
        } else {
            out.push_str(body);
        }
        out.push_str(eol);
    }
    out
}

/// 输出里不得再出现已收集的值，也不得留下未打星的 `user:pass@`。
pub fn check(path: &str, text: &str, values: &HashSet<String>) -> Result<(), Error> {
    let mut hits: Vec<&str> = values
        .iter()
        .filter(|v| text.contains(v.as_str()))
        .map(String::as_str)
        .collect();
    if !hits.is_empty() {
        hits.sort_unstable();
        let preview: Vec<String> = hits
            .iter()
            .take(5)
            .map(|v| {
                let prefix: String = v.chars().take(4).collect();
                format!("{prefix}…({} chars)", v.len())
            })
            .collect();
        return Err(Error::Leak(format!(
            "{path}: credential still present: {}",
            preview.join(", ")
        )));
    }
    if let Some((start, end)) = url_hits(text).into_iter().find(|&(start, end)| {
        let userinfo = &text[start..end];
        userinfo.contains(':') && userinfo != "*:*"
    }) {
        let from = start.saturating_sub(8);
        let to = (end + 1).min(text.len());
        let shown: String = text[from..to].chars().take(24).collect();
        return Err(Error::Leak(format!(
            "{path}: unredacted url credential: {shown}…"
        )));
    }
    Ok(())
}

fn check_bytes(path: &str, data: &[u8], values: &HashSet<String>) -> Result<(), Error> {
    for v in values {
        if !v.is_empty()
            && v.len() <= data.len()
            && data.windows(v.len()).any(|w| w == v.as_bytes())
        {
            return Err(Error::Leak(format!(
                "{path}: credential still present in binary"
            )));
        }
    }
    Ok(())
}

/// 对单份 YAML 做收集、改写、核对。
pub fn redact_yaml(text: &str) -> Result<String, Error> {
    let mut values = HashSet::new();
    harvest(text, &mut values);
    let out = redact_text(text, true);
    check("config.yaml", &out, &values)?;
    Ok(out)
}

fn display_join(tree: &str, rel: &Path) -> String {
    let rel = rel
        .iter()
        .map(|c| c.to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    format!("{tree}/{rel}")
}

fn collect_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
        let mut entries: Vec<_> = fs::read_dir(dir)?.collect();
        entries.sort_by_key(|e| e.as_ref().map(|e| e.path()).unwrap_or_default());
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_dir() {
                if path.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                rec(&path, out)?;
            } else if ft.is_file() {
                out.push(path);
            }
        }
        Ok(())
    }
    rec(root, &mut out)?;
    Ok(out)
}

fn immediate_trees(input: &Path) -> Result<Vec<PathBuf>, Error> {
    if !input.is_dir() {
        return Err(Error::Other(format!(
            "input is not a directory: {}",
            input.display()
        )));
    }
    let mut trees = Vec::new();
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            trees.push(entry.path());
        }
    }
    trees.sort();
    if trees.is_empty() {
        return Err(Error::Other(
            "input has no subdirectories (each subdirectory is one tree)".into(),
        ));
    }
    Ok(trees)
}

/// 输入目录的每个子目录是一棵文件树。先从全部 YAML 收集值，再改写并写出到输出目录同名子目录。
pub fn run(input: &Path, output: &Path) -> Result<(), Error> {
    let trees = immediate_trees(input)?;
    let mut values = HashSet::new();
    let mut pending: Vec<(PathBuf, Vec<u8>, String)> = Vec::new();

    for tree in &trees {
        let tree_name = tree
            .file_name()
            .ok_or_else(|| Error::Other(format!("invalid tree path: {}", tree.display())))?;
        let tree_name = tree_name.to_string_lossy();
        for file in collect_files(tree)? {
            let rel = file
                .strip_prefix(tree)
                .map_err(|_| Error::Other(format!("file not under tree: {}", file.display())))?;
            let label = display_join(&tree_name, rel);
            let data = fs::read(&file)?;
            if looks_text(&data) {
                let text = String::from_utf8_lossy(&data);
                if is_yaml_path(&file) {
                    harvest(&text, &mut values);
                }
            }
            let dest = output.join(tree_name.as_ref()).join(rel);
            pending.push((dest, data, label));
        }
    }

    let mut out_files: Vec<(PathBuf, Vec<u8>)> = Vec::with_capacity(pending.len());
    for (dest, data, label) in pending {
        if looks_text(&data) {
            let text = String::from_utf8_lossy(&data);
            let is_yaml = is_yaml_path(&dest);
            let redacted = redact_text(&text, is_yaml);
            check(&label, &redacted, &values)?;
            out_files.push((dest, redacted.into_bytes()));
        } else {
            check_bytes(&label, &data, &values)?;
            out_files.push((dest, data));
        }
    }

    for tree in &trees {
        let name = tree
            .file_name()
            .ok_or_else(|| Error::Other(format!("invalid tree path: {}", tree.display())))?;
        fs::create_dir_all(output.join(name))?;
    }
    for (dest, data) in out_files {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    const FAKE_PWD1: &str = "sEcReTpAsS9876xyz";
    const FAKE_PWD2: &str = "minioROOTkey123456";
    const FAKE_AK: &str = "AKIAFAKE7EXAMPLE";
    const FAKE_SK: &str = "wJalrXUtnFEMIfake/bPxRfiCYEXAMPLEKEY";
    const FAKE_TOKEN: &str = "cnb_tok_9f8e7d6c5b4a";

    fn config_v1() -> String {
        format!(
            "servers:\n    makoto:\n        id: makoto\n        type: s3\n        url: 'https://{FAKE_AK}:{FAKE_PWD1}@makoto.oss.example?region=hk&expires=600'\n    kachina-eo:  # 免费EO 500KB/s，前11MB突发\n        id: kachina-eo\n        type: direct\n        url: 'https://dfs-edgeone.example.cn/dfs/'\nresources:\n    app.exe:\n        latest: '1.0'\n        version_provider:\n            webhook_token: '{FAKE_TOKEN}'\n            options:\n                authorization: '{FAKE_PWD2}'\n"
        )
    }

    fn node_info() -> String {
        format!(
            "nodes:\n  - name: 测试节点\n    bandwidth: 50Mbps\n    access_key: dfsuser\n    secret_key: {FAKE_SK}\n    node_id:\n      - test-stor.example.com # 电信\n"
        )
    }

    #[test]
    fn redacts_urls_keys_keeps_comments_and_benign() {
        let yaml = format!("{}\n{}", config_v1(), node_info());
        let out = redact_yaml(&yaml).unwrap();
        for secret in [FAKE_PWD1, FAKE_PWD2, FAKE_SK, FAKE_TOKEN, FAKE_AK] {
            assert!(!out.contains(secret), "leaked {secret} in {out}");
        }
        assert!(out.contains("://*:*@makoto.oss.example"));
        assert!(out.contains("webhook_token: '*'"));
        assert!(out.contains("authorization: '*'"));
        assert!(out.contains("免费EO 500KB/s"));
        assert!(out.contains("secret_key: '*'"));
        assert!(out.contains("access_key: dfsuser"));
        assert!(out.contains("# 电信"));
    }

    #[test]
    fn slash_inside_url_password_is_starred() {
        let text = "url: s3://AKID:sec/ret@s3.example.com/bucket?region=us-east-1\n";
        let out = redact_yaml(text).unwrap();
        assert!(!out.contains("sec/ret"));
        assert!(!out.contains("AKID"));
        assert!(out.contains("s3://*:*@s3.example.com/bucket?region=us-east-1"));
    }

    #[test]
    fn two_trees_harvest_then_catch_leak_in_later_tree() {
        let tmp = tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");
        fs::create_dir_all(input.join("0/config")).unwrap();
        fs::create_dir_all(input.join("0/node-info")).unwrap();
        fs::create_dir_all(input.join("1")).unwrap();
        fs::write(input.join("0/config/config.yaml"), config_v1()).unwrap();
        fs::write(input.join("0/node-info/Test-Node.yaml"), node_info()).unwrap();
        fs::write(input.join("1/readme.md"), format!("debug: {FAKE_SK}\n")).unwrap();

        let err = run(&input, &output).unwrap_err();
        assert!(err.is_leak(), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("readme.md"), "{msg}");
        assert!(
            !output.exists()
                || output
                    .read_dir()
                    .map(|mut d| d.next().is_none())
                    .unwrap_or(true)
        );
    }

    #[test]
    fn run_writes_redacted_trees() {
        let tmp = tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");
        fs::create_dir_all(input.join("0/config")).unwrap();
        fs::create_dir_all(input.join("0/node-info")).unwrap();
        fs::write(input.join("0/config/config.yaml"), config_v1()).unwrap();
        fs::write(input.join("0/node-info/Test-Node.yaml"), node_info()).unwrap();
        fs::write(
            input.join("0/readme.md"),
            "# dfs config\nusername: dfsuser\n",
        )
        .unwrap();

        run(&input, &output).unwrap();
        let head = fs::read_to_string(output.join("0/config/config.yaml")).unwrap();
        assert!(head.contains("://*:*@makoto.oss.example"));
        assert!(head.contains("免费EO 500KB/s"));
        let node = fs::read_to_string(output.join("0/node-info/Test-Node.yaml")).unwrap();
        assert!(node.contains("secret_key: '*'"));
        assert!(node.contains("access_key: dfsuser"));
        assert!(node.contains("# 电信"));
    }
}
