use std::str::FromStr;

use serde::{Deserialize, Serialize};
use size::Size;

use crate::modules::storage::data_store::BANDWIDTH_MINUTE_RING_SIZE;

/// `speed` 条件省略窗口参数时的默认分钟数。
pub const DEFAULT_SPEED_WINDOW_MINUTES: u32 = 5;

// TODO(unconstructed-type): 全仓库只有这一行提到 FlowsList，没有任何构造点；flow 一律以
// Vec<FlowItem> 的形式在 ResourceConfig 上流转。确认无外部依赖后删除。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct FlowsList(pub Vec<FlowItem>);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[allow(clippy::upper_case_acronyms)]
pub enum FlowMode {
    #[serde(rename = "and")]
    AND,
    #[serde(rename = "or")]
    #[default]
    OR,
}

/// 同层节点权重的相对增减运算。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightDelta {
    Add(u32),
    Sub(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowUse {
    // clear
    Clear,
    /// 将本层内节点权重设为指定值（未入池时仅正权重入池；0 将同层已有节点禁用）。
    Server {
        id: String,
        weight: u32,
    },
    /// 在本层内对节点权重做相对增减（`+N` 累加或入池，`-N` 饱和扣减至 0）。
    ServerDelta {
        id: String,
        delta: WeightDelta,
    },
    // plugin id plugin id indirect
    Plugin {
        id: String,
        indirect: String,
    },
    // poolize
    Poolize,
    /// 停止执行整条 flow。本项 `use` 中它之后的命令也不再执行。
    Break,
    /// 结束本项所在的层：后续属于同一 `tier` 的项一概跳过，其它层照常执行。
    /// 本项 `use` 中它之后的命令同属本层，因此也不再执行。
    Continue,
}

impl FlowUse {
    /// 命令指向的服务器 ID（无论赋值还是增减），供配置加载期死引用摘除使用。
    pub fn server_id(&self) -> Option<&str> {
        match self {
            FlowUse::Server { id, .. } | FlowUse::ServerDelta { id, .. } => Some(id),
            _ => None,
        }
    }

    /// 命令是否可能以正权重将节点引入候选池（排除置 0 与纯扣减），供副本枚举与文件大小探测使用。
    pub fn introduces_server_id(&self) -> Option<&str> {
        match self {
            FlowUse::Server { id, weight } if *weight > 0 => Some(id),
            FlowUse::ServerDelta {
                id,
                delta: WeightDelta::Add(w),
            } if *w > 0 => Some(id),
            _ => None,
        }
    }
}

impl FromStr for FlowUse {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s == "clear" {
            Ok(FlowUse::Clear)
        } else if s == "poolize" {
            Ok(FlowUse::Poolize)
        } else if s == "break" {
            Ok(FlowUse::Break)
        } else if s == "continue" {
            Ok(FlowUse::Continue)
        } else if let Some(rest) = s.strip_prefix("server") {
            if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                return Err(format!("Invalid FlowUse: {s}"));
            }
            let parts: Vec<&str> = rest.split_whitespace().collect();
            let Some(&id_raw) = parts.first() else {
                return Err(
                    "server command requires format: server {id} [weight|+N|-N]".to_string()
                );
            };
            if parts.len() > 2 {
                return Err(format!(
                    "server command requires format: server {{id}} [weight|+N|-N], got '{s}'"
                ));
            }
            let id = id_raw.to_string();
            let Some(&weight_token) = parts.get(1) else {
                return Ok(FlowUse::Server { id, weight: 0 });
            };
            if let Some(num) = weight_token.strip_prefix('+') {
                let delta = num
                    .parse::<u32>()
                    .map_err(|e| format!("Invalid server weight delta '+{num}': {e}"))?;
                Ok(FlowUse::ServerDelta {
                    id,
                    delta: WeightDelta::Add(delta),
                })
            } else if let Some(num) = weight_token.strip_prefix('-') {
                let delta = num
                    .parse::<u32>()
                    .map_err(|e| format!("Invalid server weight delta '-{num}': {e}"))?;
                Ok(FlowUse::ServerDelta {
                    id,
                    delta: WeightDelta::Sub(delta),
                })
            } else {
                let weight = weight_token
                    .parse::<u32>()
                    .map_err(|e| format!("Invalid server weight '{weight_token}': {e}"))?;
                Ok(FlowUse::Server { id, weight })
            }
        } else if let Some(rest) = s.strip_prefix("plugin ") {
            let trimmed = rest.trim_start();
            if trimmed.is_empty() {
                return Err("plugin command requires format: plugin {id} [indirect]".to_string());
            }
            let (id, indirect) = match trimmed.split_once(char::is_whitespace) {
                Some((id, rem)) => (id.to_string(), rem.trim().to_string()),
                None => (trimmed.to_string(), String::new()),
            };
            Ok(FlowUse::Plugin { id, indirect })
        } else {
            Err(format!("Invalid FlowUse: {s}"))
        }
    }
}

impl std::fmt::Display for FlowUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowUse::Clear => write!(f, "clear"),
            FlowUse::Poolize => write!(f, "poolize"),
            FlowUse::Break => write!(f, "break"),
            FlowUse::Continue => write!(f, "continue"),
            FlowUse::Server { id, weight } => write!(f, "server {id} {weight}"),
            FlowUse::ServerDelta {
                id,
                delta: WeightDelta::Add(n),
            } => write!(f, "server {id} +{n}"),
            FlowUse::ServerDelta {
                id,
                delta: WeightDelta::Sub(n),
            } => write!(f, "server {id} -{n}"),
            FlowUse::Plugin { id, indirect } => {
                if indirect.is_empty() {
                    write!(f, "plugin {id}")
                } else {
                    write!(f, "plugin {id} {indirect}")
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for FlowUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FlowUse::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for FlowUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum FlowComp {
    #[default]
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}
impl FlowComp {
    pub fn matches<T: PartialOrd>(&self, lhs: T, rhs: T) -> bool {
        match self {
            FlowComp::Eq => lhs == rhs,
            FlowComp::Ne => lhs != rhs,
            FlowComp::Gt => lhs > rhs,
            FlowComp::Ge => lhs >= rhs,
            FlowComp::Lt => lhs < rhs,
            FlowComp::Le => lhs <= rhs,
        }
    }
}

impl std::str::FromStr for FlowComp {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "==" => Ok(FlowComp::Eq),
            "!=" => Ok(FlowComp::Ne),
            ">" => Ok(FlowComp::Gt),
            ">=" => Ok(FlowComp::Ge),
            "<" => Ok(FlowComp::Lt),
            "<=" => Ok(FlowComp::Le),
            _ => Err(format!("Invalid FlowComp: {s}")),
        }
    }
}

impl std::fmt::Display for FlowComp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowComp::Eq => write!(f, "=="),
            FlowComp::Ne => write!(f, "!="),
            FlowComp::Gt => write!(f, ">"),
            FlowComp::Ge => write!(f, ">="),
            FlowComp::Lt => write!(f, "<"),
            FlowComp::Le => write!(f, "<="),
        }
    }
}

impl<'de> Deserialize<'de> for FlowComp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "==" => Ok(FlowComp::Eq),
            "!=" => Ok(FlowComp::Ne),
            ">" => Ok(FlowComp::Gt),
            ">=" => Ok(FlowComp::Ge),
            "<" => Ok(FlowComp::Lt),
            "<=" => Ok(FlowComp::Le),
            _ => Err(serde::de::Error::custom(format!("Invalid FlowComp: {s}"))),
        }
    }
}
impl Serialize for FlowComp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FlowComp::Eq => serializer.serialize_str("=="),
            FlowComp::Ne => serializer.serialize_str("!="),
            FlowComp::Gt => serializer.serialize_str(">"),
            FlowComp::Ge => serializer.serialize_str(">="),
            FlowComp::Lt => serializer.serialize_str("<"),
            FlowComp::Le => serializer.serialize_str("<="),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResourcePattern {
    Global,           // * - 所有资源
    Current,          // $ - 当前资源
    Specific(String), // 具体资源ID
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpeedTarget {
    /// 全站外部节点汇总流量（`*`）
    Global,
    /// 指定节点（`server_id`）
    Server(String),
}

impl std::fmt::Display for SpeedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpeedTarget::Global => write!(f, "*"),
            SpeedTarget::Server(id) => write!(f, "{id}"),
        }
    }
}

/// 带宽速率阈值，内部统一按 `bits/s` 存储；字节率（`MB/s`、`MiB/s` 等）复用 [`Size`] 解析。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BandwidthRate {
    bits_per_sec: u64,
}

impl BandwidthRate {
    pub fn bits_per_sec(&self) -> u64 {
        self.bits_per_sec
    }
}

impl FromStr for BandwidthRate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty bandwidth rate".to_string());
        }
        if !s.is_ascii() {
            return Err(format!(
                "bandwidth rate '{s}' must contain only ASCII characters"
            ));
        }

        // 大写 `B/s` 结尾的字节率直接委托 `Size`（与 `size`、`bw_daily` 共享同一套字节单位语义）
        if let Some(size_part) = s.strip_suffix("/s").or_else(|| s.strip_suffix("/S"))
            && size_part.ends_with('B')
        {
            let size =
                Size::from_str(size_part).map_err(|e| format!("invalid byte rate '{s}': {e}"))?;
            let bytes = u64::try_from(size.bytes())
                .map_err(|_| format!("bandwidth rate '{s}' must be non-negative"))?;
            let bits_per_sec = bytes
                .checked_mul(8)
                .ok_or_else(|| format!("bandwidth rate overflow in '{s}'"))?;
            return Ok(Self { bits_per_sec });
        }

        let unit_pos = s
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(|| format!("bandwidth rate '{s}' requires a unit (e.g. Mbps, MB/s)"))?;
        let (num_str, unit_raw) = s.split_at(unit_pos);
        if num_str.is_empty() || num_str.starts_with('.') {
            return Err(format!("invalid number in bandwidth rate '{s}'"));
        }

        let unit = unit_raw.trim();
        if unit.ends_with("Bps") {
            return Err(format!(
                "ambiguous bandwidth unit '{unit}' in '{s}'; use 'MB/s' for bytes/s or 'Mbps' for bits/s"
            ));
        }

        let strip_ascii_suffix_ignore_case = |input: &str, suffix: &str| -> Option<String> {
            let prefix_len = input.len().checked_sub(suffix.len())?;
            let (head, tail) = input.split_at(prefix_len);
            tail.eq_ignore_ascii_case(suffix).then(|| head.to_string())
        };
        let mag = if let Some(m) = strip_ascii_suffix_ignore_case(unit, "bps") {
            m
        } else if let Some(head) = unit.strip_suffix("/s").or_else(|| unit.strip_suffix("/S")) {
            if let Some(m) = strip_ascii_suffix_ignore_case(head, "bit") {
                m
            } else if let Some(m) = head.strip_suffix('b') {
                m.to_string()
            } else {
                return Err(format!("unsupported bandwidth rate unit '{unit}' in '{s}'"));
            }
        } else {
            return Err(format!("unsupported bandwidth rate unit '{unit}' in '{s}'"));
        };

        let scale: f64 = match mag.to_ascii_lowercase().as_str() {
            "" => 1.0,
            "k" => 1e3,
            "m" => 1e6,
            "g" => 1e9,
            "t" => 1e12,
            _ => return Err(format!("unsupported bandwidth rate unit '{unit}' in '{s}'")),
        };

        let val: f64 = num_str
            .parse()
            .map_err(|e| format!("invalid number in bandwidth rate '{s}': {e}"))?;
        let bps = val * scale;
        if !bps.is_finite() || bps < 0.0 || bps > (u64::MAX as f64) {
            return Err(format!("bandwidth rate out of range in '{s}'"));
        }
        Ok(Self {
            bits_per_sec: bps.round() as u64,
        })
    }
}

impl std::fmt::Display for BandwidthRate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bps = self.bits_per_sec;
        if bps == 0 {
            return write!(f, "0bps");
        }
        for (unit_val, suffix) in [
            (1_000_000_000u64, "Gbps"),
            (1_000_000u64, "Mbps"),
            (1_000u64, "Kbps"),
        ] {
            if bps.is_multiple_of(unit_val) {
                return write!(f, "{}{suffix}", bps / unit_val);
            }
        }
        write!(f, "{bps}bps")
    }
}

#[derive(Debug, Clone)]
pub enum FlowCond {
    CnIp(bool),
    IpVersion(u8), // 4 for IPv4, 6 for IPv6
    Cidr(cidr::IpCidr),
    Extras(String),
    Size(FlowComp, Size),
    ResourceBwDaily(ResourcePattern, FlowComp, Size), // 资源级别的日流量限制
    ServerBwDaily(String, FlowComp, Size),            // 服务器级别的日流量限制，必须指定server_id
    ServerBwMinutes(String, u32, FlowComp, Size), // 服务器分钟级流量限制：server_id, minutes, comp, size
    /// 实时估算速率条件：`speed <* | server_id> [minutes] <comp> <rate>`（默认 5 分钟窗口）。
    Speed(SpeedTarget, u32, FlowComp, BandwidthRate),
    Time(FlowComp, chrono::NaiveTime),
    GeoIp(String), // geoip关键词匹配
    /// 取反内层条件的求值结果，包括"信息缺失"导致的 false（例如没有客户端 IP 时 `cnip` 恒为
    /// false，因而 `not cnip true` 恒为 true）。
    Not(Box<FlowCond>),
    /// 本次取件是否由调度器自身发起。用来把只对真实客户端有意义的层与内部取件分开。
    Internal(bool),
}

impl FlowCond {
    /// 条件中显式引用的具体服务器 ID（供 `dfs2 validate` 检查未定义节点名拼写错误）。
    pub fn referenced_server_id(&self) -> Option<&str> {
        match self {
            FlowCond::ServerBwDaily(id, _, _)
            | FlowCond::ServerBwMinutes(id, _, _, _)
            | FlowCond::Speed(SpeedTarget::Server(id), _, _, _) => Some(id),
            FlowCond::Not(inner) => inner.referenced_server_id(),
            _ => None,
        }
    }
}

/// 取第 `index` 个空格分隔的词，缺失时给出带用法的错误。
fn cond_arg<'a>(parts: &[&'a str], index: usize, usage: &str) -> Result<&'a str, String> {
    parts
        .get(index)
        .copied()
        .ok_or_else(|| format!("condition requires format: {usage}"))
}

impl FromStr for FlowCond {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        let method = *parts.first().ok_or_else(|| "empty condition".to_string())?;
        match method {
            "not" => {
                let inner = parts[1..].join(" ");
                if inner.is_empty() {
                    return Err("condition requires format: not {cond}".to_string());
                }
                Ok(FlowCond::Not(Box::new(FlowCond::from_str(&inner)?)))
            }
            "cnip" => {
                let value = cond_arg(&parts, 1, "cnip {true|false}")?
                    .parse::<bool>()
                    .map_err(|e| e.to_string())?;
                Ok(FlowCond::CnIp(value))
            }
            "internal" => {
                let value = cond_arg(&parts, 1, "internal {true|false}")?
                    .parse::<bool>()
                    .map_err(|e| e.to_string())?;
                Ok(FlowCond::Internal(value))
            }
            "ipversion" => {
                let version = cond_arg(&parts, 1, "ipversion {4|6}")?
                    .parse::<u8>()
                    .map_err(|e| e.to_string())?;
                if version != 4 && version != 6 {
                    return Err("IP version must be 4 or 6".to_string());
                }
                Ok(FlowCond::IpVersion(version))
            }
            "cidr" => {
                let cidr = cond_arg(&parts, 1, "cidr {cidr}")?
                    .parse::<cidr::IpCidr>()
                    .map_err(|e| e.to_string())?;
                Ok(FlowCond::Cidr(cidr))
            }
            "extras" => Ok(FlowCond::Extras(
                cond_arg(&parts, 1, "extras {key}")?.to_string(),
            )),
            "geoip" => Ok(FlowCond::GeoIp(
                cond_arg(&parts, 1, "geoip {keyword}")?.to_string(),
            )),
            "size" => {
                let usage = "size {comp} {size}";
                let comp = FlowComp::from_str(cond_arg(&parts, 1, usage)?)?;
                let size =
                    Size::from_str(cond_arg(&parts, 2, usage)?).map_err(|e| e.to_string())?;
                Ok(FlowCond::Size(comp, size))
            }
            "bw_daily" => {
                if parts.len() == 3 {
                    // 旧格式：bw_daily <comp> <size> - 视为当前资源
                    let comp = FlowComp::from_str(parts[1])?;
                    let size = Size::from_str(parts[2]).map_err(|e| e.to_string())?;
                    Ok(FlowCond::ResourceBwDaily(
                        ResourcePattern::Current,
                        comp,
                        size,
                    ))
                } else if parts.len() == 4 {
                    // 新格式：bw_daily <resource> <comp> <size>
                    let resource_pattern = match parts[1] {
                        "*" => ResourcePattern::Global,
                        "$" => ResourcePattern::Current,
                        resource_id => ResourcePattern::Specific(resource_id.to_string()),
                    };
                    let comp = FlowComp::from_str(parts[2])?;
                    let size = Size::from_str(parts[3]).map_err(|e| e.to_string())?;
                    Ok(FlowCond::ResourceBwDaily(resource_pattern, comp, size))
                } else {
                    Err("condition requires format: bw_daily [resource] {comp} {size}".to_string())
                }
            }
            "server_bw_daily" => {
                if parts.len() != 4 {
                    return Err(
                        "condition requires format: server_bw_daily {server_id} {comp} {size}"
                            .to_string(),
                    );
                }
                let comp = FlowComp::from_str(parts[2])?;
                let size = Size::from_str(parts[3]).map_err(|e| e.to_string())?;
                Ok(FlowCond::ServerBwDaily(parts[1].to_string(), comp, size))
            }
            "server_bw_minutes" => {
                if parts.len() != 5 {
                    return Err(
                        "condition requires format: server_bw_minutes {server_id} {minutes} {comp} {size}"
                            .to_string(),
                    );
                }
                let minutes = parts[2].parse::<u32>().map_err(|e| e.to_string())?;
                let comp = FlowComp::from_str(parts[3])?;
                let size = Size::from_str(parts[4]).map_err(|e| e.to_string())?;
                Ok(FlowCond::ServerBwMinutes(
                    parts[1].to_string(),
                    minutes,
                    comp,
                    size,
                ))
            }
            "speed" => {
                let usage = "speed {* | server_id} [minutes] {comp} {rate}";
                let raw_target = cond_arg(&parts, 1, usage)?;
                if raw_target == "$" {
                    return Err(
                        "speed target does not support '$'; use '*' or a server_id".to_string()
                    );
                }
                let target = if raw_target == "*" {
                    SpeedTarget::Global
                } else {
                    SpeedTarget::Server(raw_target.to_string())
                };

                let (minutes, comp_str, rate_str) = match parts.len() {
                    4 => (DEFAULT_SPEED_WINDOW_MINUTES, parts[2], parts[3]),
                    5 => {
                        if FlowComp::from_str(parts[2]).is_ok() {
                            return Err(format!(
                                "bandwidth rate in '{s}' must not contain whitespace (e.g. '80Mbps')"
                            ));
                        }
                        let m = parts[2]
                            .parse::<u32>()
                            .map_err(|e| format!("invalid minutes '{}' in '{s}': {e}", parts[2]))?;
                        if m == 0 || m > BANDWIDTH_MINUTE_RING_SIZE {
                            return Err(format!(
                                "speed minutes must be between 1 and {BANDWIDTH_MINUTE_RING_SIZE}, got {m}"
                            ));
                        }
                        (m, parts[3], parts[4])
                    }
                    _ => return Err(format!("condition requires format: {usage}")),
                };

                let comp = FlowComp::from_str(comp_str)?;
                let rate = BandwidthRate::from_str(rate_str)?;
                Ok(FlowCond::Speed(target, minutes, comp, rate))
            }
            "time" => {
                let usage = "time {comp} {HH:MM:SS}";
                let comp = FlowComp::from_str(cond_arg(&parts, 1, usage)?)?;
                let time =
                    chrono::NaiveTime::parse_from_str(cond_arg(&parts, 2, usage)?, "%H:%M:%S")
                        .map_err(|e| e.to_string())?;
                Ok(FlowCond::Time(comp, time))
            }
            _ => Err(format!("Invalid FlowCond: {s}")),
        }
    }
}

impl std::fmt::Display for FlowCond {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowCond::CnIp(value) => write!(f, "cnip {value}"),
            FlowCond::IpVersion(version) => write!(f, "ipversion {version}"),
            FlowCond::Cidr(cidr) => write!(f, "cidr {cidr}"),
            FlowCond::Extras(extras) => write!(f, "extras {extras}"),
            FlowCond::GeoIp(keyword) => write!(f, "geoip {keyword}"),
            FlowCond::Size(comp, size) => write!(f, "size {comp} {size}"),
            FlowCond::ResourceBwDaily(pattern, comp, size) => {
                let pattern_str = match pattern {
                    ResourcePattern::Global => "*",
                    ResourcePattern::Current => "$",
                    ResourcePattern::Specific(resource_id) => resource_id,
                };
                write!(f, "bw_daily {pattern_str} {comp} {size}")
            }
            FlowCond::ServerBwDaily(server_id, comp, size) => {
                write!(f, "server_bw_daily {server_id} {comp} {size}")
            }
            FlowCond::ServerBwMinutes(server_id, minutes, comp, size) => {
                write!(f, "server_bw_minutes {server_id} {minutes} {comp} {size}")
            }
            FlowCond::Speed(target, minutes, comp, rate) => {
                write!(f, "speed {target} {minutes} {comp} {rate}")
            }
            FlowCond::Time(comp, time) => write!(f, "time {comp} {time}"),
            FlowCond::Not(inner) => write!(f, "not {inner}"),
            FlowCond::Internal(value) => write!(f, "internal {value}"),
        }
    }
}

impl<'de> Deserialize<'de> for FlowCond {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FlowCond::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_comp_from_str() {
        assert_eq!(FlowComp::from_str("==").unwrap(), FlowComp::Eq);
        assert_eq!(FlowComp::from_str("!=").unwrap(), FlowComp::Ne);
        assert_eq!(FlowComp::from_str(">").unwrap(), FlowComp::Gt);
        assert_eq!(FlowComp::from_str(">=").unwrap(), FlowComp::Ge);
        assert_eq!(FlowComp::from_str("<").unwrap(), FlowComp::Lt);
        assert_eq!(FlowComp::from_str("<=").unwrap(), FlowComp::Le);

        assert!(FlowComp::from_str("invalid").is_err());
    }

    #[test]
    fn test_flow_comp_display() {
        assert_eq!(format!("{}", FlowComp::Eq), "==");
        assert_eq!(format!("{}", FlowComp::Ne), "!=");
        assert_eq!(format!("{}", FlowComp::Gt), ">");
        assert_eq!(format!("{}", FlowComp::Ge), ">=");
        assert_eq!(format!("{}", FlowComp::Lt), "<");
        assert_eq!(format!("{}", FlowComp::Le), "<=");
    }

    #[test]
    fn test_flow_use_deserialize() {
        let use_clear: FlowUse = serde_yaml::from_str("clear").unwrap();
        assert!(matches!(use_clear, FlowUse::Clear));

        let use_poolize: FlowUse = serde_yaml::from_str("poolize").unwrap();
        assert!(matches!(use_poolize, FlowUse::Poolize));

        let use_server: FlowUse = serde_yaml::from_str("server test_server 10").unwrap();
        assert!(
            matches!(use_server, FlowUse::Server { ref id, weight } if id == "test_server" && weight == 10)
        );

        let use_break: FlowUse = serde_yaml::from_str("break").unwrap();
        assert!(matches!(use_break, FlowUse::Break));
        assert_eq!(serde_yaml::to_string(&use_break).unwrap().trim(), "break");

        let use_continue: FlowUse = serde_yaml::from_str("continue").unwrap();
        assert!(matches!(use_continue, FlowUse::Continue));
        assert_eq!(
            serde_yaml::to_string(&use_continue).unwrap().trim(),
            "continue"
        );

        let use_plugin: FlowUse = serde_yaml::from_str("plugin test_plugin some_data").unwrap();
        assert!(
            matches!(use_plugin, FlowUse::Plugin { ref id, ref indirect } if id == "test_plugin" && indirect == "some_data")
        );
    }

    #[test]
    fn not_wraps_any_condition_and_round_trips() {
        let cond: FlowCond = serde_yaml::from_str("not cnip true").unwrap();
        assert!(matches!(&cond, FlowCond::Not(inner) if matches!(**inner, FlowCond::CnIp(true))));
        assert_eq!(cond.to_string(), "not cnip true");

        // 多词条件的参数不能被 not 的切分吃掉。这里比对结构而非文本：
        // Size 的 Display 会把 100MB 归一化为 95.4 MiB，与 not 无关。
        let cond: FlowCond = serde_yaml::from_str("not size > 100MB").unwrap();
        let FlowCond::Not(inner) = &cond else {
            panic!("expected a negated condition, got {cond:?}");
        };
        assert!(
            matches!(&**inner, FlowCond::Size(FlowComp::Gt, size) if size.bytes() == 100_000_000),
            "expected size > 100MB inside the negation, got {inner:?}"
        );

        // 嵌套可解析，与单层等价的判断留给求值侧
        let cond: FlowCond = serde_yaml::from_str("not not geoip telecom").unwrap();
        assert_eq!(cond.to_string(), "not not geoip telecom");

        assert!(serde_yaml::from_str::<FlowCond>("not").is_err());
        assert!(serde_yaml::from_str::<FlowCond>("not bogus_cond").is_err());
    }

    #[test]
    fn internal_condition_round_trips() {
        let cond: FlowCond = serde_yaml::from_str("internal true").unwrap();
        assert!(matches!(cond, FlowCond::Internal(true)));
        assert_eq!(cond.to_string(), "internal true");

        let cond: FlowCond = serde_yaml::from_str("not internal true").unwrap();
        assert_eq!(cond.to_string(), "not internal true");

        assert!(serde_yaml::from_str::<FlowCond>("internal maybe").is_err());
    }

    #[test]
    fn truncated_conditions_are_errors_not_panics() {
        for text in [
            "cnip",
            "internal",
            "ipversion",
            "cidr",
            "extras",
            "geoip",
            "size >",
            "time >=",
        ] {
            assert!(
                serde_yaml::from_str::<FlowCond>(text).is_err(),
                "'{text}' should be rejected"
            );
        }
    }

    #[test]
    fn test_flow_cond_deserialize() {
        // 测试CnIp条件
        let cond: FlowCond = serde_yaml::from_str("cnip true").unwrap();
        assert!(matches!(cond, FlowCond::CnIp(true)));

        // 测试IpVersion条件
        let cond: FlowCond = serde_yaml::from_str("ipversion 4").unwrap();
        assert!(matches!(cond, FlowCond::IpVersion(4)));

        let cond: FlowCond = serde_yaml::from_str("ipversion 6").unwrap();
        assert!(matches!(cond, FlowCond::IpVersion(6)));

        // 测试无效的IP版本
        let result: Result<FlowCond, _> = serde_yaml::from_str("ipversion 5");
        assert!(result.is_err());

        // 测试CIDR条件
        let cond: FlowCond = serde_yaml::from_str("cidr 192.168.1.0/24").unwrap();
        assert!(matches!(cond, FlowCond::Cidr(_)));

        // 测试Extras条件
        let cond: FlowCond = serde_yaml::from_str("extras debug").unwrap();
        assert!(matches!(cond, FlowCond::Extras(ref key) if key == "debug"));

        // 测试GeoIp条件
        let cond: FlowCond = serde_yaml::from_str("geoip china").unwrap();
        assert!(matches!(cond, FlowCond::GeoIp(ref keyword) if keyword == "china"));

        // 测试Size条件
        let cond: FlowCond = serde_yaml::from_str("size > 10MB").unwrap();
        assert!(matches!(cond, FlowCond::Size(FlowComp::Gt, _)));

        // 测试Time条件
        let cond: FlowCond = serde_yaml::from_str("time >= 09:00:00").unwrap();
        assert!(matches!(cond, FlowCond::Time(FlowComp::Ge, _)));
    }

    #[test]
    fn test_flow_cond_serialize() {
        let cond = FlowCond::CnIp(true);
        let yaml = serde_yaml::to_string(&cond).unwrap();
        assert!(yaml.contains("cnip true"));

        let cond = FlowCond::IpVersion(4);
        let yaml = serde_yaml::to_string(&cond).unwrap();
        assert!(yaml.contains("ipversion 4"));

        let cond = FlowCond::Extras("debug".to_string());
        let yaml = serde_yaml::to_string(&cond).unwrap();
        assert!(yaml.contains("extras debug"));

        let cond = FlowCond::GeoIp("china".to_string());
        let yaml = serde_yaml::to_string(&cond).unwrap();
        assert!(yaml.contains("geoip china"));
    }

    #[test]
    fn test_flow_item_default() {
        let item = FlowItem::default();
        assert_eq!(item.mode, FlowMode::OR);
        assert!(item.r#use.is_empty());
        assert!(item.rules.is_empty());
        assert_eq!(item.tier, 0);
    }

    #[test]
    fn server_use_supports_set_and_signed_deltas() {
        let set_plain: FlowUse = serde_yaml::from_str("server node_a 10").unwrap();
        assert_eq!(set_plain.to_string(), "server node_a 10");
        assert_eq!(set_plain.introduces_server_id(), Some("node_a"));

        let set_zero: FlowUse = serde_yaml::from_str("server node_a 0").unwrap();
        assert_eq!(set_zero.server_id(), Some("node_a"));
        assert_eq!(set_zero.introduces_server_id(), None);
        assert_eq!(
            serde_yaml::from_str::<FlowUse>("server node_a").unwrap(),
            set_zero
        );

        let add_delta: FlowUse = serde_yaml::from_str("server cdn_a +25").unwrap();
        assert_eq!(
            add_delta,
            FlowUse::ServerDelta {
                id: "cdn_a".to_string(),
                delta: WeightDelta::Add(25),
            }
        );
        assert_eq!(add_delta.to_string(), "server cdn_a +25");
        assert_eq!(add_delta.introduces_server_id(), Some("cdn_a"));
        assert_eq!(
            serde_yaml::from_str::<FlowUse>("server cdn_a +0")
                .unwrap()
                .introduces_server_id(),
            None
        );

        let sub_delta: FlowUse = serde_yaml::from_str("server node_a -4").unwrap();
        assert_eq!(sub_delta.to_string(), "server node_a -4");
        assert_eq!(sub_delta.server_id(), Some("node_a"));
        assert_eq!(sub_delta.introduces_server_id(), None);

        for invalid in [
            "server",
            "server node_a +",
            "server node_a -",
            "server node_a =10",
            "server node_a abc",
            "server node_a 1 2",
        ] {
            assert!(
                serde_yaml::from_str::<FlowUse>(invalid).is_err(),
                "'{invalid}' should be rejected"
            );
        }
    }

    #[test]
    fn bandwidth_rate_and_speed_condition_round_trip() {
        for (input, expected_bps) in [
            ("80Mbps", 80_000_000),
            ("80Mb/s", 80_000_000),
            ("80Mbit/s", 80_000_000),
            ("7.5Mbps", 7_500_000),
            ("1.5Gbps", 1_500_000_000),
            ("10MB/s", 80_000_000),
            ("10MiB/s", 8 * 10 * 1024 * 1024),
        ] {
            assert_eq!(
                BandwidthRate::from_str(input).unwrap().bits_per_sec(),
                expected_bps,
                "failed on {input}"
            );
        }
        assert_eq!(
            BandwidthRate::from_str("7.5Mbps").unwrap().to_string(),
            "7500Kbps"
        );

        let default_win: FlowCond = serde_yaml::from_str("speed cyrene > 80Mbps").unwrap();
        assert_eq!(default_win.to_string(), "speed cyrene 5 > 80Mbps");
        assert_eq!(default_win.referenced_server_id(), Some("cyrene"));

        let global_win: FlowCond = serde_yaml::from_str("speed * 1 > 800Mbps").unwrap();
        assert_eq!(global_win.to_string(), "speed * 1 > 800Mbps");
        assert_eq!(global_win.referenced_server_id(), None);

        let negated: FlowCond = serde_yaml::from_str("not speed iroha 10 >= 15Mbps").unwrap();
        assert_eq!(negated.referenced_server_id(), Some("iroha"));

        for invalid in [
            "speed",
            "speed cyrene >",
            "speed $ > 80Mbps",
            "speed cyrene 0 > 80Mbps",
            "speed cyrene 1441 > 80Mbps",
            "speed cyrene > 80",
            "speed cyrene > 80MB",
            "speed cyrene > 10MBps",
            "speed cyrene > -10MB/s",
            "speed cyrene > 80 Mbps",
            "speed * > 5兆b",
            "speed cyrene > 100兆bps",
            "speed cyrene > 10Мбит/s",
        ] {
            assert!(
                serde_yaml::from_str::<FlowCond>(invalid).is_err(),
                "'{invalid}' should be rejected"
            );
        }
    }
}

impl Serialize for FlowCond {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FlowItem {
    /// 展开顶层 `flows` 中同名列表片段；与 `rules`、`use` 互斥，在配置加载期单层内联。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insert: Option<String>,
    #[serde(default)]
    pub mode: FlowMode,
    #[serde(default)]
    pub r#use: Vec<FlowUse>,
    #[serde(default)]
    pub rules: Vec<FlowCond>,
    /// 本项贡献的节点属于哪一层，数字越小越优先。
    ///
    /// 选点先在最优先的层内做加权随机，只有该层内所有节点都不可用时才降到下一层。缺省 0，
    /// 因此不写 tier 的配置全部落在同一层，行为与分层引入前一致。
    #[serde(default)]
    pub tier: u32,
}
