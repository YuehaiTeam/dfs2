use std::str::FromStr;

use serde::{Deserialize, Serialize};
use size::Size;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowUse {
    // clear
    Clear,
    // server id server id weight
    Server {
        id: String,
        weight: u32,
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
impl<'de> Deserialize<'de> for FlowUse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.trim();
        if s == "clear" {
            Ok(FlowUse::Clear)
        } else if s == "poolize" {
            Ok(FlowUse::Poolize)
        } else if s == "break" {
            Ok(FlowUse::Break)
        } else if s == "continue" {
            Ok(FlowUse::Continue)
        } else if s.starts_with("server ") {
            // server id server id weight
            // eg. server example 2
            let mut parts: Vec<&str> = s.split(' ').collect();
            let id = parts[1].to_string();
            parts.remove(0);
            parts.remove(0);
            let last_all = parts.join(" ");
            let weight = if last_all.is_empty() {
                0
            } else {
                last_all.parse::<u32>().map_err(serde::de::Error::custom)?
            };
            Ok(FlowUse::Server { id, weight })
        } else if s.starts_with("plugin ") {
            // plugin:id plugin:id[indirect]
            // eg. plugin:example[2]
            let mut parts: Vec<&str> = s.split(' ').collect();
            let id = parts[1].to_string();
            parts.remove(0);
            parts.remove(0);
            let last_all = parts.join(" ");
            let indirect = if last_all.is_empty() {
                String::new()
            } else {
                last_all
            };
            Ok(FlowUse::Plugin { id, indirect })
        } else {
            Err(serde::de::Error::custom(format!("Invalid FlowUse: {s}")))
        }
    }
}

impl Serialize for FlowUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FlowUse::Clear => serializer.serialize_str("clear"),
            FlowUse::Poolize => serializer.serialize_str("poolize"),
            FlowUse::Break => serializer.serialize_str("break"),
            FlowUse::Continue => serializer.serialize_str("continue"),
            FlowUse::Server { id, weight } => {
                if *weight > 0 {
                    serializer.serialize_str(&format!("server {id}[{weight}]"))
                } else {
                    serializer.serialize_str(&format!("server {id}"))
                }
            }
            FlowUse::Plugin { id, indirect } => {
                if !indirect.is_empty() {
                    serializer.serialize_str(&format!("plugin {id}[{indirect}]"))
                } else {
                    serializer.serialize_str(&format!("plugin {id}"))
                }
            }
        }
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
    Time(FlowComp, chrono::NaiveTime),
    GeoIp(String), // geoip关键词匹配
    /// 取反内层条件的求值结果，包括"信息缺失"导致的 false（例如没有客户端 IP 时 `cnip` 恒为
    /// false，因而 `not cnip true` 恒为 true）。
    Not(Box<FlowCond>),
    /// 本次取件是否由调度器自身发起。用来把只对真实客户端有意义的层与内部取件分开。
    Internal(bool),
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
