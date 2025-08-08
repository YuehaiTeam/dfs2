use std::str::FromStr;

use serde::{Deserialize, Serialize};
use size::Size;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FlowsList(pub Vec<FlowItem>);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub enum FlowMode {
    #[serde(rename = "and")]
    AND,
    #[serde(rename = "or")]
    #[default]
    OR,
}

#[derive(Debug, Clone)]
pub enum FlowUse {
    // clear
    Clear,
    // server id server id weight
    Server { id: String, weight: u32 },
    // plugin id plugin id indirect
    Plugin { id: String, indirect: String },
    // poolize
    Poolize,
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
            Err(serde::de::Error::custom(format!("Invalid FlowUse: {}", s)))
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
            FlowUse::Server { id, weight } => {
                if *weight > 0 {
                    serializer.serialize_str(&format!("server {}[{}]", id, weight))
                } else {
                    serializer.serialize_str(&format!("server {}", id))
                }
            }
            FlowUse::Plugin { id, indirect } => {
                if !indirect.is_empty() {
                    serializer.serialize_str(&format!("plugin {}[{}]", id, indirect))
                } else {
                    serializer.serialize_str(&format!("plugin {}", id))
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
            _ => Err(format!("Invalid FlowComp: {}", s)),
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
            _ => Err(serde::de::Error::custom(format!("Invalid FlowComp: {}", s))),
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
    ServerBwDaily(String, FlowComp, Size), // 服务器级别的日流量限制，必须指定server_id
    Time(FlowComp, chrono::NaiveTime),
    GeoIp(String), // geoip关键词匹配
}
impl<'de> Deserialize<'de> for FlowCond {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        // split by space, first is type
        let parts: Vec<&str> = s.split_whitespace().collect();
        let method = parts[0];
        match method {
            "cnip" => {
                let value = parts[1].parse::<bool>().map_err(serde::de::Error::custom)?;
                Ok(FlowCond::CnIp(value))
            }
            "ipversion" => {
                let version = parts[1].parse::<u8>().map_err(serde::de::Error::custom)?;
                if version != 4 && version != 6 {
                    return Err(serde::de::Error::custom("IP version must be 4 or 6"));
                }
                Ok(FlowCond::IpVersion(version))
            }
            "cidr" => {
                let cidr = parts[1]
                    .parse::<cidr::IpCidr>()
                    .map_err(serde::de::Error::custom)?;
                Ok(FlowCond::Cidr(cidr))
            }
            "extras" => {
                let extras = parts[1].to_string();
                Ok(FlowCond::Extras(extras))
            }
            "geoip" => {
                let keyword = parts[1].to_string();
                Ok(FlowCond::GeoIp(keyword))
            }
            "size" => {
                let comp = FlowComp::from_str(parts[1]).map_err(serde::de::Error::custom)?;
                let size = Size::from_str(parts[2]).map_err(serde::de::Error::custom)?;
                Ok(FlowCond::Size(comp, size))
            }
            "bw_daily" => {
                if parts.len() == 3 {
                    // 旧格式：bw_daily <comp> <size> - 视为当前资源
                    let comp = FlowComp::from_str(parts[1]).map_err(serde::de::Error::custom)?;
                    let size = Size::from_str(parts[2]).map_err(serde::de::Error::custom)?;
                    Ok(FlowCond::ResourceBwDaily(ResourcePattern::Current, comp, size))
                } else if parts.len() == 4 {
                    // 新格式：bw_daily <resource> <comp> <size>
                    let resource_pattern = match parts[1] {
                        "*" => ResourcePattern::Global,
                        "$" => ResourcePattern::Current,
                        resource_id => ResourcePattern::Specific(resource_id.to_string()),
                    };
                    let comp = FlowComp::from_str(parts[2]).map_err(serde::de::Error::custom)?;
                    let size = Size::from_str(parts[3]).map_err(serde::de::Error::custom)?;
                    Ok(FlowCond::ResourceBwDaily(resource_pattern, comp, size))
                } else {
                    return Err(serde::de::Error::custom(
                        "bw_daily requires format: bw_daily [resource] {comp} {size}"
                    ));
                }
            }
            "server_bw_daily" => {
                if parts.len() != 4 {
                    return Err(serde::de::Error::custom(
                        "server_bw_daily requires format: server_bw_daily {server_id} {comp} {size}"
                    ));
                }
                let server_id = parts[1].to_string();
                let comp = FlowComp::from_str(parts[2]).map_err(serde::de::Error::custom)?;
                let size = Size::from_str(parts[3]).map_err(serde::de::Error::custom)?;
                Ok(FlowCond::ServerBwDaily(server_id, comp, size))
            }
            "time" => {
                let comp = FlowComp::from_str(parts[1]).map_err(serde::de::Error::custom)?;
                let time = chrono::NaiveTime::parse_from_str(parts[2], "%H:%M:%S")
                    .map_err(serde::de::Error::custom)?;
                Ok(FlowCond::Time(comp, time))
            }
            _ => Err(serde::de::Error::custom(format!("Invalid FlowCond: {}", s))),
        }
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

        let use_plugin: FlowUse = serde_yaml::from_str("plugin test_plugin some_data").unwrap();
        assert!(
            matches!(use_plugin, FlowUse::Plugin { ref id, ref indirect } if id == "test_plugin" && indirect == "some_data")
        );
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
        assert_eq!(item.r#break, false);
        assert!(item.r#use.is_empty());
        assert!(item.rules.is_empty());
    }
}

impl Serialize for FlowCond {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FlowCond::CnIp(value) => serializer.serialize_str(&format!("cnip {}", value)),
            FlowCond::IpVersion(version) => {
                serializer.serialize_str(&format!("ipversion {}", version))
            }
            FlowCond::Cidr(cidr) => serializer.serialize_str(&format!("cidr {}", cidr)),
            FlowCond::Extras(extras) => serializer.serialize_str(&format!("extras {}", extras)),
            FlowCond::GeoIp(keyword) => serializer.serialize_str(&format!("geoip {}", keyword)),
            FlowCond::Size(comp, size) => {
                serializer.serialize_str(&format!("size {} {}", comp, size))
            }
            FlowCond::ResourceBwDaily(pattern, comp, size) => {
                let pattern_str = match pattern {
                    ResourcePattern::Global => "*",
                    ResourcePattern::Current => "$",
                    ResourcePattern::Specific(resource_id) => resource_id,
                };
                serializer.serialize_str(&format!("bw_daily {} {} {}", pattern_str, comp, size))
            }
            FlowCond::ServerBwDaily(server_id, comp, size) => {
                serializer.serialize_str(&format!("server_bw_daily {} {} {}", server_id, comp, size))
            }
            FlowCond::Time(comp, time) => {
                serializer.serialize_str(&format!("time {} {}", comp, time))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FlowItem {
    #[serde(default)]
    pub mode: FlowMode,
    #[serde(default)]
    pub r#break: bool,
    #[serde(default)]
    pub r#use: Vec<FlowUse>,
    #[serde(default)]
    pub rules: Vec<FlowCond>,
}
