use std::str::FromStr;

use serde::{Deserialize, Serialize};
use size::Size;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FlowsList(pub Vec<FlowItem>);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[derive(Default)]
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

#[derive(Debug, Clone)]
#[derive(Default)]
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

#[derive(Debug, Clone)]
pub enum FlowCond {
    CnIp(bool),
    Cidr(cidr::IpCidr),
    Extras(String),
    Size(FlowComp, Size),
    BwDaily(FlowComp, Size),
    Time(FlowComp, chrono::NaiveTime),
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
            "size" => {
                let comp = FlowComp::from_str(parts[1]).map_err(serde::de::Error::custom)?;
                let size = Size::from_str(parts[2]).map_err(serde::de::Error::custom)?;
                Ok(FlowCond::Size(comp, size))
            }
            "bw_daily" => {
                let comp = FlowComp::from_str(parts[1]).map_err(serde::de::Error::custom)?;
                let size = Size::from_str(parts[2]).map_err(serde::de::Error::custom)?;
                Ok(FlowCond::BwDaily(comp, size))
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

impl Serialize for FlowCond {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            FlowCond::CnIp(value) => serializer.serialize_str(&format!("cnip {}", value)),
            FlowCond::Cidr(cidr) => serializer.serialize_str(&format!("cidr {}", cidr)),
            FlowCond::Extras(extras) => serializer.serialize_str(&format!("extras {}", extras)),
            FlowCond::Size(comp, size) => {
                serializer.serialize_str(&format!("size {} {}", comp, size))
            }
            FlowCond::BwDaily(comp, size) => {
                serializer.serialize_str(&format!("bw_daily {} {}", comp, size))
            }
            FlowCond::Time(comp, time) => {
                serializer.serialize_str(&format!("time {} {}", comp, time))
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
