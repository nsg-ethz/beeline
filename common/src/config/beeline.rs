use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub socket: Option<SocketAddr>,
    pub tls: Option<SocketAddr>,
    pub proxy: Option<SocketAddr>,
    #[serde(default)]
    pub stats: bool,
    pub hosts: Vec<Host>,
    #[serde(default, rename = "accelerate")]
    pub network: Option<Cidr>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    pub routes: Vec<Route>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Cidr {
    pub addr: Ipv4Addr,
    pub mask: u32,
}

impl Cidr {
    pub fn len(&self) -> u32 {
        2u32.pow(32 - self.mask)
    }
}

impl Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.mask)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CidrParseRangeError;

impl Display for CidrParseRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid CIDR range")
    }
}

impl FromStr for Cidr {
    type Err = CidrParseRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(CidrParseRangeError);
        }
        let addr = match parts[0].parse::<IpAddr>() {
            Ok(addr) => addr,
            Err(_) => return Err(CidrParseRangeError),
        };
        let addr = match addr {
            IpAddr::V4(addr) => addr,
            IpAddr::V6(_) => return Err(CidrParseRangeError),
        };
        let mask = match parts[1].parse::<u32>() {
            Ok(mask) => mask,
            Err(_) => return Err(CidrParseRangeError),
        };
        Ok(Cidr { addr, mask })
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for Cidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let v = format!("{}/{}", self.addr, self.mask);
        serializer.serialize_str(&v)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub name: String,
    pub method: Option<String>,
    pub path: Option<String>,

    #[serde(rename = "destination_ip")]
    pub dest_ip4: Option<IpAddr>,
    #[serde(rename = "destination_port")]
    pub dest_port: Option<u16>,

    #[serde(rename = "source_ip")]
    pub src_ip4: Option<IpAddr>,

    pub headers: Option<HashMap<String, String>>,

    pub allow: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(alias = "match")]
    pub pattern: Pattern,
    pub dest: String,

    #[serde(default)]
    pub filters: Vec<Filter>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Filter {
    #[serde(rename = "jwt")]
    Jwt(JwtFilter),

    #[serde(rename = "mutate")]
    Mutate(MutateFilter),
}

impl Filter {
    pub fn is_jwt(&self) -> bool {
        match self {
            Filter::Jwt(_) => true,
            _ => false,
        }
    }

    pub fn is_mutate(&self) -> bool {
        match self {
            Filter::Mutate(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct JwtFilter {
    pub secret: String,
    pub audience: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MutateFilter {
    pub add: Option<HashMap<String, String>>,
    pub remove: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub name: String,
    #[serde(default)]
    pub load_balancer: Option<LoadBalancer>,
    pub instances: Vec<SocketAddr>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum LoadBalancer {
    #[serde(rename = "ring")]
    Ring(RingLoadBalancer),
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RingLoadBalancer {
    pub size: usize,
}

impl Config {
    pub fn resolve_host(&self, name: &str) -> Option<Host> {
        if name.eq_ignore_ascii_case("proxy") {
            if let Some(addr) = self.proxy {
                return Some(Host {
                    name: "proxy".to_string(),
                    load_balancer: None,
                    instances: vec![addr],
                });
            }
        }

        self.hosts.iter().find(|host| host.name == *name).cloned()
    }

    pub fn all_backend_instances(&self, backend: &str) -> Option<&Vec<SocketAddr>> {
        let host = self.hosts.iter().find(|host| host.name == *backend)?;

        Some(&host.instances)
    }
}
