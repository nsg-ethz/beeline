use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub static_resources: StaticResources,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct StaticResources {
    pub clusters: Vec<Cluster>,
    pub listeners: Vec<Listener>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Cluster {
    pub name: String,
    pub lb_policy: String,
    pub load_assignment: LoadAssignment,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct LoadAssignment {
    pub cluster_name: String,
    pub endpoints: Vec<LoadEndpoint>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct LoadEndpoint {
    pub lb_endpoints: Vec<LbEndpoint>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct LbEndpoint {
    pub endpoint: Endpoint,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Endpoint {
    pub address: EndpointAddr,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct EndpointAddr {
    pub socket_address: SocketAddr,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct SocketAddr {
    pub address: String,
    pub port_value: u16,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Listener {
    pub name: String,
    pub address: EndpointAddr,
    pub filter_chains: Vec<FilterChain>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct FilterChain {
    pub filters: Vec<Filter>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Filter {
    pub name: String,
    pub typed_config: TypedFilterConfig,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct TypedFilterConfig {
    pub route_config: RouteConfig,
    pub http_filters: Vec<HttpFilter>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(tag = "name")]
pub enum HttpFilter {
    #[serde(rename = "envoy.filters.http.JwtAuthentication")]
    Jwt(JwtFilter),

    #[serde(other)]
    Unsupported,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct JwtFilter {
    pub typed_config: TypedJwtConfig,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct TypedJwtConfig {
    pub providers: Vec<JwtProvider>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct JwtProvider {
    pub issuer: Option<String>,
    pub audiences: Option<Vec<String>>,
    pub local_jwks: LocalJwks,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct LocalJwks {
    pub inline_string: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct RouteConfig {
    pub name: String,
    pub virtual_hosts: Vec<VirtualHost>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct VirtualHost {
    pub name: String,
    pub routes: Vec<Route>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Route {
    pub r#match: RouteMatch,
    pub route: RouteAction,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct RouteMatch {
    pub prefix: String,
    pub headers: Vec<HeaderMatch>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct HeaderMatch {
    pub name: String,
    pub string_match: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct RouteAction {
    pub cluster: String,
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_deserializes_envoy_config() {
        let manifest_dir =
            std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
        let config_path = format!(
            "{}/../config/envoy/http1.yaml",
            manifest_dir.to_str().unwrap()
        );

        let config = std::fs::File::open(config_path).expect("Failed to find config file");
        let _: Config =
            serde_yaml::from_reader(config).expect("Failed to deserialize Envoy config");
    }
}
