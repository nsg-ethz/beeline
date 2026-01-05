use anyhow::{bail, Result};
use clap::Parser;
use common::config::{
    beeline::{Config as BConfig, Filter, JwtFilter as BJwtFilter, MutateFilter},
    envoy::{Config as EConfig, HeaderMatch},
};
use std::{collections::HashMap, fs::File, path::Path, str::FromStr};

const KEYS: &str = "abcdefghijklmopqrstuvwxyz";

#[derive(Debug, Clone, Copy)]
enum Target {
    Beeline,
    Envoy,
}

impl FromStr for Target {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "beeline" => Ok(Target::Beeline),
            "envoy" => Ok(Target::Envoy),
            _ => Err(format!("Invalid target: {}", s)),
        }
    }
}

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    target: Target,

    #[arg(long)]
    n1: Option<usize>,

    #[arg(long)]
    m1: Option<usize>,

    #[arg(long)]
    n2: Option<usize>,

    #[arg(long)]
    n3: Option<usize>,

    #[arg(long)]
    m3: Option<usize>,

    #[arg(long)]
    n4: Option<usize>,

    #[arg(short, long)]
    out: String,

    #[arg(long)]
    template: Option<String>,

    #[arg(short, long, default_value = "config")]
    config_dir: String,
}

fn load_config<C: serde::de::DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<C> {
    let file = File::open(path)?;
    serde_yaml::from_reader(&file).map_err(anyhow::Error::new)
}

fn generate_policy1_args(n: usize, m: usize) -> HashMap<String, String> {
    let mut args = HashMap::new();
    let val = str::repeat("a", m);
    for i in 0..n {
        let key = KEYS.chars().nth(i).unwrap();
        args.insert(key.to_string(), val.clone());
    }

    args
}

fn generate_policy3_args(n: usize, m: usize) -> HashMap<String, String> {
    let iss = str::repeat("a", n);
    let aud = str::repeat("a", m);

    HashMap::from([("iss".to_string(), iss), ("aud".to_string(), aud)])
}

fn generate_policy4_args(n: usize) -> Vec<String> {
    let mut keys = Vec::new();
    for i in 0..n {
        let key = KEYS.chars().nth(i).unwrap();
        keys.push(key.to_string());
    }

    keys
}

fn generate_beeline_policy1(config: &mut BConfig, n: usize, m: usize) -> Result<()> {
    let hdrs = generate_policy1_args(n, m);
    for route in config.routes.iter_mut() {
        route.pattern.headers = Some(hdrs.clone());
    }

    Ok(())
}

fn generate_envoy_policy1(config: &mut EConfig, n: usize, m: usize) -> Result<()> {
    let hdrs = generate_policy1_args(n, m)
        .iter()
        .map(|(k, v)| HeaderMatch {
            name: k.clone(),
            string_match: HashMap::from([(String::from("exact"), v.clone())]),
        })
        .collect::<Vec<_>>();

    for listeners in config.static_resources.listeners.iter_mut() {
        for chain in listeners.filter_chains.iter_mut() {
            for filter in chain.filters.iter_mut() {
                for host in filter.typed_config.route_config.virtual_hosts.iter_mut() {
                    for route in host.routes.iter_mut() {
                        route.r#match.headers = hdrs.clone();
                    }
                }
            }
        }
    }

    Ok(())
}

fn generate_beeline_policy2(config: &mut BConfig, n: usize) -> Result<()> {
    assert!(n >= 3);
    config.policies = config.policies[config.policies.len() - n..].to_vec();

    Ok(())
}

fn generate_envoy_policy2(config: &mut EConfig, n: usize) -> Result<()> {
    assert!(n >= 3);
    for listeners in config.static_resources.listeners.iter_mut() {
        for chain in listeners.filter_chains.iter_mut() {
            for filter in chain.filters.iter_mut() {
                for http_filter in filter.typed_config.http_filters.iter_mut() {
                    let name = http_filter.get("name").unwrap();
                    if name == "envoy.filters.http.rbac" {
                        let typed_config = http_filter.get_mut("typed_config").unwrap();
                        let rules = typed_config
                            .get_mut("rules")
                            .unwrap()
                            .as_mapping_mut()
                            .unwrap();

                        let policies = rules.get_mut("policies").unwrap().as_mapping().unwrap();

                        let mut policy_keys = vec![
                            "service-1-post-policy-v1",
                            "service-2-post-policy-v1",
                            "service-3-post-policy-v1",
                        ];
                        for k in policies.keys() {
                            if policy_keys.len() == n {
                                break;
                            }

                            let k = k.as_str().unwrap();
                            if !policy_keys.contains(&k) {
                                policy_keys.insert(0, k);
                            }
                        }

                        let mut new_policies = serde_yaml::Mapping::new();
                        for k in policy_keys.iter() {
                            let k = serde_yaml::Value::from(k.to_string());
                            new_policies.insert(k.clone(), policies.get(k).unwrap().clone());
                        }

                        rules.insert(
                            serde_yaml::Value::from("policies"),
                            serde_yaml::Value::from(new_policies),
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

fn generate_beeline_policy3(config: &mut BConfig, n: usize, m: usize) -> Result<()> {
    let claims = generate_policy3_args(n, m);
    let filter = BJwtFilter {
        secret: String::from("testtest12345678"),
        issuer: Some(claims["iss"].clone()),
        audience: Some(claims["aud"].clone()),
    };

    for route in config.routes.iter_mut() {
        route.filters.push(Filter::Jwt(filter.clone()));
    }

    Ok(())
}

fn generate_envoy_policy3(config: &mut EConfig, n: usize, m: usize) -> Result<()> {
    let claims = generate_policy3_args(n, m);

    for listeners in config.static_resources.listeners.iter_mut() {
        for chain in listeners.filter_chains.iter_mut() {
            for filter in chain.filters.iter_mut() {
                for http_filter in filter.typed_config.http_filters.iter_mut() {
                    let name = http_filter.get("name").unwrap();
                    if name == "envoy.filters.http.JwtAuthentication" {
                        let typed_config = http_filter.get_mut("typed_config").unwrap();
                        let providers = typed_config
                            .get_mut("providers")
                            .unwrap()
                            .as_mapping_mut()
                            .unwrap();

                        for provider in providers.values_mut() {
                            let provider = provider.as_mapping_mut().unwrap();

                            provider.insert(
                                serde_yaml::Value::from("issuer"),
                                serde_yaml::Value::from(claims.get("iss").unwrap().clone()),
                            );
                            provider.insert(
                                serde_yaml::Value::from("audiences"),
                                serde_yaml::Value::from(vec![serde_yaml::Value::from(
                                    claims.get("aud").unwrap().clone(),
                                )]),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn generate_beeline_policy4(config: &mut BConfig, n: usize) -> Result<()> {
    let keys = generate_policy4_args(n);
    let filter = MutateFilter {
        remove: Some(keys),
        add: None,
    };

    for route in config.routes.iter_mut() {
        route.filters.push(Filter::Mutate(filter.clone()));
    }

    Ok(())
}

fn generate_envoy_policy4(config: &mut EConfig, n: usize) -> Result<()> {
    let keys = generate_policy4_args(n);
    for listeners in config.static_resources.listeners.iter_mut() {
        for chain in listeners.filter_chains.iter_mut() {
            for filter in chain.filters.iter_mut() {
                for host in filter.typed_config.route_config.virtual_hosts.iter_mut() {
                    for route in host.routes.iter_mut() {
                        route.request_headers_to_remove = keys.clone();
                    }
                }
            }
        }
    }

    Ok(())
}

fn generate(args: Args) -> Result<()> {
    let max_policy = if args.n4.is_some() {
        4
    } else if args.n3.is_some() || args.m3.is_some() {
        3
    } else if args.n2.is_some() {
        2
    } else if args.n1.is_some() || args.m1.is_some() {
        1
    } else {
        bail!("No policy specified");
    };

    match args.target {
        Target::Beeline => {
            let path = args.template.unwrap_or(format!(
                "{}/beeline/ssm-p{}.yaml",
                args.config_dir, max_policy
            ));
            let mut config: BConfig = load_config(path)?;
            let mut num_policies = 0;

            if let (Some(n1), Some(m1)) = (args.n1, args.m1) {
                generate_beeline_policy1(&mut config, n1, m1)?;
                num_policies += 1;
            }

            if let Some(n2) = args.n2 {
                generate_beeline_policy2(&mut config, n2)?;
                num_policies += 1;
            }

            if let (Some(n3), Some(m3)) = (args.n3, args.m3) {
                generate_beeline_policy3(&mut config, n3, m3)?;
                num_policies += 1;
            }

            if let Some(n4) = args.n4 {
                generate_beeline_policy4(&mut config, n4)?;
                num_policies += 1;
            }

            if num_policies != max_policy {
                bail!("Failed to generate the correct number of policies");
            }

            let mut file = File::create(args.out)?;
            serde_yaml::to_writer(&mut file, &config)?;
        }
        Target::Envoy => {
            let path = args.template.unwrap_or(format!(
                "{}/envoy/ssm-p{}.yaml",
                args.config_dir, max_policy
            ));
            let mut config: EConfig = load_config(path)?;
            let mut num_policies = 0;

            if let (Some(n1), Some(m1)) = (args.n1, args.m1) {
                generate_envoy_policy1(&mut config, n1, m1)?;
                num_policies += 1;
            }

            if let Some(n2) = args.n2 {
                generate_envoy_policy2(&mut config, n2)?;
                num_policies += 1;
            }

            if let (Some(n3), Some(m3)) = (args.n3, args.m3) {
                generate_envoy_policy3(&mut config, n3, m3)?;
                num_policies += 1;
            }

            if let Some(n4) = args.n4 {
                generate_envoy_policy4(&mut config, n4)?;
                num_policies += 1;
            }

            if num_policies != max_policy {
                bail!("Failed to generate the correct number of policies");
            }

            let mut file = File::create(args.out)?;
            serde_yaml::to_writer(&mut file, &config)?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    generate(args)
}

#[cfg(test)]
mod tests {

    use super::*;

    fn generate_config<C: serde::de::DeserializeOwned>(
        n1: Option<usize>,
        m1: Option<usize>,
        n2: Option<usize>,
        n3: Option<usize>,
        m3: Option<usize>,
        n4: Option<usize>,
        target: Target,
    ) -> C {
        let manifest_dir =
            std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set");
        let path = format!("{}/../res/pol/test.yaml", manifest_dir.to_str().unwrap());

        let args = Args {
            n1,
            m1,
            n2,
            n3,
            m3,
            n4,
            target,
            out: path.clone(),
            config_dir: format!("{}/../config", manifest_dir.to_str().unwrap()),
            template: None,
        };

        generate(args).expect("Failed to generate policy");

        let config = std::fs::File::open(path).expect("Failed to find config file");
        serde_yaml::from_reader(config).expect("Failed to deserialize config")
    }

    fn assert_beeline_policy1(config: &BConfig) {
        let mut checked = false;
        for route in config.routes.iter() {
            let headers = route.pattern.headers.as_ref().unwrap();
            assert_eq!(headers.len(), 2);
            assert_eq!(*headers.get("a").unwrap(), "a".repeat(20).to_string());
            assert_eq!(*headers.get("b").unwrap(), "a".repeat(20).to_string());
            checked = true;
        }
        assert!(checked);
    }

    fn assert_envoy_policy1(config: &EConfig) {
        let mut checked = false;
        for listeners in config.static_resources.listeners.iter() {
            for chain in listeners.filter_chains.iter() {
                for filter in chain.filters.iter() {
                    for host in filter.typed_config.route_config.virtual_hosts.iter() {
                        for route in host.routes.iter() {
                            assert_eq!(route.r#match.headers.len(), 2);
                            // assert_eq!(*headers.get("a").unwrap(), "a".repeat(20).to_string());
                            // assert_eq!(*headers.get("b").unwrap(), "a".repeat(20).to_string());
                            checked = true;
                        }
                    }
                }
            }
        }
        assert!(checked);
    }

    fn assert_beeline_policy2(config: &BConfig) {
        assert_eq!(config.policies.len(), 13);
    }

    fn assert_envoy_policy2(config: &EConfig) {
        let mut checked = false;
        for listeners in config.static_resources.listeners.iter() {
            for chain in listeners.filter_chains.iter() {
                for filter in chain.filters.iter() {
                    for http_filter in filter.typed_config.http_filters.iter() {
                        let name = http_filter.get("name").unwrap();
                        if name == "envoy.filters.http.rbac" {
                            let typed_config = http_filter.get("typed_config").unwrap();
                            let rules = typed_config.get("rules").unwrap().as_mapping().unwrap();
                            let policies = rules.get("policies").unwrap().as_mapping().unwrap();

                            assert_eq!(policies.len(), 13);
                            checked = true;
                        }
                    }
                }
            }
        }

        assert!(checked);
    }

    fn assert_beeline_policy3(config: &BConfig) {
        let mut checked = false;
        for route in config.routes.iter() {
            let jwt = route.filters.iter().filter(|f| f.is_jwt()).next().unwrap();
            if let Filter::Jwt(jwt) = jwt {
                assert_eq!(jwt.issuer.as_ref().unwrap().len(), 1028);
                assert_eq!(jwt.audience.as_ref().unwrap().len(), 512);
                checked = true;
            }
        }
        assert!(checked);
    }

    fn assert_envoy_policy3(config: &EConfig) {
        let mut checked = false;
        for listeners in config.static_resources.listeners.iter() {
            for chain in listeners.filter_chains.iter() {
                for filter in chain.filters.iter() {
                    for http_filter in filter.typed_config.http_filters.iter() {
                        let name = http_filter.get("name").unwrap();
                        if name == "envoy.filters.http.JwtAuthentication" {
                            let typed_config = http_filter.get("typed_config").unwrap();
                            let providers =
                                typed_config.get("providers").unwrap().as_mapping().unwrap();

                            for provider in providers.values() {
                                let provider = provider.as_mapping().unwrap();

                                assert_eq!(
                                    provider.get("issuer").unwrap().as_str().unwrap().len(),
                                    1028
                                );

                                assert_eq!(
                                    provider
                                        .get("audiences")
                                        .unwrap()
                                        .as_sequence()
                                        .unwrap()
                                        .first()
                                        .unwrap()
                                        .as_str()
                                        .unwrap()
                                        .len(),
                                    512
                                );

                                checked = true;
                            }
                        }
                    }
                }
            }
        }

        assert!(checked);
    }

    fn assert_beeline_policy4(config: &BConfig) {
        let mut checked = false;
        for route in config.routes.iter() {
            let mutate = route
                .filters
                .iter()
                .filter(|f| f.is_mutate())
                .next()
                .unwrap();
            if let Filter::Mutate(mutate) = mutate {
                assert_eq!(
                    mutate.remove.as_ref().unwrap(),
                    &vec!["a".to_string(), "b".to_string(), "c".to_string()]
                );
                checked = true;
            }
        }
        assert!(checked);
    }

    fn assert_envoy_policy4(config: &EConfig) {
        let mut checked = false;
        for listeners in config.static_resources.listeners.iter() {
            for chain in listeners.filter_chains.iter() {
                for filter in chain.filters.iter() {
                    for host in filter.typed_config.route_config.virtual_hosts.iter() {
                        for route in host.routes.iter() {
                            assert_eq!(
                                route.request_headers_to_remove,
                                vec!["a".to_string(), "b".to_string(), "c".to_string()]
                            );
                            checked = true;
                        }
                    }
                }
            }
        }
        assert!(checked);
    }

    #[test]
    fn it_generates_beeline_policy1() {
        let config: BConfig =
            generate_config(Some(2), Some(20), None, None, None, None, Target::Beeline);
        assert_beeline_policy1(&config);
    }

    #[test]
    fn it_generates_beeline_policy2() {
        let config: BConfig = generate_config(
            Some(2),
            Some(20),
            Some(13),
            None,
            None,
            None,
            Target::Beeline,
        );

        assert_beeline_policy1(&config);
        assert_beeline_policy2(&config);
    }

    #[test]
    fn it_generates_beeline_policy3() {
        let config: BConfig = generate_config(
            Some(2),
            Some(20),
            Some(13),
            Some(1028),
            Some(512),
            None,
            Target::Beeline,
        );

        assert_beeline_policy1(&config);
        assert_beeline_policy2(&config);
        assert_beeline_policy3(&config);
    }

    #[test]
    fn it_generates_beeline_policy4() {
        let config: BConfig = generate_config(
            Some(2),
            Some(20),
            Some(13),
            Some(1028),
            Some(512),
            Some(3),
            Target::Beeline,
        );

        assert_beeline_policy1(&config);
        assert_beeline_policy2(&config);
        assert_beeline_policy3(&config);
        assert_beeline_policy4(&config);
    }

    #[test]
    fn it_generates_envoy_policy1() {
        let config: EConfig =
            generate_config(Some(2), Some(20), None, None, None, None, Target::Envoy);
        assert_envoy_policy1(&config);
    }

    #[test]
    fn it_generates_envoy_policy2() {
        let config: EConfig =
            generate_config(Some(2), Some(20), Some(13), None, None, None, Target::Envoy);
        assert_envoy_policy1(&config);
        assert_envoy_policy2(&config);
    }

    #[test]
    fn it_generates_envoy_policy3() {
        let config: EConfig = generate_config(
            Some(2),
            Some(20),
            Some(13),
            Some(1028),
            Some(512),
            None,
            Target::Envoy,
        );

        assert_envoy_policy1(&config);
        assert_envoy_policy2(&config);
        assert_envoy_policy3(&config);
    }

    #[test]
    fn it_generates_envoy_policy4() {
        let config: EConfig = generate_config(
            Some(2),
            Some(20),
            Some(13),
            Some(1028),
            Some(512),
            Some(3),
            Target::Envoy,
        );

        assert_envoy_policy1(&config);
        assert_envoy_policy2(&config);
        assert_envoy_policy3(&config);
        assert_envoy_policy4(&config);
    }
}
