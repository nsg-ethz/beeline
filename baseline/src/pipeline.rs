use anyhow::{anyhow, bail, Result};
use common::Config;
use hmac::{Hmac, Mac};
use httparse::Status;
use jwt::VerifyWithKey;
use log::{debug, trace};
use rand::{self, seq::SliceRandom};
use sha2::Sha256;
use tokio::{task, time};
use std::{collections::{BTreeMap, HashMap, HashSet}, net::SocketAddr, sync::{Arc, RwLock}, time::Duration, u32};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DownstreamState {
    num_bytes: u32,
    num_reqs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpstreamLoadState {
    num_bytes: u32,
    num_reqs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpstreamState {
    reserved: bool
}

struct Context {
    hdrs: HashMap<String, String>,
    origin: SocketAddr,
    ft: ForwardingToken,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
enum Direction {
    #[default]
    Downstream,
    Upstream,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Exisiting(SocketAddr),
    New(SocketAddr, ForwardingToken),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum ForwardingDimension<T: PartialEq> {
    Concrete(T),
    Min,
    DontCare
}

impl<T> ForwardingDimension<T> where T: PartialEq {

    fn concrete_val(&self) -> Option<&T> {
        match &self {
            &ForwardingDimension::Concrete(val) => Some(val),
            _ => None
        }
    }

}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ForwardingToken {
    reserved: ForwardingDimension<bool>,
    conn_id: ForwardingDimension<u32>,
    direction: ForwardingDimension<Direction>,
    backend: ForwardingDimension<u8>,
    instance: ForwardingDimension<u16>
}

impl ForwardingToken {

    fn dont_care() -> ForwardingToken {
        ForwardingToken {
            reserved: ForwardingDimension::DontCare,
            conn_id: ForwardingDimension::DontCare,
            direction: ForwardingDimension::DontCare,
            backend: ForwardingDimension::DontCare,
            instance: ForwardingDimension::DontCare
        }
    }

}

pub struct Pipeline {
    config: Arc<Config>,
    ds_state: Arc<RwLock<HashMap<SocketAddr, DownstreamState>>>,
    us_state: Arc<RwLock<HashMap<SocketAddr, UpstreamState>>>,
    us_load_state: Arc<RwLock<HashMap<(u8, u16), UpstreamLoadState>>>,
    fib: Arc<RwLock<HashMap<ForwardingToken, SocketAddr>>>,
    min_instance: Arc<RwLock<HashMap<ForwardingToken, u16>>>,
}

impl Pipeline {

    pub fn new(config: Config) -> Self {
        Pipeline {
            config: Arc::new(config),
            ds_state: Arc::new(RwLock::new(HashMap::new())),
            us_state: Arc::new(RwLock::new(HashMap::new())),
            us_load_state: Arc::new(RwLock::new(HashMap::new())),
            fib: Arc::new(RwLock::new(HashMap::new())),
            min_instance: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn start_updating_fib(&self, freq: Duration) {
        let us_state = self.us_state.clone();
        let us_load_state = self.us_load_state.clone();
        let fib = self.fib.clone();
        let min_instance = self.min_instance.clone();

        task::spawn(async move {
            let mut interval = time::interval(freq);
    
            loop {
                interval.tick().await;

                let us_load_states = us_load_state.read().unwrap();
                let us_state = us_state.read().unwrap();
                let fib = fib.read().unwrap();
                let mut min_instance = min_instance.write().unwrap();

                // find all the possible groups over which we want to find the min instance
                // this works by finding all unique possibilities for connections that have an instance assigned
                let groups = fib.iter()
                    .filter(|(ft, _)| ft.instance != ForwardingDimension::DontCare)
                    .map(|(ft, _)| {
                        let mut ft = ft.clone();
                        ft.instance = ForwardingDimension::Min;

                        ft
                    })
                    .collect::<HashSet<_>>()
                    .clone();

                // for each group, find the min instance
                for g in groups.into_iter() {
                    let instance = fib.iter()
                        .filter(|(ft, _)| ft.reserved == g.reserved && ft.conn_id == g.conn_id && ft.direction == g.direction && ft.backend == g.backend) // filter for all elements in the same group
                        .filter(|(_, addr)| {
                            if let Some(state) = us_state.get(&addr) {
                                !state.reserved
                            }
                            else {
                                true
                            }
                        }) 
                        .min_by_key(|(ft, _)| {
                            let backend = *ft.backend.concrete_val().unwrap();
                            let instance = *ft.instance.concrete_val().unwrap();
                            us_load_states.get(&(backend, instance)).map(|s| s.num_bytes).unwrap_or(u32::MAX)
                        })
                        .map(|(ft, _)| ft.instance.concrete_val().unwrap().clone())
                        .unwrap();

                    min_instance.insert(g, instance);
                }
            }
        });
    }

    pub async fn process(self: &Arc<Self>, buf: &mut Vec<u8>, origin: SocketAddr, is_downstream: bool) -> Result<Destination> {
        trace!("Processing msg from {:?}", origin);

        // TODO: this should only parse once to make it a fair comparison
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let (hdrs, len) = if is_downstream {
            let mut req = httparse::Request::new(&mut headers);
            let hdr_len = match req.parse(&buf) {
                Ok(Status::Complete(len)) => len,
                Ok(Status::Partial) => return Err(anyhow!("Partial request")),
                Err(e) => return Err(anyhow!(e)),
            };

            (req.headers, hdr_len)
        } 
        else {
            let mut res = httparse::Response::new(&mut headers);
            let hdr_len = match res.parse(&buf) {
                Ok(Status::Complete(len)) => len,
                Ok(Status::Partial) => return Err(anyhow!("Partial response")),
                Err(e) => return Err(anyhow!(e)),
            };

            (res.headers, hdr_len)
        };

        let hdrs = hdrs.iter()
            .map(|hdr| (hdr.name.to_string().to_lowercase(), String::from_utf8(hdr.value.to_vec()).unwrap()))
            .collect();

        let mut ctx = Context { hdrs, origin, ft: ForwardingToken::dont_care() };

        if is_downstream {
            self.authenticate(&mut ctx).await?;
            self.update_ds_conn(&mut ctx)?;
            self.forward_ds_conn(&mut ctx).await?;

            let conn_id_hdr = format!("conn-id: {}\r\n", origin.port());
            buf.splice(len-2..len-2, conn_id_hdr.bytes());
        } 
        else {
            self.update_us_conn(&mut ctx).await?;
            self.forward_us_conn(&mut ctx).await?;
        }

        let dest = self.select_sock(&mut ctx).await?;

        if is_downstream {
            self.post_decision_update_us_conn(&mut ctx, &dest).await?;
        }

        Ok(dest)
    }

    async fn authenticate(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let token = ctx.hdrs.get("authorization")
            .ok_or_else(|| anyhow!("No Authorization header found"))?;
        let token = token.strip_prefix("Bearer")
            .expect("Invalid auth token")
            .split("\r\n")
            .next()
            .expect("Invalid auth token")
            .trim();

        let key: Hmac<Sha256> = Hmac::new_from_slice(b"testtest12345678")?;
        match token.verify_with_key(&key) {
            Ok::<BTreeMap<String, String>, _>(_) => Ok(()),
            Err(_) => Err(anyhow!("Invalid token: {token}"))
        }
    }

    fn update_ds_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        self.ds_state.write()
            .unwrap()
            .entry(ctx.origin)
            .and_modify(|state| {
                state.num_reqs += 1;
                state.num_bytes += ctx.hdrs.len() as u32;
            })
            .or_insert(DownstreamState {
                num_reqs: 1,
                num_bytes: ctx.hdrs.len() as u32,
            });

        Ok(())
    }

    async fn update_us_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let backend = ctx.hdrs.get("signature");
        if backend.is_none() || backend.unwrap().len() == 0 {
            bail!("Response without signature: {:?}", ctx.hdrs.keys());
        }

        let backend = backend.unwrap()
            .chars()
            .last()
            .unwrap()
            .to_digit(10)
            .unwrap() as u8;

        self.us_load_state.write()
            .unwrap()
            .entry((backend, ctx.origin.port()))
            .and_modify(|state| {
                state.num_reqs += 1;
                state.num_bytes += ctx.hdrs.len() as u32;
            })
            .or_insert(UpstreamLoadState {
                num_reqs: 1,
                num_bytes: ctx.hdrs.len() as u32,
            });

        self.us_state.write()    
            .unwrap()
            .entry(ctx.origin)
            .and_modify(|state| {
                state.reserved = false
            })
            .or_insert(UpstreamState {
                reserved: false
            });

        Ok(())
    }

    async fn forward_ds_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let backend = ctx.hdrs.get("backend").ok_or_else(|| anyhow!("No Backend header found"))?;
        let backend = match backend.as_str() {
            "server1" => 1,
            "server2" => 2,
            "server3" => 3,
            "server4" => 4,
            _ => return Err(anyhow!("Invalid backend"))
        };

        ctx.ft.reserved = ForwardingDimension::Concrete(false);
        ctx.ft.direction = ForwardingDimension::Concrete(Direction::Upstream);
        ctx.ft.backend = ForwardingDimension::Concrete(backend);
        ctx.ft.instance = ForwardingDimension::Min;

        let ft_inv = ForwardingToken {
            reserved: ForwardingDimension::Concrete(false),
            conn_id: ForwardingDimension::Concrete(ctx.origin.port() as u32),
            direction: ForwardingDimension::Concrete(Direction::Downstream),
            backend: ForwardingDimension::DontCare,
            instance: ForwardingDimension::DontCare
        };

        self.fib.write()
            .unwrap()
            .insert(ft_inv, ctx.origin);

        Ok(())
    }

    async fn forward_us_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let conn_id = ctx.hdrs.get("conn-id")
            .ok_or_else(|| anyhow!("No conn-id header found"))?
            .parse()?;
        ctx.ft.reserved = ForwardingDimension::Concrete(false);
        ctx.ft.conn_id = ForwardingDimension::Concrete(conn_id);
        ctx.ft.direction = ForwardingDimension::Concrete(Direction::Downstream);

        Ok(())
    }

    async fn select_sock(self: &Arc<Self>, ctx: &mut Context) -> Result<Destination> {
        trace!("Selecting sock for {:?}", ctx.ft);

        // check if we have to retrieve the min instance for that group
        let ft = if ctx.ft.instance == ForwardingDimension::Min {
            let min_instance = self.min_instance.read().unwrap();
            let instance = min_instance.get(&ctx.ft);
            debug!("{:?}", min_instance.keys());

            if let Some(instance) = instance {
                let mut ft = ctx.ft.clone();
                ft.instance = ForwardingDimension::Concrete(instance.clone());
                debug!("Min instance is {}", instance);

                ft
            }
            else {
                ctx.ft.clone()
            }
        }
        else {
            ctx.ft.clone()
        };

        let fib = self.fib.read().unwrap();
        let addr = fib.get(&ft);

        if let Some(addr) = addr {
            Ok(Destination::Exisiting(addr.clone()))
        } 
        else {
            if ctx.ft.direction.concrete_val() == Some(&Direction::Downstream) {
                bail!("No socket found for downstream connection: {:?}", ctx.ft);
            }

            let backend = ctx.ft.backend.concrete_val().unwrap();
            let addr = self.resolve_preconfigured_instance_rand(*backend);
            if addr.is_none() {
                bail!("Could not resolve preconfigured address for backend {}", backend);
            }
            let addr = addr.unwrap();

            let ft = ForwardingToken {
                reserved: ForwardingDimension::Concrete(false),
                conn_id: ForwardingDimension::DontCare,
                direction: ForwardingDimension::Concrete(Direction::Upstream),
                backend: ctx.ft.backend.clone(),
                instance: ForwardingDimension::Concrete(addr.port())
            };

            Ok(Destination::New(addr, ft))
        }
    }

    async fn post_decision_update_us_conn(self: &Arc<Self>, _ctx: &mut Context, dest: &Destination) -> Result<()> {
        if let &Destination::Exisiting(addr) = dest {
            self.us_state.write()    
                .unwrap()
                .entry(addr)
                .and_modify(|state| {
                    state.reserved = true
                })
                .or_insert(UpstreamState {
                    reserved: true
                });
        }

        Ok(())
    }

    pub async fn add_sock(self: &Arc<Self>, ft: ForwardingToken, addr: SocketAddr) {
        trace!("Add {:?} to FIB", ft);
        self.fib.write()
            .unwrap()
            .insert(ft, addr);
    }

    fn resolve_preconfigured_instance_rand(self: &Arc<Self>, backend: u8) -> Option<SocketAddr> {
        let name = format!("server{}", backend);

        let addr = self.config.hosts.iter()
            .find(|host| host.name == name)
            .and_then(|host| {
                host.instances.choose(&mut rand::thread_rng())
            })?;

        addr.parse().ok()
    }

}