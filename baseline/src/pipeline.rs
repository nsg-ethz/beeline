use anyhow::{anyhow, bail, Result};
use common::Config;
use hmac::{Hmac, Mac};
use httparse::Status;
use jwt::VerifyWithKey;
use log::trace;
use rand::{self, seq::SliceRandom};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
    u32,
};
use tokio::{task, time};

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
    reserved: bool,
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
    DontCare,
}

impl<T> ForwardingDimension<T>
where
    T: PartialEq,
{
    fn concrete_val(&self) -> Option<&T> {
        match &self {
            &ForwardingDimension::Concrete(val) => Some(val),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ForwardingToken {
    conn_id: ForwardingDimension<u32>,
    direction: ForwardingDimension<Direction>,
    backend: ForwardingDimension<String>,
    instance: ForwardingDimension<u16>,
}

impl ForwardingToken {
    fn dont_care() -> ForwardingToken {
        ForwardingToken {
            conn_id: ForwardingDimension::DontCare,
            direction: ForwardingDimension::DontCare,
            backend: ForwardingDimension::DontCare,
            instance: ForwardingDimension::DontCare,
        }
    }
}

pub struct Pipeline {
    config: Arc<Config>,
    ds_state: Arc<RwLock<HashMap<SocketAddr, DownstreamState>>>,
    us_state: Arc<RwLock<HashMap<SocketAddr, UpstreamState>>>,
    us_load_state: Arc<RwLock<HashMap<(String, u16), UpstreamLoadState>>>,
    fib: Arc<RwLock<HashMap<ForwardingToken, Vec<SocketAddr>>>>,
    min_instance: Arc<RwLock<HashMap<ForwardingToken, u16>>>,
}

impl Pipeline {
    pub fn new(config: Config) -> Self {
        let min_instances = config
            .hosts
            .iter()
            .map(|host| {
                let ft = ForwardingToken {
                    conn_id: ForwardingDimension::DontCare,
                    direction: ForwardingDimension::Concrete(Direction::Upstream),
                    backend: ForwardingDimension::Concrete(host.name.clone()),
                    instance: ForwardingDimension::Min,
                };

                (ft, host.instances[0].port())
            })
            .collect();

        Pipeline {
            config: Arc::new(config),
            ds_state: Arc::new(RwLock::new(HashMap::new())),
            us_state: Arc::new(RwLock::new(HashMap::new())),
            us_load_state: Arc::new(RwLock::new(HashMap::new())),
            fib: Arc::new(RwLock::new(HashMap::new())),
            min_instance: Arc::new(RwLock::new(min_instances)),
        }
    }

    pub fn start_updating_fib(&self, freq: Duration) {
        let us_load_state = self.us_load_state.clone();
        let min_instance = self.min_instance.clone();
        let hosts = self.config.hosts.clone();

        task::spawn(async move {
            let mut interval = time::interval(freq);

            loop {
                interval.tick().await;

                let us_load_states = us_load_state.read().unwrap();
                let mut min_instance = min_instance.write().unwrap();

                // for every host in our config, select the one with the smallest load
                for host in hosts.iter() {
                    let instance = host
                        .instances
                        .iter()
                        .min_by_key(|addr| {
                            us_load_states
                                .get(&(host.name.clone(), addr.port()))
                                .map(|s| s.num_bytes)
                                .unwrap_or(u32::MAX)
                        })
                        .unwrap_or_else(|| host.instances.choose(&mut rand::thread_rng()).unwrap());

                    let ft = ForwardingToken {
                        conn_id: ForwardingDimension::DontCare,
                        direction: ForwardingDimension::Concrete(Direction::Upstream),
                        backend: ForwardingDimension::Concrete(host.name.clone()),
                        instance: ForwardingDimension::Min,
                    };
                    min_instance.insert(ft, instance.port());
                }
            }
        });
    }

    pub async fn process(
        self: &Arc<Self>,
        buf: &mut Vec<u8>,
        origin: SocketAddr,
        is_downstream: bool,
    ) -> Result<Destination> {
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
        } else {
            let mut res = httparse::Response::new(&mut headers);
            let hdr_len = match res.parse(&buf) {
                Ok(Status::Complete(len)) => len,
                Ok(Status::Partial) => return Err(anyhow!("Partial response")),
                Err(e) => return Err(anyhow!(e)),
            };

            (res.headers, hdr_len)
        };

        let hdrs = hdrs
            .iter()
            .map(|hdr| {
                (
                    hdr.name.to_string().to_lowercase(),
                    String::from_utf8(hdr.value.to_vec()).unwrap(),
                )
            })
            .collect();

        trace!("Processing msg from {:?} headers: {:?}", origin, hdrs);

        let mut ctx = Context {
            hdrs,
            origin,
            ft: ForwardingToken::dont_care(),
        };

        if is_downstream {
            self.authenticate(&mut ctx).await?;
            self.update_ds_conn(&mut ctx)?;
            self.forward_ds_conn(&mut ctx).await?;

            let conn_id_hdr = format!("conn-id: {}\r\n", origin.port());
            buf.splice(len - 2..len - 2, conn_id_hdr.bytes());
        } else {
            self.update_us_conn(&mut ctx).await?;
            self.forward_us_conn(&mut ctx).await?;
        }

        let dest = self.select_sock(&mut ctx).await?;

        trace!("Selected sock {:?} -> {:?}", origin, dest);

        Ok(dest)
    }

    async fn authenticate(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let token = ctx
            .hdrs
            .get("authorization")
            .ok_or_else(|| anyhow!("No Authorization header found"))?;
        let token = token
            .strip_prefix("Bearer")
            .expect("Invalid auth token")
            .split("\r\n")
            .next()
            .expect("Invalid auth token")
            .trim();

        let key: Hmac<Sha256> = Hmac::new_from_slice(b"testtest12345678")?;
        match token.verify_with_key(&key) {
            Ok::<BTreeMap<String, String>, _>(_) => Ok(()),
            Err(_) => Err(anyhow!("Invalid token: {token}")),
        }
    }

    fn update_ds_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        self.ds_state
            .write()
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

        self.us_load_state
            .write()
            .unwrap()
            .entry((backend.unwrap().clone(), ctx.origin.port()))
            .and_modify(|state| {
                state.num_reqs += 1;
                state.num_bytes += ctx.hdrs.len() as u32;
            })
            .or_insert(UpstreamLoadState {
                num_reqs: 1,
                num_bytes: ctx.hdrs.len() as u32,
            });

        self.us_state
            .write()
            .unwrap()
            .entry(ctx.origin)
            .and_modify(|state| state.reserved = false)
            .or_insert(UpstreamState { reserved: false });

        Ok(())
    }

    async fn forward_ds_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let backend = ctx
            .hdrs
            .get("backend")
            .ok_or_else(|| anyhow!("No Backend header found"))?;

        ctx.ft.direction = ForwardingDimension::Concrete(Direction::Upstream);
        ctx.ft.backend = ForwardingDimension::Concrete(backend.clone());
        ctx.ft.instance = ForwardingDimension::Min;

        let ft_inv = ForwardingToken {
            conn_id: ForwardingDimension::Concrete(ctx.origin.port() as u32),
            direction: ForwardingDimension::Concrete(Direction::Downstream),
            backend: ForwardingDimension::DontCare,
            instance: ForwardingDimension::DontCare,
        };

        self.fib.write().unwrap().insert(ft_inv, vec![ctx.origin]);

        Ok(())
    }

    async fn forward_us_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let conn_id = ctx
            .hdrs
            .get("conn-id")
            .ok_or_else(|| anyhow!("No conn-id header found"))?
            .parse()?;
        ctx.ft.conn_id = ForwardingDimension::Concrete(conn_id);
        ctx.ft.direction = ForwardingDimension::Concrete(Direction::Downstream);

        Ok(())
    }

    async fn select_sock(self: &Arc<Self>, ctx: &mut Context) -> Result<Destination> {
        // check if we have to retrieve the min instance for that group
        let ft = if ctx.ft.instance == ForwardingDimension::Min {
            let min_instance = self.min_instance.read().unwrap();
            let instance = min_instance.get(&ctx.ft).unwrap();

            let mut ft = ctx.ft.clone();
            ft.instance = ForwardingDimension::Concrete(instance.clone());

            ft
        } else {
            ctx.ft.clone()
        };

        let fib = self.fib.read().unwrap();
        let addrs = fib.get(&ft);

        if let Some(addrs) = addrs {
            let mut us_state = self.us_state.write().unwrap();
            if ft.direction == ForwardingDimension::Concrete(Direction::Upstream) {
                let addr = addrs
                    .iter()
                    .find(|addr| {
                        us_state
                            .get(addr)
                            .map(|state| !state.reserved)
                            .unwrap_or(false)
                    })
                    .cloned();

                if let Some(addr) = addr {
                    // we have to reserve this connection while we hold the lock
                    us_state.insert(addr, UpstreamState { reserved: true });

                    return Ok(Destination::Exisiting(addr));
                }
            } else {
                assert!(addrs.len() == 1);
                return Ok(Destination::Exisiting(addrs[0].clone()));
            }
        }

        if ctx.ft.direction.concrete_val() == Some(&Direction::Downstream) {
            bail!("No socket found for downstream connection: {:?}", ctx.ft);
        }

        let addr = self.resolve_preconfigured_instance(&ft);
        if addr.is_none() {
            bail!("Could not resolve preconfigured address for {:?}", ft);
        }
        let addr = addr.unwrap();

        let ft = ForwardingToken {
            conn_id: ForwardingDimension::DontCare,
            direction: ForwardingDimension::Concrete(Direction::Upstream),
            backend: ctx.ft.backend.clone(),
            instance: ForwardingDimension::Concrete(addr.port()),
        };

        Ok(Destination::New(addr.clone(), ft))
    }

    pub async fn add_sock(self: &Arc<Self>, ft: ForwardingToken, addr: SocketAddr) {
        trace!("Add {:?} to FIB", ft);
        self.fib
            .write()
            .unwrap()
            .entry(ft)
            .or_insert(vec![])
            .push(addr);
    }

    fn resolve_preconfigured_instance(
        self: &Arc<Self>,
        ft: &ForwardingToken,
    ) -> Option<&SocketAddr> {
        let backend = ft.backend.concrete_val()?;
        let instance = ft.instance.concrete_val()?;

        self.config
            .hosts
            .iter()
            .find(|host| host.name == *backend)
            .and_then(|host| host.instances.iter().find(|addr| addr.port() == *instance))
    }
}
