use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use futures::lock::Mutex;
use httparse::Status;
use jwt::VerifyWithKey;
use log::trace;
use sha2::Sha256;
use std::{collections::{BTreeMap, HashMap, HashSet}, net::SocketAddr, str::FromStr, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DownstreamState {
    num_bytes: u32,
    num_reqs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpstreamState {
    num_bytes: u32,
    num_reqs: u32,
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
    New(SocketAddr),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ForwardingToken {
    conn_id: u32,
    direction: Direction,
    backend: u8,
}

pub struct Pipeline {
    ds_state: Arc<Mutex<HashMap<SocketAddr, DownstreamState>>>,
    us_state: Arc<Mutex<HashMap<SocketAddr, UpstreamState>>>,
    forwarding_decision_tree: Arc<Mutex<HashMap<ForwardingToken, HashSet<SocketAddr>>>>,
}

impl Pipeline {

    pub fn new() -> Self {
        Pipeline {
            ds_state: Arc::new(Mutex::new(HashMap::new())),
            us_state: Arc::new(Mutex::new(HashMap::new())),
            forwarding_decision_tree: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn process(self: &Arc<Self>, buf: &mut Vec<u8>, origin: SocketAddr, is_downstream: bool) -> Result<(Destination, ForwardingToken)> {
        trace!("Processing msg from {:?}", origin);

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

        let mut ctx = Context { hdrs, origin, ft: ForwardingToken::default() };

        if is_downstream {
            self.authenticate(&mut ctx).await?;
            self.update_ds_conn(&mut ctx).await?;
            self.forward_ds_conn(&mut ctx).await?;

            let conn_id_hdr = format!("conn-id: {}\r\n", origin.port());
            buf.splice(len-2..len-2, conn_id_hdr.bytes());
        } 
        else {
            self.update_us_conn(&mut ctx).await?;
            self.forward_us_conn(&mut ctx).await?;
        }

        let ft = ctx.ft.clone();
        Ok((self.select_sock(ctx).await, ft))
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

        let key: Hmac<Sha256> = Hmac::new_from_slice(b"some-secret")?;
        match token.verify_with_key(&key) {
            Ok::<BTreeMap<String, String>, _>(_) => Ok(()),
            Err(_) => Err(anyhow!("Invalid token"))
        }
    }

    async fn update_ds_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        self.ds_state.lock()
            .await
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
        self.us_state.lock()
            .await
            .entry(ctx.origin)
            .and_modify(|state| {
                state.num_reqs += 1;
                state.num_bytes += ctx.hdrs.len() as u32;
            })
            .or_insert(UpstreamState {
                num_reqs: 1,
                num_bytes: ctx.hdrs.len() as u32,
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

        ctx.ft.direction = Direction::Upstream;
        ctx.ft.backend = backend;

        let ft_inv = ForwardingToken {
            conn_id: ctx.origin.port() as u32,
            direction: Direction::Downstream,
            backend: 0,
        };

        self.forwarding_decision_tree.lock()
            .await
            .entry(ft_inv)
            .or_insert_with(HashSet::new)
            .insert(ctx.origin);

        Ok(())
    }

    async fn forward_us_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let conn_id = ctx.hdrs.get("conn-id").ok_or_else(|| anyhow!("No conn-id header found"))?;
        ctx.ft.conn_id = conn_id.parse()?;
        ctx.ft.direction = Direction::Downstream;

        Ok(())
    }

    async fn select_sock(self: &Arc<Self>, ctx: Context) -> Destination {
        let mut fdt = self.forwarding_decision_tree.lock().await;
        let socks = fdt.entry(ctx.ft.clone()).or_insert_with(HashSet::new);
        let us_state = self.us_state.lock().await;

        let addr = if ctx.ft.direction == Direction::Upstream {
            socks.iter()
                .min_by_key(|addr| { 
                    // it's possible that we haven't received a response from this particular
                    // upstream connection yet -> num_reqs will be 0
                    us_state.get(addr)
                        .map(|state| state.num_reqs)
                        .unwrap_or(0)
                })
        } else {
            assert!(socks.len() == 1);
            socks.iter().next()
        };

        if let Some(addr) = addr {
            Destination::Exisiting(addr.clone())
        } 
        else {
            // let addr = format!("10.0.{}.1:8000", ctx.ft.backend);
            let addr = format!("127.0.0.1:800{}", ctx.ft.backend);
            Destination::New(SocketAddr::from_str(&addr).unwrap())
        }
    }

    pub async fn add_sock(self: &Arc<Self>, ft: ForwardingToken, addr: SocketAddr) {
        self.forwarding_decision_tree.lock()
            .await
            .entry(ft)
            .or_insert_with(HashSet::new)
            .insert(addr);
    }

}