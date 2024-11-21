use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use futures::lock::Mutex;
use jwt::VerifyWithKey;
use log::debug;
use sha2::Sha256;
use std::{collections::{BTreeMap, HashMap}, io::Cursor, net::SocketAddr, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream};

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
struct ForwardingToken {
    conn_id: u32,
    direction: Direction,
    backend: u8,
}

pub struct Pipeline {
    ds_state: Arc<Mutex<HashMap<SocketAddr, DownstreamState>>>,
    us_state: Arc<Mutex<HashMap<SocketAddr, UpstreamState>>>,
    forwarding_decision_tree: Arc<Mutex<HashMap<ForwardingToken, Vec<SocketAddr>>>>,
    sockets: Arc<Mutex<HashMap<SocketAddr, TcpStream>>>,
}

impl Pipeline {

    pub fn new() -> Self {
        Pipeline {
            ds_state: Arc::new(Mutex::new(HashMap::new())),
            us_state: Arc::new(Mutex::new(HashMap::new())),
            forwarding_decision_tree: Arc::new(Mutex::new(HashMap::new())),
            sockets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn process(self: Arc<Self>, buf: &[u8], origin: SocketAddr) -> Result<()> {
        let mut headers = [httparse::EMPTY_HEADER; 8192];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(&buf)?;

        let hdrs = req.headers.iter()
            .map(|hdr| (hdr.name.to_string(), String::from_utf8(hdr.value.to_vec()).unwrap()))
            .collect();

        let mut ctx = Context { hdrs, origin, ft: ForwardingToken::default() };

        let is_downstream = origin.port() == 3000;
        if is_downstream {
            self.authenticate(&mut ctx).await?;
            self.update_ds_conn(&mut ctx).await?;
            self.forward_ds_conn(&mut ctx).await?;
        } 
        else {
            self.update_us_conn(&mut ctx).await?;
            self.forward_us_conn(&mut ctx).await?;
        }

        self.write_to_stream(ctx, &buf).await
    }

    async fn authenticate(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let token = ctx.hdrs.get("Authorization")
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
        let backend = ctx.hdrs.get("Backend").ok_or_else(|| anyhow!("No Backend header found"))?;

        ctx.ft.direction = Direction::Upstream;
        ctx.ft.backend = backend.parse()?;

        Ok(())
    }

    async fn forward_us_conn(self: &Arc<Self>, ctx: &mut Context) -> Result<()> {
        let conn_id = ctx.hdrs.get("conn_id").ok_or_else(|| anyhow!("No conn_id header found"))?;
        ctx.ft.conn_id = conn_id.parse()?;
        ctx.ft.direction = Direction::Downstream;

        Ok(())
    }

    async fn write_to_stream(self: &Arc<Self>, ctx: Context, buf: &[u8]) -> Result<()> {
        let mut fdt = self.forwarding_decision_tree.lock().await;
        let fdt_socks = fdt.entry(ctx.ft.clone()).or_insert_with(Vec::new);
        let us_state = self.us_state.lock().await;

        let addr = if fdt_socks.len() > 1 {
            fdt_socks.iter()
                .min_by_key(|addr| { 
                    let state = us_state.get(addr).unwrap();
                    state.num_reqs
                })
        } else {
            fdt_socks.first()
        };

        let mut socks = self.sockets.lock().await;

        if let Some(addr) = addr {
           let stream = socks
                .get_mut(addr)
                .unwrap();

            let mut req_buf = Cursor::new(&buf);
            stream.write_all_buf(&mut req_buf).await.unwrap();
    
            return Ok(());
        }

        let mut stream = Self::open_new_conn(&ctx.ft).await?;
        let addr = stream.peer_addr().unwrap();

        debug!("Opening upstream connection [{}->{}]", ctx.origin, addr);

        let mut req_buf = Cursor::new(&buf);
        stream.write_all_buf(&mut req_buf).await.unwrap();

        fdt_socks.push(addr);
        socks.insert(addr, stream);

        Ok(())
    }

    async fn open_new_conn(ft: &ForwardingToken) -> Result<TcpStream> {
        if ft.direction == Direction::Downstream {
            return Err(anyhow!("Cannot open downstream connection"));
        }

        let addr = match ft.backend {
            1 => "127.0.0.1:8001",
            2 => "127.0.0.1:8002",
            3 => "127.0.0.1:8003",
            4 => "127.0.0.1:8004",
            _ => return Err(anyhow!("Invalid backend"))
        };

        let stream = TcpStream::connect(addr).await?;
        Ok(stream)
    }

}