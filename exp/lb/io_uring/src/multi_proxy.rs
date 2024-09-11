use anyhow::Result;
use io_uring::{cqueue, opcode, squeue, types};
use log::{
    debug,
    error,
    info
};
use std::{
    collections::{
        HashMap,
        VecDeque
    }, 
    io, 
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs}, 
    os::unix::io::{AsRawFd, RawFd}, 
    sync::{Arc, Mutex},
    thread,
    vec
};
use slab::Slab;
use socket2::{Socket, Domain, Type};

use crate::http;

type ConnectionPool = HashMap<String, Vec<TcpStream>>;

const BUF_NUM: usize = 64;
const BUF_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Token {
    ProvideBuffers { fd: Option<RawFd>, addr: *mut u8, num_bufs: u16, buf_len: i32, bgid: u16, bid: u16 },
    Read { fd: RawFd, bgid: u16 },
    Cancel { fd: RawFd, user_data: u64 },
    Write { fd: RawFd, bgid: u16, bid: usize, len: usize },
    Shutdown {fd: RawFd }
}

pub struct Connection {
    client: RawFd,
    backend: Option<TcpStream>,
    backends: HashMap<String, String>,
    closing_backends: HashMap<RawFd, TcpStream>,
    conn_pool: Arc<Mutex<ConnectionPool>>,
    buf_pool: Vec<u16>,
    buf_alloc: Slab<Box<[u8]>>,
    token_alloc: Slab<Token>,
    shutdown: bool,
}

impl Connection {

    pub fn new(client: RawFd, backends: HashMap<String, String>, conn_pool: Arc<Mutex<ConnectionPool>>) -> Connection {
        Connection {
            client,
            backend: None,
            backends,
            closing_backends: HashMap::new(),
            conn_pool,
            buf_pool: Vec::with_capacity(64),
            buf_alloc: Slab::with_capacity(1000),
            token_alloc: Slab::with_capacity(1000),
            shutdown: false,
        }
    }

    fn process(&mut self, fd: RawFd) -> Result<()> {
        let mut ring = io_uring::IoUring::builder()
            .setup_defer_taskrun()
            .setup_coop_taskrun()
            .setup_single_issuer()
            .build(2048)?;

        let (submitter, mut sq, mut cq) = ring.split();

        let mut backlog = VecDeque::new();

        unsafe {
            for tok in self.prep_socket(fd) {
                sq.push(&self.sqe_from_token(tok))?;
            }
        }

        loop {
            if self.shutdown {
                break;
            }

            sq.sync();

            match submitter.submit_and_wait(1) {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => error!("ring is busy: {:?}", err),
                Err(err) => return Err(err.into()),
            }

            // clean backlog
            loop {
                if sq.is_full() {
                    match submitter.submit() {
                        Ok(_) => (),
                        Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => {
                            error!("ring is busy: {:?}", err);
                            break;
                        },
                        Err(err) => return Err(err.into()),
                    }
                }
                sq.sync();

                match backlog.pop_front() {
                    Some(sqe) => unsafe {
                        sq.push(&sqe)?;
                    },
                    None => break,
                }
            }

            cq.sync();
            for cqe in &mut cq {
                let next_tokens = self.handle_cqe(cqe);
    
                for tok in next_tokens {    
                    debug!("submit sqe: {:?}", tok);
                    let sqe = self.sqe_from_token(tok);
                    unsafe {
                        if sq.push(&sqe).is_err() {
                            backlog.push_back(sqe);
                        }
                    }
                }
            }
        }

        unsafe {
            libc::close(self.client);
        }

        Ok(())
    }

    fn get_buf_ptr(&mut self, bgid: u16, bid: usize) -> *mut u8 {
        self.buf_alloc[bgid as usize][bid * BUF_LEN..].as_mut_ptr()
    }

    fn get_vacant_bgid(&mut self) -> u16 {
        self.buf_pool.pop().unwrap_or_else(|| {
            let buf = vec![0u8; BUF_NUM * BUF_LEN].into_boxed_slice();
            let buf_entry = self.buf_alloc.vacant_entry();
            let bgid = buf_entry.key();
            buf_entry.insert(buf);
            bgid as u16
        })
    }
    
    fn handle_cqe(&mut self, cqe: cqueue::Entry) -> Vec<Token> {
        let token_idx = cqe.user_data() as usize;
        let token = self.token_alloc[token_idx].clone();

        debug!("handle cqe: {:?}", token);

        // for shutdowns we don't care about the result
        if let Token::Shutdown { .. } = token {
            // return the backend connection
            if let Some(stream) = self.backend.take() {
                self.put_conn_back_to_pool(stream);
            }
            
            self.shutdown = true;
            return vec![];
        }

        let ret = cqe.result();
        if ret < 0 {
            let is_canceled_read = matches!(token, Token::Read { .. }) && ret == -libc::ECANCELED;
            let cancel_not_found = matches!(token, Token::Cancel { .. }) && ret == -libc::ENOENT;
            if !is_canceled_read && !cancel_not_found {
                error!("token: {:?} error: {:?}, ret: {:?}", token, io::Error::from_raw_os_error(-ret), -ret);
            }

            return vec![];
        }
    
        match token {
            Token::Read { fd, bgid } => self.handle_read(cqe, fd, bgid),
            Token::Write { bgid, bid, .. } => vec![Token::ProvideBuffers { fd: None, addr: self.get_buf_ptr(bgid, bid), num_bufs: 1, buf_len: BUF_LEN as i32, bgid, bid: bid as u16 }],
            Token::ProvideBuffers { fd: Some(fd), bgid, .. } => vec![Token::Read { fd, bgid }],
            Token::Cancel { fd, .. } => {
                if let Some(stream) = self.closing_backends.remove(&fd) {
                    self.put_conn_back_to_pool(stream);
                }
                vec![]
            },
            _ => vec![]
        }
    }

    fn prep_socket(&mut self, fd: RawFd) -> Vec<Token> {
        let bgid = self.get_vacant_bgid();
        let addr = self.get_buf_ptr(bgid, 0);
        vec![
            Token::ProvideBuffers { fd: Some(fd), addr, num_bufs: BUF_NUM as u16, buf_len: BUF_LEN as i32, bgid, bid: 0 }, 
        ]
    }

    fn handle_read(&mut self, cqe: cqueue::Entry, fd: RawFd, bgid: u16) -> Vec<Token> {
        if cqe.result() == 0 {
            if !cqueue::more(cqe.flags()) {
                self.buf_pool.push(bgid);
                if self.client == fd {
                    debug!("shutdown {:?}", fd);

                    return vec![Token::Shutdown { fd }];
                }
            }
            
            vec![]
        } 
        else {
            if self.client == fd {
                self.read_client_req(cqe, bgid)
            }
            else if self.backend.is_some() {
                self.read_backend_req(cqe, bgid)
            }
            else {
                error!("unknown fd: {:?}", fd);
                vec![Token::Cancel { fd, user_data: cqe.user_data() }]
            }
        }
    }

    fn read_client_req(&mut self, cqe: cqueue::Entry, bgid: u16) -> Vec<Token> {
        let len = cqe.result() as usize;
        let bid = cqueue::buffer_select(cqe.flags()).unwrap() as usize;
        let buf = &self.buf_alloc[bgid as usize][bid * BUF_LEN..][..len];
        let bfd = self.backend
            .as_ref()
            .map(|s| s.as_raw_fd());
        
        if let Some((method, _, _)) = http::parse_hdr(buf.as_ref()).clone() {
            let req_addr = self.backends.get(method.url());
            if req_addr.is_none() {
                error!("no backend found for {:?}", method.url());
                return vec![];
            }
            let req_addr = req_addr.unwrap().clone();

            // check if the client is connected to an existing backend
            let mut tokens = Vec::new();
            if let Some(stream) = self.backend.take() {
                let cur_addr = &stream.peer_addr().unwrap().to_string();
                let bfd = stream.as_raw_fd();

                // the client is currently connected to the requested backend
                if *cur_addr == req_addr {
                    self.backend = Some(stream);
                    return vec![Token::Write { fd: bfd, bgid, bid, len }];
                }
                // the client is not connected to the requested backend, put backend back in pool
                else {
                    let user_data = self.token_alloc
                        .iter()
                        .find(|(_, tok)| if let  Token::Read { fd, .. } = tok {
                            *fd == bfd
                        }
                        else {
                            false
                        });

                    if let Some((idx, _)) = user_data {
                        debug!("canceling backend connection read: {:?}", bfd);
                        tokens.push(Token::Cancel { fd: bfd, user_data: idx as _ });
                        self.closing_backends.insert(bfd, stream);
                    }
                }
            }

            let req_backend = self.conn_pool.lock().unwrap().get_mut(method.url())
                .unwrap()
                .pop();

            self.backend = match req_backend {
                Some(stream) => {
                    debug!("reusing backend connection: {:?}", stream.as_raw_fd());
                    Some(stream)
                },
                None => {
                    match std::net::TcpStream::connect(req_addr) {
                        Ok(stream) => {
                            debug!("connecting to backend: {:?}", stream.as_raw_fd());
                            Some(stream)
                        },
                        Err(e) => {
                            error!("failed to connect to backend: {:?}", e);
                            return vec![];
                        }
                    }
                }
            };

            let bfd = self.backend
                .as_ref()
                .unwrap()
                .as_raw_fd();

            tokens.extend_from_slice(&self.prep_socket(bfd).as_slice());
            tokens.push(Token::Write { fd: bfd, bgid, bid, len });

            debug!("forwarding client req to backend: {:?}", bfd);
            
            tokens
        }
        else if let Some(bfd) = bfd {
            vec![Token::Write { fd: bfd, bgid, bid, len }]
        }
        else {
            vec![]
        }
    }

    fn read_backend_req(&mut self, cqe: cqueue::Entry, bgid: u16) -> Vec<Token> {
        let len = cqe.result() as usize;
        let bid = cqueue::buffer_select(cqe.flags()).unwrap() as usize;

        vec![Token::Write { fd: self.client, bgid, bid, len }]
    }

    fn sqe_from_token(&mut self, token: Token) -> squeue::Entry {
        let token_idx = self.token_alloc.insert(token.clone());
        let sqe = match token {
            Token::ProvideBuffers { addr, num_bufs, buf_len, bgid, bid, .. } => opcode::ProvideBuffers::new(addr, buf_len, num_bufs, bgid, bid).build(),
            Token::Read { fd, bgid } => opcode::RecvMulti::new(types::Fd(fd), bgid).build(),
            Token::Cancel { user_data, .. } => opcode::AsyncCancel::new(user_data).build(),
            Token::Write { fd, bgid, bid, len } => opcode::Send::new(types::Fd(fd), self.get_buf_ptr(bgid, bid), len as _).build(),
            Token::Shutdown { fd, .. } => opcode::Shutdown::new(types::Fd(fd), 2).build(),
        };

        sqe.user_data(token_idx as _)
    }

    fn put_conn_back_to_pool(&mut self, stream: TcpStream) {
        let addr = &stream.peer_addr().unwrap().to_string();
        let name = self.backends
            .iter()
            .find_map(|(key, &ref val)| if val == addr { Some(key) } else { None })
            .unwrap();

        self.conn_pool
            .lock()
            .unwrap()
            .get_mut(name)
            .unwrap()
            .push(stream);
    }

}

pub struct Proxy {
    addr: SocketAddr,
    backends: HashMap<String, String>,
    conn_pool: Arc<Mutex<ConnectionPool>>,
}

impl Proxy {

    pub fn new<A: ToSocketAddrs>(addr: A, backends: HashMap<String, String>) -> Result<Proxy> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let conn_pool = backends.keys().map(|k| (k.clone(), Vec::new())).collect();

        Ok(Proxy {
            addr,
            backends,
            conn_pool: Arc::new(Mutex::new(conn_pool)),
        })
    }

    pub fn listen(&mut self) -> Result<()> {
        let mut ring = io_uring::IoUring::<squeue::Entry, cqueue::Entry>::builder()
            .setup_defer_taskrun()
            .setup_coop_taskrun()
            .setup_single_issuer()
            .build(2048)?;

        let (submitter, mut sq, mut cq) = ring.split();

        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        socket.set_reuse_address(true)?;
        socket.bind(&self.addr.into())?;
        socket.listen(4096)?;

        let mut threads = Vec::new();
        let listener: TcpListener = socket.into();
        let accept = opcode::AcceptMulti::new(types::Fd(listener.as_raw_fd())).build();

        unsafe {
            sq.push(&accept)?;
        }

        info!("listening on {:?}", self.addr);

        loop {
            sq.sync();

            match submitter.submit_and_wait(1) {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => error!("ring is busy: {:?}", err),
                Err(err) => return Err(err.into()),
            }

            cq.sync();
            for cqe in &mut cq {
                let fd = cqe.result();
                if fd < 0 {
                    error!("token: {:?} error: {:?}", accept, io::Error::from_raw_os_error(-fd));
                }
                else {
                    debug!("accept {:?}", fd);

                    let backends = self.backends.clone();
                    let conn_pool = self.conn_pool.clone();
                    let handle = thread::spawn(move || {
                        let mut conn = Connection::new(fd, backends, conn_pool);
                        if let Err(e) = conn.process(fd) {
                            error!("failed to process connection: {:?}", e);
                        }
                    });
                    threads.push(handle);
                }       
            }
        }
    }

}
