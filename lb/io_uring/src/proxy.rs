use anyhow::Result;
use io_uring::{cqueue, opcode, squeue, types, IoUring};
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
    vec,
};
use slab::Slab;

use crate::http;

const BUF_NUM: usize = 64;
const BUF_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Token {
    ProvideBuffers { fd: Option<RawFd>, addr: *mut u8, num_bufs: u16, buf_len: i32, bgid: u16, bid: u16 },
    Accept { fd: RawFd },
    Read { fd: RawFd, bgid: u16 },
    Write { fd: RawFd, bgid: u16, bid: usize, len: usize },
    Shutdown { fd: RawFd, bgid: u16 }
}

pub struct Proxy {
    addr: SocketAddr,
    backends: HashMap<String, String>,
    streams: HashMap<RawFd, TcpStream>,
    conns: HashMap<RawFd, RawFd>,
    conn_pool: HashMap<String, Vec<RawFd>>,
    buf_pool: Vec<u16>,
    buf_alloc: Slab<Box<[u8]>>,
    token_alloc: Slab<Token>,
}

impl Proxy {

    pub fn new<A: ToSocketAddrs>(addr: A, backends: HashMap<String, String>) -> Result<Proxy> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let conn_pool = backends.keys().map(|k| (k.clone(), Vec::new())).collect();

        Ok(Proxy {
            addr,
            backends,
            streams: HashMap::new(),
            conns: HashMap::new(),
            conn_pool: conn_pool,
            buf_pool: Vec::with_capacity(64),
            buf_alloc: Slab::with_capacity(1000),
            token_alloc: Slab::with_capacity(1000)
        })
    }

    pub fn listen(&mut self) -> Result<()> {
        let mut ring = IoUring::new(2048)?;
        let (submitter, mut sq, mut cq) = ring.split();
        let mut backlog = VecDeque::new();

        let listener = TcpListener::bind(self.addr)?;
        let accept = Token::Accept { fd: listener.as_raw_fd() };

        unsafe {
            sq.push(&self.sqe_from_token(accept))?;
        }

        info!("listening on {:?}", self.addr);

        loop {
            sq.sync();

            match submitter.submit_and_wait(1) {
                Ok(_) => (),
                Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => (),
                Err(err) => return Err(err.into()),
            }
            cq.sync();

            // clean backlog
            loop {
                if sq.is_full() {
                    match submitter.submit() {
                        Ok(_) => (),
                        Err(ref err) if err.raw_os_error() == Some(libc::EBUSY) => break,
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
    
            for cqe in &mut cq {
                let next_tokens = self.handle_cqe(cqe);
    
                if !next_tokens.is_empty() {
                    for tok in next_tokens {    
                        let sqe = self.sqe_from_token(tok);
                        unsafe {
                            if sq.push(&sqe).is_err() {
                                backlog.push_back(sqe);
                            }
                        }
                    }
                }
            }
        }
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

        let ret = cqe.result();
        if ret < 0 {
            error!("token: {:?} error: {:?}", token, io::Error::from_raw_os_error(-ret));
            return vec![];
        }
    
        match token {
            Token::Accept { fd } => {
                let mut toks = self.handle_accept(ret);
                toks.push(Token::Accept { fd });
                toks
            },
            Token::Read { fd, bgid } => self.handle_read(cqe, fd, bgid),
            Token::Write { bgid, bid, .. } => vec![Token::ProvideBuffers { fd: None, addr: self.get_buf_ptr(bgid, bid), num_bufs: 1, buf_len: BUF_LEN as i32, bgid, bid: bid as u16 }],
            Token::Shutdown { fd, bgid } => {
                self.buf_pool.push(bgid);
                if let Some(bfd) = self.conns.remove(&fd) {
                    self.conns.remove(&bfd);
                }

                vec![]
            },
            Token::ProvideBuffers { fd: Some(fd), bgid, .. } => vec![Token::Read { fd, bgid }],
            _ => vec![]
        }
    }

    fn handle_accept(&mut self, fd: RawFd) -> Vec<Token> {
        debug!("accept {:?}", fd);
        self.prep_socket(fd)
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
                debug!("shutdown {:?}", fd);
                // here we should cancel reading the sockets
                vec![Token::Shutdown { fd, bgid }]
            }
            else {
                vec![]
            }
        } else {
            let is_backend = self.streams.contains_key(&fd);
            if is_backend {
                self.read_backend_req(cqe, fd, bgid)
            } else {
                self.read_client_req(cqe, fd, bgid)
            }
        }
    }

    fn read_client_req(&mut self, cqe: cqueue::Entry, cfd: RawFd, bgid: u16) -> Vec<Token> {
        let len = cqe.result() as usize;
        let bid = cqueue::buffer_select(cqe.flags()).unwrap() as usize;
        let buf = &self.buf_alloc[bgid as usize][bid * BUF_LEN..][..len];
        
        if let Some((method, _, _)) = http::parse_hdr(buf.as_ref()).clone() {
            let backend = self.backends.get(method.url());
            if backend.is_none() {
                error!("no backend found for {:?}", method.url());
                return vec![];
            }
            let backend = backend.unwrap().clone();

            // check if the client is connected to an existing backend
            let stream = self.conns
                .get(&cfd)
                .and_then(|bfd| self.streams.get(bfd));

            if let Some(stream) = stream {
                let host = &stream.peer_addr().unwrap().to_string();
                let bfd = stream.as_raw_fd();

                // the client is currently connected to the requested backend
                if *host == backend {
                    return vec![Token::Write { fd: bfd, bgid, bid, len }];
                }
                // the client is not connected to the requested backend, put backend back in pool
                else {
                    let backend = self.backends
                        .iter()
                        .find_map(|(key, &ref val)| if val == host { Some(key) } else { None })
                        .unwrap();

                    self.conn_pool.get_mut(backend).unwrap().push(bfd);
                    self.conns.remove(&cfd);
                    self.conns.remove(&bfd);
                }
            }

            let mut tokens = Vec::new();
            let bfd = self.conn_pool.get_mut(method.url())
                .unwrap()
                .pop()
                .or_else(|| {
                    debug!("connecting to backend: {:?}", backend);
                    match self.connect_to_host(&backend) {
                        Ok(fd) => {
                            tokens.extend_from_slice(&self.prep_socket(fd).as_slice());
                            Some(fd)       
                        },
                        Err(e) => {
                            error!("failed to connect to backend: {:?}", e);
                            None
                        }
                    }
                });

            if bfd.is_none() {
                return vec![];
            }
            let bfd = bfd.unwrap();

            self.conns.insert(cfd, bfd);
            self.conns.insert(bfd, cfd);

            tokens.push(Token::Write { fd: bfd, bgid, bid, len });
            tokens
        }
        else {
            match self.conns.get(&cfd) {
                Some(bfd) => {
                    vec![Token::Write { fd: *bfd, bgid, bid, len }]
                },
                _ => {
                    error!("failed to parse request");
                    vec![]
                }
            }
        }
    }

    fn read_backend_req(&mut self, cqe: cqueue::Entry, bfd: RawFd, bgid: u16) -> Vec<Token> {
        let len = cqe.result() as usize;
        let bid = cqueue::buffer_select(cqe.flags()).unwrap() as usize;

        if let Some(cfd) = self.conns.get(&bfd) {
            vec![Token::Write { fd: *cfd, bgid, bid, len }]
        }
        else {
            vec![]
        }
    }

    fn sqe_from_token(&mut self, token: Token) -> squeue::Entry {
        let token_idx = self.token_alloc.insert(token.clone());
        let sqe = match token {
            Token::ProvideBuffers { addr, num_bufs, buf_len, bgid, bid, .. } => opcode::ProvideBuffers::new(addr, buf_len, num_bufs, bgid, bid).build(),
            Token::Accept { fd } => opcode::Accept::new(types::Fd(fd), std::ptr::null_mut(), std::ptr::null_mut()).build(),
            Token::Read { fd, bgid } => opcode::RecvMulti::new(types::Fd(fd), bgid).build(),
            Token::Write { fd, bgid, bid, len } => opcode::Send::new(types::Fd(fd), self.get_buf_ptr(bgid, bid), len as _).build(),
            Token::Shutdown { fd, .. } => opcode::Shutdown::new(types::Fd(fd), 2).build(),
        };

        sqe.user_data(token_idx as _)
    }

    fn connect_to_host(&mut self, addr: &str) -> Result<RawFd> {
        let addr = addr.to_socket_addrs()?.next().unwrap();
        let stream = std::net::TcpStream::connect(addr)?;
        let fd = stream.as_raw_fd();
        self.streams.insert(fd, stream);

        Ok(fd)
    }

}
