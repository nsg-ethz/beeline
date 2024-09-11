use anyhow::{Context, Result};
use libbpf_rs::{MapHandle, MapType, MapFlags};
use libbpf_sys;
use std::{
    mem::size_of,
    os::fd::{AsFd, AsRawFd}
};

use crate::parser;

const CRLF: &str = "\r\n";

pub struct StateMachine<'a, 'b> {
    skel: &'a mut parser::ParserSkel<'b>,
    tss: Vec<MapHandle>
}

#[allow(dead_code)]
impl StateMachine<'_, '_> {

    pub fn new<'a, 'b>(skel: &'a mut parser::ParserSkel<'b>) -> Result<StateMachine<'a, 'b>> {
        let mut sm = StateMachine {
            skel,
            tss: Vec::new()
        };

        // create s_init
        sm.create_state()?;

        // create s_any
        sm.create_state()?;

        Ok(sm)
    }

    fn s_init(&self) -> usize {
        self.skel.rodata().s_init as usize
    }

    fn s_any(&self) -> usize {
        self.skel.rodata().s_any as usize
    }

    fn s_match(&self) -> usize {
        self.skel.rodata().s_match as usize
    }

    fn s_no_match(&self) -> usize {
        self.skel.rodata().s_no_match as usize
    }

    fn create_state(&mut self) -> Result<()> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        
        let idx = self.tss.len();
        let name = format!("t{}", idx);
        let map = MapHandle::create(MapType::Hash, Some(name), 1, 4, 256, &opts)
            .context("Failed to create map")?;
        let fd = map.as_fd().as_raw_fd();

        self.skel
            .maps()
            .s2ts()
            .update(&(idx as u32).to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
            .context("Failed to insert state into s2ts")?;

        self.tss.push(map);

        Ok(())
    }
    
    fn add_transition(&mut self, from: usize, to: usize, input: char) -> Result<()> {
        assert!(self.tss.len() > from);

        let ts = self.tss.get_mut(from).unwrap();
        let key = (input as u8).to_ne_bytes();
        let val = (to as u32).to_ne_bytes();
        ts.update(&key, &val, MapFlags::ANY)?;
    
        Ok(())
    }

    fn add_word_transition(&mut self, from: usize, to: usize, input: &str) -> Result<()> {
        assert!(input.len() >= 2);
        assert!(self.tss.len() > from);

        let mut s = self.tss.len();
        for _ in 0..input.len() {
            self.create_state()?;
        }

        self.add_transition(from, s, input.chars().nth(0).unwrap())?;

        for i in 1..input.len()-1 {
            self.add_transition(s, s + 1, input.chars().nth(i).unwrap())?;
            s += 1;
        }

        self.add_transition(s, to, input.chars().last().unwrap())?;

        Ok(())
    }

    fn add_not_word_transition(&mut self, from: usize, to: usize, input: &str) -> Result<()> {
        assert!(input.len() >= 2);

        self.add_transition(from, from, '*')?;
        self.add_word_transition(from, to, input)?;


        Ok(())
    }

    pub fn match_http_uri(&mut self, uri: &str) -> Result<()> {
        // if we encounter a newline, abort this match
        self.add_not_word_transition(self.s_init(), self.s_no_match(), CRLF)?;
        self.add_word_transition(self.s_init(), self.s_match(), &uri)?;

        Ok(())
    }
    
    pub fn match_http_hdr(&mut self, key: &str, val: &str) -> Result<()> {
        let mut s = self.tss.len();
        let num_states = 2*CRLF.len() + key.len() + val.len();
        for _ in 0..num_states {
            self.create_state()?;
        }

        // the first state of our new pattern needs to get 
        // hooked up to s_init
        self.add_transition(self.s_any(), s, CRLF.chars().nth(0).unwrap())?;
        self.add_transition(s, s + 1, CRLF.chars().nth(1).unwrap())?;
        s += 1;
    
        for c in key.chars() {
            self.add_transition(s, s + 1, c.to_ascii_lowercase())?;
            self.add_transition(s, s + 1, c.to_ascii_uppercase())?;
            s += 1;
        }
        
        self.add_transition(s, s, '\t')?;
        self.add_transition(s, s, ' ')?;
    
        self.add_transition(s, s + 1, ':')?;
        s += 1;
    
        self.add_transition(s, s, '\t')?;
        self.add_transition(s, s, ' ')?;
    
        for c in val.chars() {
            self.add_transition(s, s + 1, c.to_ascii_lowercase())?;
            self.add_transition(s, s + 1, c.to_ascii_uppercase())?;
            s += 1;
        }
    
        self.add_transition(s, s + 1, CRLF.chars().nth(0).unwrap())?;
        s += 1;
        self.add_transition(s, self.s_match(), CRLF.chars().nth(1).unwrap())?;
    
        Ok(())
    }

}