use anyhow::{anyhow, Context, Result};
use libbpf_rs::{MapHandle, MapType, MapFlags};
use libbpf_sys;
use std::{
    mem::size_of,
    os::fd::{AsFd, AsRawFd}
};

use crate::parser;

pub struct StateMachine<'a, 'b> {
    skel: &'a mut parser::ParserSkel<'b>,
    tss: Vec<MapHandle>
}

impl StateMachine<'_, '_> {

    pub fn new<'a, 'b>(skel: &'a mut parser::ParserSkel<'b>) -> Result<StateMachine<'a, 'b>> {
        let mut sm = StateMachine {
            skel,
            tss: Vec::new()
        };

        // create s_init
        sm.create_state()?;

        Ok(sm)
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
        let ts = self.tss.get_mut(from).ok_or_else(|| anyhow!("Invalid from state {}", from))?;
        let key = (input as u8).to_ne_bytes();
        let val = (to as u32).to_ne_bytes();
        ts.update(&key, &val, MapFlags::ANY)?;
    
        Ok(())
    }
    
    pub fn match_http_hdr_field(&mut self, key: String, val: String) -> Result<()> {
        let crlf = "\r\n";
        let num_states = 2*crlf.len() + key.len() + val.len();

        for _ in 0..num_states {
            self.create_state()?;
        }
    
        let s_init = self.skel.rodata().s_init;
        let s_match = self.skel.rodata().s_match;
        let mut s = s_init as usize;
    
        for c in crlf.chars() {
            self.add_transition(s, s + 1, c)?;
            s += 1;
        }
    
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
    
        self.add_transition(s, s + 1, crlf.chars().nth(0).unwrap())?;
        s += 1;
        self.add_transition(s, s_match as usize, crlf.chars().nth(1).unwrap())?;
    
        Ok(())
    }

}