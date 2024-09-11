use anyhow::{Context, Ok, Result};
use libbpf_rs::{MapHandle, MapType, MapFlags};
use libbpf_sys;
use std::{
    mem::size_of, os::fd::{AsFd, AsRawFd}
};

use crate::parser;
use crate::dfa::DFA;

const CRLF: &str = "\r\n";

pub struct StateMachine<'a, 'b> {
    skel: &'a mut parser::ParserSkel<'b>,
    dfa: DFA,
}

#[allow(dead_code)]
impl StateMachine<'_, '_> {

    pub fn new<'a, 'b>(skel: &'a mut parser::ParserSkel<'b>) -> StateMachine<'a, 'b> {
        let states = vec![
            skel.rodata().s_init,
            skel.rodata().s_any,
        ];

        StateMachine {
            skel,
            dfa: DFA::new(states.into_iter()),
        }
    }

    fn s_init(&self) -> u16 {
        self.skel.rodata().s_init
    }

    fn s_any(&self) -> u16 {
        self.skel.rodata().s_any
    }

    fn a_match(&self) -> u16 {
        self.skel.rodata().a_match
    }

    fn a_done(&self) -> u16 {
        self.skel.rodata().a_done
    }

    pub fn inject_match_dfa(&mut self) -> Result<()> {
        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        self.done_at_http_hdr_end();

        let mut states = self.dfa.iter_states()
            .map(|s| s.clone())
            .collect::<Vec<_>>();

        states.sort();

        let mut tss = states.iter()
            .map (|idx| self.create_match_state(*idx))
            .collect::<Result<Vec<_>>>()?;

        for (from, to, input, action) in self.dfa.iter_transitions() {
            let ts = tss.get_mut(*from as usize).unwrap();
            let key = (*input as u8).to_ne_bytes();

            let val = (*action as u32) << 16 | (*to as u32);
            let val = val.to_ne_bytes();
            ts.update(&key, &val, MapFlags::ANY)?;
        }

        Ok(())
    }

    fn create_match_state(&mut self, state: u16) -> Result<MapHandle> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        
        let idx = state as u32;
        let name = format!("t{}", idx);
        let map = MapHandle::create(MapType::Hash, Some(name), 1, 4, 256, &opts)
            .context("Failed to create map")?;
        let fd = map.as_fd().as_raw_fd();

        self.skel
            .maps()
            .s2ts_mat()
            .update(&idx.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
            .context("Failed to insert state into s2ts")?;

        Ok(map)
    }

    fn done_at_http_hdr_end(&mut self) {
        let hdr_end = format!("{}{}", CRLF, CRLF);
        self.dfa.add_transitions_to_new_state(self.s_any(), &hdr_end, self.a_done());
    }

    pub fn match_http_uri(&mut self, uri: &str) {
        // if we encounter a newline, abort this match
        self.dfa.add_transition(self.s_init(), self.s_init(), '*', 0);
        self.dfa.add_transitions_to_new_state(self.s_init(), &uri, self.a_match());
    }
    
    pub fn match_http_hdr(&mut self, key: &str, val: &str) {
        let s = self.dfa.add_transitions_to_new_state(self.s_any(), CRLF, 0);
        let s = self.dfa.add_transitions_to_new_state(s, key, 0);

        self.dfa.add_transition(s, s, '\t', 0);
        self.dfa.add_transition(s, s, ' ', 0);

        let s = self.dfa.add_transition_to_new_state(s, ':', 0);

        self.dfa.add_transition(s, s, '\t', 0);
        self.dfa.add_transition(s, s, ' ', 0);

        let s = self.dfa.add_transitions_to_new_state(s, val, 0);
        self.dfa.add_transitions_to_new_state(s, CRLF, self.a_match());
    }

}