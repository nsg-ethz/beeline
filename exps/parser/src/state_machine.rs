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
            skel.rodata().s_init as usize,
            skel.rodata().s_any as usize,
        ];

        StateMachine {
            skel,
            dfa: DFA::new(states.into_iter()),
        }
    }

    fn s_init(&self) -> usize {
        self.skel.rodata().s_init as usize
    }

    fn s_any(&self) -> usize {
        self.skel.rodata().s_any as usize
    }

    fn a_match(&self) -> usize {
        self.skel.rodata().a_match as usize
    }

    fn a_done(&self) -> usize {
        self.skel.rodata().a_done as usize
    }

    pub fn inject_match_dfa(&mut self) -> Result<()> {
        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        self.done_at_http_hdr_end();

        let mut states = self.dfa.iter_states()
            .map(|s| s.clone())
            .filter(|s| *s != self.a_match() && *s != self.a_done()) // actions are not states
            .collect::<Vec<_>>();

        states.sort();

        let mut tss = states.iter()
            .map (|idx| self.create_match_state(*idx))
            .collect::<Result<Vec<_>>>()?;

        for (from, to, input) in self.dfa.iter_transitions() {
            let ts = tss.get_mut(*from).unwrap();
            let key = (*input as u8).to_ne_bytes();
            let val = (*to as u32).to_ne_bytes();
            ts.update(&key, &val, MapFlags::ANY)?;
        }

        Ok(())
    }

    fn create_match_state(&mut self, idx: usize) -> Result<MapHandle> {
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        
        let name = format!("t{}", idx);
        let map = MapHandle::create(MapType::Hash, Some(name), 1, 4, 256, &opts)
            .context("Failed to create map")?;
        let fd = map.as_fd().as_raw_fd();

        self.skel
            .maps()
            .s2ts_mat()
            .update(&(idx as u32).to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
            .context("Failed to insert state into s2ts")?;

        Ok(map)
    }

    fn done_at_http_hdr_end(&mut self) {
        let hdr_end = format!("{}{}", CRLF, CRLF);
        self.dfa.add_transitions(self.s_any(), self.a_done(), &hdr_end);
    }

    pub fn match_http_uri(&mut self, uri: &str) {
        // if we encounter a newline, abort this match
        self.dfa.add_transition(self.s_init(), self.s_init(), '*');
        self.dfa.add_transitions(self.s_init(), self.a_match(), &uri);
    }
    
    pub fn match_http_hdr(&mut self, key: &str, val: &str) {
        let s = self.dfa.add_transitions_to_new_state(self.s_any(), CRLF);
        let s = self.dfa.add_transitions_to_new_state(s, key);

        self.dfa.add_transition(s, s, '\t');
        self.dfa.add_transition(s, s, ' ');

        let s = self.dfa.add_transition_to_new_state(s, ':');

        self.dfa.add_transition(s, s, '\t');
        self.dfa.add_transition(s, s, ' ');

        let s = self.dfa.add_transitions_to_new_state(s, val);
        self.dfa.add_transitions(s, self.a_match(), CRLF);
    }

}