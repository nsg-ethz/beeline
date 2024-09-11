use anyhow::{Context, Ok, Result};
use libbpf_rs::{MapHandle, MapType, MapFlags};
use libbpf_sys;
use std::{
    mem::size_of, os::fd::{AsFd, AsRawFd}
};

use crate::parser;
use crate::dfa::{Action, DFA};

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

    fn a_cap_mask(&self) -> u16 {
        self.skel.rodata().a_cap_mask
    }

    fn state_action_to_raw(&self, state: u16, action: Action) -> u32 {
        let action = match action {
            Action::Capture(cid) => {
                let raw_cid = (cid as u16) & self.a_cap_mask();
                if raw_cid != cid as u16 {
                    panic!("Capture group id {} is too large, truncating to {}", cid, raw_cid);
                }
                raw_cid
            }
            Action::Match(cid) => {
                let raw_cid = (cid as u16) & self.a_cap_mask();
                if raw_cid != cid as u16 {
                    panic!("Capture group id {} is too large, truncating to {}", cid, raw_cid);
                }

                self.a_match() | (self.a_cap_mask() & raw_cid)
            },
            Action::Done => self.a_done(),
            Action::None => 0,
        };

        ((action as u32) << 16) | (state as u32)
    }

    pub fn inject_dfa(&mut self) -> Result<()> {
        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        self.done_on_http_hdr_end()?;

        let mut states = self.dfa.iter_states()
            .map(|s| s.clone())
            .collect::<Vec<_>>();

        states.sort();

        let mut tss = states.iter()
            .map (|idx| self.create_state(*idx))
            .collect::<Result<Vec<_>>>()?;

        for (from, to, input, action) in self.dfa.iter_transitions() {
            let ts = tss.get_mut(*from as usize).unwrap();
            let key = (*input as u8).to_ne_bytes();

            let val = self.state_action_to_raw(*to, *action);
            let val = val.to_ne_bytes();
            ts.update(&key, &val, MapFlags::ANY)?;
        }

        Ok(())
    }

    fn create_state(&mut self, state: u16) -> Result<MapHandle> {
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

    fn done_on_http_hdr_end(&mut self) -> Result<()> {
        self.dfa.start_pattern(self.s_any())
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(())
    }

    pub fn match_http_uri(&mut self, uri: &str) -> Result<()> {
        self.dfa.start_pattern(self.s_init())
            .push("POST ")?
            .start_capturing()
            .match_on(uri)?;

        Ok(())
    }
    
    pub fn match_http_hdr(&mut self, key: &str, val: &str) -> Result<()> {
        self.dfa.start_pattern(self.s_any())
            .push(CRLF)?
            .start_capturing()
            .push(key)?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(val)?
            .match_on(CRLF)?;
            
        Ok(())
    }

    pub fn remove_http_hdr(&mut self, key: &str) -> Result<()> {
        self.dfa.start_pattern(self.s_any())
            .push(CRLF)?
            .start_capturing()
            .push(key)?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .push_optional('*')?
            .match_on(CRLF)?;

        Ok(())
    }

}