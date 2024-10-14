use anyhow::{bail, Result};
use crate::parse::Action;
use log::debug;
use std::collections::{HashMap, HashSet};

pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,
    start: u16,

    // the current filter id
    fid: u8,

    // the current modification id
    mid: Option<u8>,

    // the current state id 
    sid: u16,

    // `true` if the current pattern captures a range
    capturing: bool,
}

impl DfaBuilder<'_> {

    pub fn push(&mut self, input: &str) -> Result<&mut Self> {
        assert!(self.dfa.states.contains(&self.sid));

        for c in input.chars() {
            let start_capture = self.capturing && self.mid.is_none();

            if let Some((to, act)) = self.dfa.transitions.get(&(self.sid, c)).map(|(to, action)| (*to, *action)) {    
                match (act, start_capture) {
                    (Action::StartCapture(mid), true) => {
                        self.mid = Some(mid);
                        self.sid = to;
                    },
                    (Action::EndCapture(mid), true) => {
                        self.mid = Some(mid);
                        self.sid = to;
                    },
                    (Action::None, _) => self.sid = to,
                    (old_act, _) => bail!("Conflicting actions (old: {:?}, new: {:?}) for input {}", old_act, act, c.escape_debug())
                }
            }
            else {
                let action = if start_capture {
                    self.mid = Some(self.dfa.new_capture_group());
                    Action::StartCapture(self.mid.unwrap())
                }
                else {
                    Action::None
                };

                let next = self.dfa.insert_state();
                self.dfa.insert_transition(self.sid, next, c, action);
                self.sid = next;
            }
        }

        Ok(self)
    }

    pub fn push_optional(&mut self, input: char) -> Result<&mut Self> {
        assert!(self.dfa.states.contains(&self.sid));
        
        // if we start capturing, we have to create a new state
        let start_capture = self.capturing && self.mid.is_none();
        if start_capture {
            self.push(&input.to_string())?;
        }

        // we can keep in the current state as long as we want
        if let Some((to, action)) = self.dfa.insert_transition(self.sid, self.sid, input, Action::None) {
            if to != self.sid || action.is_some() {
                bail!("Conflicting transition for optional input.");
            }
        }

        Ok(self)
    }

    pub fn start_capturing(&mut self) -> &mut Self {
        self.capturing = true;
        self
    }

    pub fn match_on(&mut self, input: &str) -> Result<u8> {
        self.end_pattern(input, Action::Match(self.fid), None)?;
        Ok(self.fid)
    }

    pub fn match_and_restart_with(&mut self, input: &str) -> Result<u8> {
        let to = self.get_sid(input);
        self.end_pattern(input, Action::Match(self.fid), to)?;
        Ok(self.fid)
    }

    pub fn end_caputuring_and_restart_with(&mut self, input: &str) -> Result<u8> {
        if !self.capturing || self.mid.is_none() {
            bail!("No capture ID set.");
        }

        let to = self.get_sid(input);
        self.end_pattern(input, Action::EndCapture(self.mid.unwrap()), to)?;

        Ok(self.mid.unwrap())
    }

    pub fn done_on(&mut self, input: &str) -> Result<&mut Self> {
        if self.capturing || self.mid.is_some() {
            bail!("Capture group will always get aborted.");
        }

        self.end_pattern(input, Action::Done, None)
    }
    
    fn end_pattern(&mut self, input: &str, action: Action, to: Option<u16>) -> Result<&mut Self> {
        let all_but_last: String = input.chars()
            .take(input.len() - 1)
            .collect();

        if all_but_last.len() > 0 {
            self.push(&all_but_last)?;
        }

        let last_char = input.chars().last().unwrap();
        let to = to.or_else(|| {
            if let Some((state, old_action)) = self.dfa.transitions.get(&(self.sid, last_char)) {
                println!("Found state: {:?}", state);
                if *state == self.sid && (old_action.is_none() || *old_action == action) {
                    println!("it's valid");
                    return Some(*state);
                }
            }
            
            None
        })
        .unwrap_or_else(|| self.dfa.insert_state());
    
        if let Some((state, old_action)) = self.dfa.insert_transition(self.sid, to, last_char, action) {
            if state != self.sid || (old_action.is_some() && old_action != action) {
                bail!("Conflicting transition to state (old: {:?}, new: {:?}) and action (old: {:?}, new: {:?}) on input: {}", state, self.sid, old_action, action, last_char.escape_debug());
            }
        }

        Ok(self)
    }

    fn get_sid(&self, input: &str) -> Option<u16> {
        let mut sid = self.start;
        for c in input.chars() {
            if let Some((to, _)) = self.dfa.transitions.get(&(sid, c)) {
                sid = *to;
            }
            else {
                return None;
            }
        }

        Some(sid)
    }

}

pub(crate) struct Dfa {
    // next free state id
    sid: u16,

    // next free capture id
    // mid 0 is reserved -> init from 1
    mid: u8,

    states: HashSet<u16>,
    transitions: HashMap<(u16, char), (u16, Action)>,
}

impl Dfa {

    pub fn new(reserved_states: impl Iterator<Item = u16>) -> Dfa {
        Dfa {
            sid: 0,
            mid: 0,
            states: reserved_states.collect(),
            transitions: HashMap::new(),
        }
    }

    fn insert_state(&mut self) -> u16 {
        while self.states.contains(&self.sid) {
            self.sid += 1;
        }

        self.states.insert(self.sid);
        self.sid
    }

    fn new_capture_group(&mut self) -> u8 {
        let mid = self.mid;
        self.mid += 1;
        mid
    }

    pub fn insert_transition(&mut self, from: u16, to: u16, input: char, action: Action) -> Option<(u16, Action)> {
        let lc_input = input.to_ascii_lowercase();
        let uc_input = input.to_ascii_uppercase();

        if let Some(transition) = self.transitions.insert((from, lc_input), (to, action)) {
            return Some(transition);
        }

        debug!(target: "dfa", "{} --({})--> {} {:?}", from, input.escape_debug(), to, action);

        if lc_input != uc_input {
            if let Some(transition) = self.transitions.insert((from, uc_input), (to, action)) {
                return Some(transition);
            }
        }

        None
    }

    pub fn start_pattern<'a>(&'a mut self, from: u16, fid: u8) -> DfaBuilder<'a> {
        debug!(target: "dfa", "new pattern starting from: {} for filter: {}", from, fid);
        DfaBuilder {
            dfa: self,
            start: from,
            fid,
            sid: from,
            mid: None,
            capturing: false,
        }
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16>  {
        self.states.iter()
    }

    pub fn iter_transitions<'a>(&'a self) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)>  {
        self.transitions
            .iter()
            .map(|((from, input), (to, action))| (from, to, input, action))
    }

}