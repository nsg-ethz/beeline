use anyhow::{bail, Result};
use crate::parse::Action;
use log::debug;
use std::collections::{HashMap, HashSet};

pub struct DfaBuilder<'a> {
    dfa: &'a mut Dfa,
    start: u16,
    sid: u16,
    cid: Option<u8>,
    capturing: bool,
}

impl DfaBuilder<'_> {

    pub fn push(&mut self, input: &str) -> Result<&mut Self> {
        assert!(self.dfa.states.contains(&self.sid));

        for c in input.chars() {
            let start_capture = self.capturing && self.cid.is_none();

            if let Some((to, act)) = self.dfa.transitions.get(&(self.sid, c)).map(|(to, action)| (*to, *action)) {    
                match (act, start_capture) {
                    (Action::Capture(cid), true) => {
                        self.cid = Some(cid);
                        self.sid = to;
                    },
                    (Action::None, false) => self.sid = to,
                    _ => bail!("Conflicting action {:?} for input {}", act, c.escape_debug())
                }
            }
            else {
                let action = if start_capture {
                    self.cid = Some(self.dfa.new_capture_group());
                    Action::Capture(self.cid.unwrap())
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
        let start_capture = self.capturing && self.cid.is_none();
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

    fn match_and_continue_with(&mut self, input: &str, to: Option<u16>) -> Result<u8> {
        if input.len() <= 1 {
            bail!("Cannot end pattern with character.");
        }

        let all_but_last: String = input.chars()
            .take(input.len() - 1)
            .collect();

        if all_but_last.len() > 0 {
            self.push(&all_but_last)?;
        }  

        if !self.capturing || self.cid.is_none() {
            bail!("No capture ID set.");
        }

        let cid = self.cid.unwrap();
        self.end_pattern(input.chars().last().unwrap(), Action::Match(cid), to)?;

        Ok(cid)
    }

    pub fn match_on(&mut self, input: &str) -> Result<u8> {
        self.match_and_continue_with(input, None)
    }

    pub fn match_and_restart_with(&mut self, input: &str) -> Result<u8> {
        let to = self.get_sid(input);
        self.match_and_continue_with(input, to)
    }

    pub fn done_on(&mut self, input: &str) -> Result<&mut Self> {
        if input.len() <= 1 {
            bail!("Cannot end pattern with character.");
        }

        let all_but_last: String = input.chars()
            .take(input.len() - 1)
            .collect();

        if all_but_last.len() > 0 {
            self.push(&all_but_last)?;
        }

        if self.capturing || self.cid.is_some() {
            bail!("Capture group will always get aborted.");
        }

        self.end_pattern(input.chars().last().unwrap(), Action::Done, None)
    }
    
    fn end_pattern(&mut self, input: char, action: Action, to: Option<u16>) -> Result<&mut Self> {
        let to = to.unwrap_or_else(|| self.dfa.insert_state());
        if let Some((state, action)) = self.dfa.insert_transition(self.sid, to, input, action) {
            if state != self.sid || action.is_some() {
                bail!("Conflicting transition for capture and match.");
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
    // cid 0 is reserved -> init from 1
    cid: u8,

    states: HashSet<u16>,
    transitions: HashMap<(u16, char), (u16, Action)>,
}

impl Dfa {

    pub fn new(reserved_states: impl Iterator<Item = u16>) -> Dfa {
        Dfa {
            sid: 0,
            cid: 1,
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
        let cid = self.cid;
        self.cid += 1;
        cid
    }

    pub fn insert_transition(&mut self, from: u16, to: u16, input: char, action: Action) -> Option<(u16, Action)> {
        let lc_input = input.to_ascii_lowercase();
        let uc_input = input.to_ascii_uppercase();

        if let Some(transition) = self.transitions.insert((from, lc_input), (to, action)) {
            return Some(transition);
        }

        debug!(target: "Dfa", "{} --({})--> {} {:?}", from, input.escape_debug(), to, action);

        if lc_input != uc_input {
            if let Some(transition) = self.transitions.insert((from, uc_input), (to, action)) {
                return Some(transition);
            }
        }

        None
    }

    pub fn start_pattern<'a>(&'a mut self, from: u16) -> DfaBuilder<'a> {
        debug!(target: "Dfa", "new pattern starting from: {}", from);
        DfaBuilder {
            dfa: self,
            start: from,
            sid: from,
            cid: None,
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