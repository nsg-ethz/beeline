use core::panic;
use std::collections::{HashMap, HashSet};

pub struct DFA {
    sid: u16,
    states: HashSet<u16>,
    transitions: HashMap<(u16, char), (u16, u16)>,
}

impl DFA {

    pub fn new(reserved_states: impl Iterator<Item = u16>) -> DFA {
        DFA {
            sid: 0,
            states: HashSet::from_iter(reserved_states),
            transitions: HashMap::new(),
        }
    }

    fn insert_new_state(&mut self) -> u16 {
        while self.states.contains(&self.sid) {
            self.sid += 1;
        }

        self.states.insert(self.sid);
        self.sid
    }

    pub fn add_transition(&mut self, from: u16, to: u16, input: char, action: u16) {
        let lc_input = input.to_ascii_lowercase();
        let uc_input = input.to_ascii_uppercase();

        if let Some((cstate, _)) = self.transitions.insert((from, lc_input), (to, action)) {
            panic!("Transition from {} to {} on {} already exists", from, cstate, input);
        }

        if lc_input != uc_input {
            if let Some((cstate, _)) = self.transitions.insert((from, uc_input), (to, action)) {
                panic!("Transition from {} to {} on {} already exists", from, cstate, input);
            }
        }
    }

    pub fn add_transition_to_new_state(&mut self, from: u16, input: char, action: u16) -> u16 {
        match self.transitions.get(&(from, input)) {
            Some((cnext, caction)) => if *caction == action { *cnext } else { panic!("Transition from {} to {} on {} already exists", from, cnext, input) },
            None => {
                let next = self.insert_new_state();
                self.add_transition(from, next, input, action);
                next
            }
        }
    }

    pub fn add_transitions_to_new_state(&mut self, from: u16, input: &str, final_action: u16) -> u16 {
        assert!(input.len() >= 1);
        assert!(self.states.contains(&from));

        let mut state = from;
        for (idx, c) in input.chars().enumerate() {
            let action = if idx == input.len() - 1 { final_action } else { 0 };
            state = self.add_transition_to_new_state(state, c, action);
        }

        state
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16>  {
        self.states.iter()
    }

    pub fn iter_transitions<'a>(&'a self) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a u16)>  {
        self.transitions
            .iter()
            .map(|((from, input), (to, action))| (from, to, input, action))
    }

}