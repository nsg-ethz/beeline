use core::panic;
use std::{collections::{HashMap, HashSet}};

pub struct DFA {
    sid: usize,
    states: HashSet<usize>,
    transitions: HashMap<(usize, char), usize>,
}

impl DFA {

    pub fn new(reserved_states: impl Iterator<Item = usize>) -> DFA {
        DFA {
            sid: 0,
            states: HashSet::from_iter(reserved_states),
            transitions: HashMap::new(),
        }
    }

    fn insert_new_state(&mut self) -> usize {
        while self.states.contains(&self.sid) {
            self.sid += 1;
        }

        self.states.insert(self.sid);
        self.sid
    }

    pub fn add_transition(&mut self, from: usize, to: usize, input: char) {
        let lc_input = input.to_ascii_lowercase();
        let uc_input = input.to_ascii_uppercase();

        if let Some(old) = self.transitions.insert((from, lc_input), to) {
            panic!("Transition from {} to {} on {} already exists", from, old, input);
        }

        if lc_input != uc_input {
            if let Some(old) = self.transitions.insert((from, uc_input), to) {
                panic!("Transition from {} to {} on {} already exists", from, old, input);
            }
        }
    }

    pub fn add_transition_to_new_state(&mut self, from: usize, input: char) -> usize {
        match self.transitions.get(&(from, input)) {
            Some(next) => *next,
            None => {
                let next = self.insert_new_state();
                self.transitions.insert((from, input), next);
                next
            }
        }
    }

    pub fn add_transitions(&mut self, from: usize, to: usize, input: &str) {
        assert!(input.len() >= 1);

        // add from and to if they aren't exisitng already
        if !self.states.contains(&from) {
            self.states.insert(from);
        }

        if !self.states.contains(&to) {
            self.states.insert(to);
        }

        let mut state = from;
        let all_but_last_chars = input.chars().take(input.len() - 1);
        for c in all_but_last_chars {
            state = self.add_transition_to_new_state(state, c);
        }

        let last_char = input.chars().last().unwrap();
        self.add_transition(state, to, last_char);
    }

    pub fn add_transitions_to_new_state(&mut self, from: usize, input: &str) -> usize {
        let to = self.insert_new_state();
        self.add_transitions(from, to, input);

        to
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a usize>  {
        self.states.iter()
    }

    pub fn iter_transitions<'a>(&'a self) -> impl Iterator<Item = (&'a usize, &'a usize, &'a char)>  {
        self.transitions
            .iter()
            .map(|((from, input), to)| (from, to, input))
    }

}