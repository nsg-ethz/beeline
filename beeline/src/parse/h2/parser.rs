use crate::parse::h2::{create_header_maps, dfa::Dfa, Action};
use anyhow::Result;
use httlib_huffman as huffman;

pub struct Parser {
    s_any: u16,

    dfa: Dfa,
}

#[allow(dead_code)]
impl Parser {
    /// Creates a new HTTP/2 parser.
    ///
    /// Additional configuration must be done through the builder methods before calling `attach`.
    pub fn new(s_init: u16, s_any: u16) -> Parser {
        let states = vec![s_init, s_any];

        Parser {
            s_any,
            dfa: Dfa::new(states.into_iter()),
        }
    }

    pub fn num_captures(&self) -> u8 {
        self.dfa.num_captures()
    }

    pub fn num_states(&self) -> usize {
        self.dfa.num_states()
    }

    /// Configures the parser to capture an HTTP/2 header field value.
    ///
    /// # Arguments
    ///
    /// * `key` - The HTTP/2 header name to capture
    ///
    /// # Errors
    ///
    /// Returns an error if the pattern configuration fails.
    pub fn capture_http_hdr(&mut self, key: &str) -> Result<()> {
        let cid = self.dfa.insert_new_capture_start();
        let (st_keys, st_hfs) = create_header_maps();

        fn insert_idx(dfa: &mut Dfa, from: u16, cid: u8, idx: u8) -> Result<()> {
            let mut key_encoded = Vec::new();
            key_encoded.insert(0, idx + 16);

            dfa.start_pattern(from)
                .push(&key_encoded)?
                .capture_field_value(Some(cid));
            Ok(())
        }

        if let Some(idx) = st_keys.get(key) {
            insert_idx(&mut self.dfa, self.s_any, cid, *idx as u8)?;
        } else if let Some(vals) = st_hfs.get(key) {
            for (_, idx) in vals.iter() {
                insert_idx(&mut self.dfa, self.s_any, cid, *idx as u8)?;
            }
        }

        let mut key_encoded = Vec::new();
        huffman::encode(key.as_bytes(), &mut key_encoded)?;
        key_encoded.insert(0, 16);

        self.dfa
            .start_pattern(self.s_any)
            .push(&key_encoded)?
            .capture_field_value(Some(cid));

        Ok(())
    }

    /// Returns an iterator over all states in the parser's DFA.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to state identifiers.
    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.dfa.iter_states()
    }

    /// Returns an iterator over all transitions in the parser's DFA.
    ///
    /// # Returns
    ///
    /// An iterator yielding tuples of (from_state, to_state, input_byte, action).
    /// Note: Unlike HTTP/1.1, HTTP/2 uses bytes instead of chars for transitions.
    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a u8, &'a Action)> {
        self.dfa.iter_transitions()
    }
}
