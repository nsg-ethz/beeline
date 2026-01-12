use crate::{
    bpf::types::*,
    parse::h2::{create_header_maps, dfa::Dfa, Action},
};
use anyhow::Result;
use as_bytes::AsBytes;
use httlib_huffman as huffman;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

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
        let mut key_encoded = Vec::new();
        huffman::encode(key.as_bytes(), &mut key_encoded)?;

        self.dfa
            .start_pattern(self.s_any)
            .push(&key_encoded)?
            .capture_field_value();

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

pub fn populate_static_table(static_table: &MapHandle) -> Result<()> {
    let insert = |idx: u32, key: &str, val: Option<&str>| {
        let mut hf_key = Vec::new();
        huffman::encode(key.as_bytes(), &mut hf_key)?;

        let mut hf_val = Vec::new();
        if let Some(val) = val {
            huffman::encode(val.as_bytes(), &mut hf_val)?;
        }

        hf_key.resize(32, 0);
        hf_val.resize(32, 0);

        let hf = header_field {
            key: hf_key.try_into().unwrap(),
            val: hf_val.try_into().unwrap(),
        };

        let idx = unsafe { idx.as_bytes() };
        let hf = unsafe { hf.as_bytes() };

        static_table.update(&idx, &hf, MapFlags::ANY)?;

        anyhow::Ok(())
    };

    let (st_keys, st_hfs) = create_header_maps();
    for (key, vals) in st_hfs.iter() {
        for (val, idx) in vals.iter() {
            insert(*idx as u32, key, Some(val))?;
        }
    }

    for (key, idx) in st_keys.iter() {
        insert(*idx as u32, key, None)?;
    }

    static_table.freeze()?;

    Ok(())
}
