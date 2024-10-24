use anyhow::{Ok, Result};
use crate::parse::{
    dfa::Dfa, Action, Modification
};
use std::collections::HashMap;

const CRLF: &str = "\r\n";

pub struct HttpParser {
    pub s_init: u16,
    pub s_any: u16,

    /// the modifications that should be made for a given modification id
    pub modifications: HashMap<u8, Modification>,

    dfa: Dfa,
}

#[allow(dead_code)]
impl HttpParser {

    pub fn new(s_init: u16, s_any: u16) -> HttpParser {
        let states = vec![
            s_init,
            s_any,
        ];

        HttpParser {
            s_init,
            s_any,
            modifications: HashMap::new(),
            dfa: Dfa::new(states.into_iter()),
        }
    }

    pub fn done_on_http_hdr_end(&mut self) -> Result<()> {
        self.dfa.start_pattern(self.s_any)
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(())
    }

    // pub fn match_http_uri(&mut self, uri: &str) -> Result<()> {
    //     self.dfa.start_pattern(self.s_init)
    //         .push("POST ")?
    //         .start_capturing()
    //         .match_on(uri)?;

    //     Ok(())
    // }
    
    pub fn match_http_hdr(&mut self, key: &str, val: &str) -> Result<()> {
        self.dfa.start_pattern(self.s_any)
            .push(CRLF)?
            .push(key)?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(val)?
            .match_and_restart_with(CRLF)?;
            
        Ok(())
    }

    pub fn remove_http_hdr(&mut self, key: &str) -> Result<u8> {
        let mid = self.dfa.start_pattern(self.s_any)
            .push(CRLF)?
            .start_capturing()
            .push(key)?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF)?;

        self.modifications.insert(mid, Modification {
            replacement: "".to_string(),
            tail: 0,
        });

        Ok(mid)
    }

    pub fn set_http_hdr(&mut self, key: &str, val: &str) -> Result<u8> {
        let mid = self.dfa.start_pattern(self.s_any)
            .push(CRLF)?
            .push(key)?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .start_capturing()
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF)?;

        let val = val.to_string();
        self.modifications.insert(mid, Modification {
            replacement: val,
            tail: 2,
        });

        Ok(mid)
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16>  {
        self.dfa.iter_states()
    }

    pub fn iter_transitions<'a>(&'a self) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)>  {
        self.dfa.iter_transitions()
    }

}