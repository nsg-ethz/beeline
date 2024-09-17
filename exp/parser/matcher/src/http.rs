use anyhow::{Ok, Result};
use crate::dfa::DFA;

const CRLF: &str = "\r\n";

pub struct HttpMatcher {
    pub s_init: u16,
    pub s_any: u16,
    pub dfa: DFA,
}

#[allow(dead_code)]
impl HttpMatcher {

    pub fn new(s_init: u16, s_any: u16) -> HttpMatcher {
        let states = vec![
            s_init,
            s_any,
        ];

        HttpMatcher {
            s_init,
            s_any,
            dfa: DFA::new(states.into_iter()),
        }
    }

    pub fn done_on_http_hdr_end(&mut self) -> Result<()> {
        self.dfa.start_pattern(self.s_any)
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(())
    }

    pub fn match_http_uri(&mut self, uri: &str) -> Result<()> {
        self.dfa.start_pattern(self.s_init)
            .push("POST ")?
            .start_capturing()
            .match_on(uri)?;

        Ok(())
    }
    
    pub fn match_http_hdr(&mut self, key: &str, val: &str) -> Result<()> {
        self.dfa.start_pattern(self.s_any)
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
        self.dfa.start_pattern(self.s_any)
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