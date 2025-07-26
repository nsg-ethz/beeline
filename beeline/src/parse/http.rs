use crate::parse::{dfa::Dfa, Action};
use anyhow::{Ok, Result};

const CRLF: &str = "\r\n";

pub struct HttpParser {
    pub s_init: u16,
    pub s_any: u16,

    dfa: Dfa,
}

#[allow(dead_code)]
impl HttpParser {
    pub fn new(s_init: u16, s_any: u16) -> HttpParser {
        let states = vec![s_init, s_any];

        HttpParser {
            s_init,
            s_any,
            dfa: Dfa::new(states.into_iter()),
        }
    }

    pub fn done_on_http_hdr_end(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .done_on(CRLF)?;

        Ok(())
    }

    pub fn match_http_req_status_line(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_init)
            .start_capturing()
            .push_optional('*')?
            .end_capturing(" ")?
            .start_capturing()
            .push_optional('*')?
            .push(" HTTP/1.1")?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn match_http_status_code(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_init)
            .push("HTTP/1.1 ")?
            .start_capturing()
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn match_http_hdr(&mut self, key: &str) -> Result<()> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .push(key)?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .start_capturing()
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn match_http_hdr_auth(&mut self) -> Result<()> {
        self.dfa
            .start_pattern(self.s_any)
            .push(CRLF)?
            .push("Authorization")?
            .push_optional('\t')?
            .push_optional(' ')?
            .push(":")?
            .push_optional('\t')?
            .push_optional(' ')?
            .push("Bearer ")?
            .start_capturing()
            .push_optional('*')?
            .push(".")?
            .push_optional('*')?
            .end_capturing(".")?
            .start_capturing() //start capturing signature
            .push_optional('*')?
            .end_caputuring_and_restart_with(CRLF, self.s_any)?;

        Ok(())
    }

    pub fn num_captures(&self) -> u8 {
        self.dfa.num_captures()
    }

    pub fn num_states(&self) -> usize {
        self.dfa.num_states()
    }

    pub fn s_crlf(&self) -> Option<u16> {
        self.dfa.get_state(self.s_any, "\r\n")
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16> {
        self.dfa.iter_states()
    }

    pub fn iter_transitions<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)> {
        self.dfa.iter_transitions()
    }
}
