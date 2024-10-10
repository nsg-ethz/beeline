use anyhow::{Context, Result};
use log::warn;
use crate::{
    dfa::Dfa, Action, Modification
};
use prost_build::{Config, Module};
use std::{collections::HashMap, fs, path::Path};

pub struct RpcParser {
    pub s_init: u16,
    pub s_any: u16,
    pub modifications: HashMap<u8, Modification>,
    field_numbers: HashMap<String, usize>,
    dfa: Dfa,
}

impl RpcParser {

    pub fn new<P: AsRef<Path>>(s_init: u16, s_any: u16, proto: P) -> Result<RpcParser> {
        let states = vec![
            s_init,
            s_any,
        ];

        let proto_path = fs::canonicalize(&proto)?;
        let proto_path = proto_path.as_path();
        let proto_dir = proto_path
            .parent()
            .expect("proto file should reside in a directory");

        let mut config = Config::new();
        let fds = config.load_fds(&[proto_path], &[proto_dir])?;

        let services = fds
            .file
            .into_iter()
            .map(|descriptor| {
                (
                    Module::from_protobuf_package_name(descriptor.package()),
                    descriptor,
                )
            })
            .collect::<Vec<_>>();

        let mut field_numbers = HashMap::new();
        for s in services.iter() {
            for m in s.1.message_type.iter() {
                for f in m.field.iter() {
                    match (&f.name, f.number) {
                        (Some(name), Some(number)) => {
                            field_numbers.insert(name.clone(), number as usize);
                        },
                        _ => warn!("Field name or number missing"),
                    }
                }
            }
        }

        Ok(RpcParser {
            s_init,
            s_any,
            modifications: HashMap::new(),
            field_numbers,
            dfa: Dfa::new(states.into_iter()),
        })
    }
    
    pub fn match_field(&mut self, key: &str, value: &str) -> Result<()> {
        let field_number = self.field_numbers
            .get(key)
            .context("Unknown field")?;

        // self.dfa.start_pattern(self.s_any)
        //     .push(CRLF)?
        //     .start_capturing()
        //     .push(key)?
        //     .push_optional('\t')?
        //     .push_optional(' ')?
        //     .push(":")?
        //     .push_optional('\t')?
        //     .push_optional(' ')?
        //     .push(val)?
        //     .match_and_restart_with(CRLF)?;
            
        Ok(())
    }

    pub fn iter_states<'a>(&'a self) -> impl Iterator<Item = &'a u16>  {
        self.dfa.iter_states()
    }

    pub fn iter_transitions<'a>(&'a self) -> impl Iterator<Item = (&'a u16, &'a u16, &'a char, &'a Action)>  {
        self.dfa.iter_transitions()
    }

}