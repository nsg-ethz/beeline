pub mod http;
pub mod dfa;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Capture(u8),
    Match(u8),
    Done,
    None
}

#[derive(Clone, Debug, PartialEq)]
pub struct Modification {
    pub replacement: String,
    pub tail: u8,
}

impl Action {

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Action::None)
    }

}
