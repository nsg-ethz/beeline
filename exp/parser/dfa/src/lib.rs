pub mod http;
pub mod dfa;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Capture(u8),
    Match(u8),
    Done,
    None
}

impl Action {

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Action::None)
    }

}
