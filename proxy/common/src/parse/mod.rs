pub mod http;
pub mod dfa;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Starts capturing a range
    /// The start index is identified by the cid
    StartCapture(u8),

    /// Ends capturing a range with a given cid (1st argument)
    /// The range is identified by the mid (2nd argument)
    EndCapture(u8, u8),

    /// Matches a filter with a given fid
    Match(u8),

    /// Terminates parsing
    Done,

    // No action
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
