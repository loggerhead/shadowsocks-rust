use std::fmt;

#[derive(PartialEq, Clone, Copy)]
pub enum Mode {
    Fast,
    Balance,
    None,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Mode::Fast => write!(f, "fast"),
            Mode::Balance => write!(f, "balance"),
            Mode::None => write!(f, "none"),
        }
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub mod rtt_record;
pub mod server_chooser;

pub use self::rtt_record::RttRecord;
pub use self::server_chooser::ServerChooser;
