use std::error;
use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    BadDecrypt,
    BadHex(String),
    KeyImport(String),
    InputOverflow,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::result::Result<(), fmt::Error> {
        match self {
            Self::IO(e) => write!(f, "io error: {e}"),
            Self::BadDecrypt => write!(f, "decryption failed"),
            Self::BadHex(s) => write!(f, "hex error: {s}"),
            Self::KeyImport(s) => write!(f, "key import error: {s}"),
            Self::InputOverflow => write!(f, "input overflow"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::IO(err)
    }
}
