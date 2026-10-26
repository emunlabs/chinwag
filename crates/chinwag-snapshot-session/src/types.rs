#![forbid(unsafe_code)]

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Sqlite {
        code: i32,
        message: String,
    },
    Contract(&'static str),
    Closed,
    Io(std::io::Error),
    Cleanup {
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
    Rollback {
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite { code, message } => write!(f, "SQLite {code}: {message}"),
            Self::Contract(message) => f.write_str(message),
            Self::Closed => f.write_str("Connection is closed"),
            Self::Io(error) => error.fmt(f),
            Self::Cleanup { operation, cleanup } => write!(f, "{operation}; close: {cleanup}"),
            Self::Rollback { operation, cleanup } => write!(f, "{operation}; rollback: {cleanup}"),
        }
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FiniteReal(f64);
impl FiniteReal {
    pub fn new(value: f64) -> Result<Self> {
        if value.is_finite() {
            Ok(Self(value))
        } else {
            Err(Error::Contract("Non-finite SQL real"))
        }
    }
    pub fn get(self) -> f64 {
        self.0
    }
}
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(FiniteReal),
    Text(String),
    Blob(Vec<u8>),
}
pub type Rows = Vec<Vec<Value>>;
