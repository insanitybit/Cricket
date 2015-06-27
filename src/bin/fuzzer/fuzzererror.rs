extern crate url;
extern crate serde;

use std::io::prelude::*;
use std::{io,error};
use std::error::Error;
use std::convert::From;
use std::fmt;

/// A set of errors that can occur while dealing with a fuzzer or fuzzerview
#[derive(Debug)]
pub enum FuzzerError {
    IoError(io::Error),
    Ser(serde::json::error::Error),
    UrlError(url::parser::ParseError)
}

impl fmt::Display for FuzzerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FuzzerError::IoError(ref err) => write!(f, "IO error: {}", err),
            FuzzerError::Ser(ref err) => write!(f, "Parse error: {}", err),
            FuzzerError::UrlError(ref err) => write!(f, "URL error: {}", err),
        }
    }
}

impl error::Error for FuzzerError {
    fn description(&self) -> &str {
        match *self {
            FuzzerError::IoError(ref err) => err.description(),
            FuzzerError::Ser(ref err) => error::Error::description(err),
            FuzzerError::UrlError(ref err) => error::Error::description(err),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            FuzzerError::IoError(ref err) => Some(err),
            FuzzerError::Ser(ref err) => Some(err),
            FuzzerError::UrlError(ref err) => Some(err),
        }
    }
}

impl From<io::Error> for FuzzerError {
    fn from(err: io::Error) -> FuzzerError {
        FuzzerError::IoError(err)
    }
}

impl From<serde::json::error::Error> for FuzzerError {
    fn from(err: serde::json::error::Error) -> FuzzerError {
        FuzzerError::Ser(err)
    }
}

impl From<url::parser::ParseError> for FuzzerError {
    fn from(err: url::parser::ParseError) -> FuzzerError {
        FuzzerError::UrlError(err)
    }
}
