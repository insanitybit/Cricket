extern crate url;
extern crate serde;
extern crate hyper;

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
    HyperError(hyper::error::Error),
    AlreadyRunning // Ideally will extend to provide further information
    // ParserError(url::parser::ParseError)
}

impl fmt::Display for FuzzerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FuzzerError::IoError(ref err) => write!(f, "IO error: {}", err),
            FuzzerError::Ser(ref err) => write!(f, "Parse error: {}", err),
            FuzzerError::HyperError(ref err) => write!(f, "Hyper error: {}", err),
            FuzzerError::AlreadyRunning => write!(f, "Fuzzer is already running!"),
            // FuzzerError::ParserError(ref err) => write!(f, "URL error: {}", err),
        }
    }
}

impl error::Error for FuzzerError {
    fn description(&self) -> &str {
        match *self {
            FuzzerError::IoError(ref err)       => err.description(),
            FuzzerError::Ser(ref err)           => error::Error::description(err),
            FuzzerError::HyperError(ref err)    => err.description(),
            FuzzerError::AlreadyRunning         => &"Launch was called while the Fuzzer is running.",
            // FuzzerError::ParserError(ref err) => error::Error::description(err),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            FuzzerError::IoError(ref err) => Some(err),
            FuzzerError::Ser(ref err) => Some(err),
            FuzzerError::HyperError(ref err) => Some(err),
            FuzzerError::AlreadyRunning     => None

            // FuzzerError::ParserError(ref err) => Some(err),
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

impl From<hyper::error::Error> for FuzzerError {
    fn from(err: hyper::error::Error) -> FuzzerError {
        FuzzerError::HyperError(err)
    }
}

// impl From<url::parser::ParseError> for FuzzerError {
//     fn from(err: url::parser::ParseError) -> FuzzerError {
//         FuzzerError::ParserError(err)
//     }
// }
