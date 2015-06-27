#![allow(unused_features)]
#![allow(unused_variables)]
#![feature(custom_derive, plugin, fs_walk, convert, scoped)]
#![plugin(serde_macros)]

// extern crate csv;
extern crate iron;
extern crate router;
extern crate serde;
extern crate url;
extern crate threadpool;
extern crate hyper;
extern crate num_cpus;

use self::hyper::Client;
use self::hyper::client::{IntoUrl, Response};
use std::str::FromStr;
use serde::json::{self, Value};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::prelude::*;
use std::{io,error};
use std::error::Error;
use std::convert::From;
use std::fmt;
use std::thread;
use std::sync::{Arc, Mutex};

pub trait FuzzerView {
    fn get_stats(&self) -> String;
    fn passq(&self, &str);
}


pub trait Genetic {
    fn score_stats(&self) -> u64;
    fn get_spread_rate(&self) -> u32;
}

#[derive(Debug,Display)]
pub enum FuzzerError {
    IoError(io::Error),
    Ser(serde::json::error::Error)
}

impl fmt::Display for FuzzerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FuzzerError::IoError(ref err) => write!(f, "IO error: {}", err),
            FuzzerError::Ser(ref err) => write!(f, "Parse error: {}", err),
        }
    }
}

impl error::Error for FuzzerError {
    fn description(&self) -> &str {
        match *self {
            FuzzerError::IoError(ref err) => err.description(),
            FuzzerError::Ser(ref err) => error::Error::description(err),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            FuzzerError::IoError(ref err) => Some(err),
            FuzzerError::Ser(ref err) => Some(err),
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

#[derive(Serialize, Deserialize)]
pub struct AFLView {
    hostname: String,
    neighbors: Vec<String>,
    generation: u64,
    mutation_rate: f64,
    args: Vec<String>,
    spread_rate: u32
}

impl Genetic for AFLView {
    fn score_stats(&self) -> u64 {
        let titles = vec![
        "paths_total".to_owned(),
        "paths_found".to_owned(),
        "max_depth".to_owned()];

        let mut stats = String::with_capacity(512);
        let stats : Vec<String> = json::from_str(&self.get_stats()).unwrap();
        let mut score : u64 = 0;

        for stat in stats.iter() {
            let stats : Vec<String> = stat.split("\n")
            .map(|s| s.replace(" ", "").to_owned()).collect();

            for stat in stats {
                let stat : Vec<String> = stat.split(":").map(|s| s.to_owned()).collect();
                if stat.len() != 2 {continue};
                if titles.contains(&stat[0]) {
                    let s : Result<u64,_> = FromStr::from_str(&stat[1]);
                    score += s.unwrap();
                }
            }
        }
        score
    }

    fn get_spread_rate(&self) -> u32 {
        self.spread_rate
    }

}

impl FuzzerView for AFLView {
    fn get_stats(&self) -> String {
        let mut client = Client::new();
        let mut s = String::with_capacity(512);

        let url =  self.hostname.clone() + &"/stats";
        let url = url.into_url().unwrap();
        let mut res = client.get(url).send().unwrap();
        res.read_to_string(&mut s).unwrap();
        s
    }

    fn passq(&self, host: &str) {
        let mut client = Client::new();
        let mut s = String::new();

        let url =  self.hostname.clone() + &"/passq";
        let url = url.into_url().unwrap();
        let mut res = client.post(url).send().unwrap();
        res.read_to_string(&mut s).unwrap();
    }

}

#[derive(Serialize, Deserialize)]
pub struct Network<T : FuzzerView + serde::ser::Serialize
                     + serde::de::Deserialize + Genetic + Sync> {
    workers:Vec<BTreeMap<String,T>>,
    worker_count: usize,
    generation: u64,
    mutation_rate: u64
}

impl<T : FuzzerView
+ serde::ser::Serialize
+ serde::de::Deserialize
+ Genetic + Sync> Network<T> {
    pub fn new() -> Network<T> {
        Network {
            workers:Vec::new(),
            generation: 0,
            mutation_rate: 500,
            worker_count: 0
        }
    }

    pub fn load_network(path: String) -> Result<Network<T>,FuzzerError> {
        let mut s = String::with_capacity(256);
        let mut f = try!(File::open(&path));

        try!(f.read_to_string(&mut s));

        let net : Network<T> = try!(json::from_str(&s));
        Ok(net)
    }

    // implement proper error handling
    pub fn save_network(&self, path: &str) -> Result<(()),FuzzerError> {
        let net = json::to_value(self);
        let jnet = &net.as_string().unwrap();


        let mut f = try!(File::create(&path));
        try!(f.write_all(jnet.as_bytes()));
        Ok(())
    }

    pub fn score(&self) -> u64 {
        let mut score = 0;
        for worker in self.workers.iter() {

            for (name,view) in worker.iter() {
                score += view.score_stats();
            }
        }
        score
    }

    /// Commands remote Fuzzer instances to begin work
    /// Takes a callback, which must return a value of PartialEq + Eq
    /// The callback acts as a fitness function
    pub fn fuzz<F>(&self, lifespan: &u32, callback: F) where
        F: Fn(&str, &T) {
        // let mut intervals : Vec<u64> = Vec::with_capacity(self.worker_count);
        // 15 minutes
        // let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);
        let mut lifespan = lifespan.clone();
        // let interval = lifespan / 5; // Every 3 minutes

        while lifespan > 0 {
            for worker in self.workers.iter() {
                    for (key,value) in worker.iter() {
                        let spread_rate = value.get_spread_rate();
                        let mut interval = lifespan / spread_rate;
                        // thread::scoped(move|| {
                            while interval > 0 {
                                value.passq(key);
                                thread::sleep_ms(interval);
                                interval -= spread_rate;
                            }
                        // });
                        lifespan -= interval;
                        callback(&key, &value);
                    }
            }
        }

    }
}
