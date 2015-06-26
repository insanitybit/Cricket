#![allow(unused_features)]
#![allow(unused_variables)]
#![feature(custom_derive, plugin, fs_walk, convert)]
#![plugin(serde_macros)]

// extern crate csv;
extern crate iron;
extern crate router;
extern crate serde;
extern crate url;
extern crate threadpool;
extern crate hyper;

use self::hyper::Client;
use self::hyper::client::{IntoUrl, Response};
use std::str::FromStr;
use std::io;
use std::num;
use serde::json::{self, Value};
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::prelude::*;
use std::io::error;

#[derive(Debug)]
enum FuzzerError {
    Io(io::Error),
    Parse(num::ParseIntError),
    Ser(serde::json::error::Error)
}

pub trait FuzzerView {
    fn get_stats(&self) -> String;
    // fn passq(&self, );
    fn score_stats(&self) -> u64;
    fn get_spread_rate(&self) -> u64;
}

#[derive(Serialize, Deserialize)]
pub struct AFLView {
    hostname: String,
    neighbors: Vec<String>,
    generation: u64,
    mutation_rate: f64,
    args: Vec<String>,
    spread_rate: u64
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

    fn get_spread_rate(&self) -> u64 {
        self.spread_rate
    }
}


#[derive(Serialize, Deserialize)]
pub struct Network<T : FuzzerView + serde::ser::Serialize + serde::de::Deserialize> {
    workers:Vec<BTreeMap<String,T>>,
    worker_count: usize,
    generation: u64,
    mutation_rate: u64
}

impl<T : FuzzerView
+ serde::ser::Serialize
+ serde::de::Deserialize> Network<T> {
    pub fn new() -> Network<T> {
        Network {
            workers:Vec::new(),
            generation: 0,
            mutation_rate: 500,
            worker_count: 0
        }
    }

    // implement proper error handling // Result<Network<T>,std::io::error>
    pub fn load_network(path: String) -> Result<Network<T>,FuzzerError> {
        let mut s = String::new();
        let mut f = try!(File::open(&path).map_err(FuzzerError::Io));

        try!(f.read_to_string(&mut s).map_err(FuzzerError::Io));

        // let s = json::from_
        try!(json::from_str(&s).map_err(FuzzerError::Ser));
        // Ok(net)
    }

    // implement proper error handling
    pub fn save_network(&self, path: &str) {
        let net = json::to_value(self);
        let mut f = File::create(&path).unwrap();
        f.write_all(&net.as_string().unwrap().as_bytes()).unwrap();
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

    pub fn launch(&self, lifespan: &u32) {
        let mut intervals : Vec<u64> = Vec::with_capacity(self.worker_count);
        for map in self.workers.iter() {
            for (host, worker) in map {
                intervals.push(*lifespan as u64 / worker.get_spread_rate());

            }
        }


    }
}
