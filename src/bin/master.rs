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
// extern crate ini;
extern crate hyper;



use hyper::Client;
use hyper::client::{IntoUrl, Response};

use serde::json::{self, Value};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::prelude::*;

// use ini::Ini;
/// WorkerView represents a worker node, which may be running fuzzing services. Every worker view

trait WorkerView {
    fn get_stats(&self) -> String;
    fn score_stats(&self) -> u64;
}

#[derive(Serialize, Deserialize)]
struct AFLView {
    hostname: String,
    neighbors: Vec<String>,
    generation: u64,
    mutation_rate: f64,
    args: Vec<String>,
    spread_rate: u64
}

impl WorkerView for AFLView {
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
        let mut stats = String::with_capacity(512);
        let stats : Vec<String> = self.get_stats().split("\n")
        .map(|s| s.replace(" ", "").to_owned()).collect();
        let mut score = 0;
        let mut attr = String::with_capacity(16);
        for stat in stats {
            let stat : Vec<String> = stat.split(":").map(|s| s.to_owned()).collect();
            println!("stat {:?}", stat);
        }
        score
    }
}


#[derive(Serialize, Deserialize)]
struct Network<T : WorkerView + serde::ser::Serialize + serde::de::Deserialize> {
    workers:Vec<BTreeMap<String,T>>,
    worker_count: usize,
    generation: u64,
    mutation_rate: u64
}

// TODO: Grab this from disk, can be stored in json

impl<T : WorkerView
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

    // implement proper error handling
    pub fn load_network(path: String) -> Network<T> {
        let mut s = String::new();
        let mut f = File::open(&path)
        .unwrap_or_else(|e| panic!("{}",e));

        f.read_to_string(&mut s)
        .unwrap_or_else(|e| panic!("{}",e));
        // let s = json::from_
        let net = json::from_str(&s).unwrap();
        net
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
        0
    }
}


fn main() {

    let mut network = Network::<AFLView>::load_network("./config/test_net.json".to_owned());
    // let mut stats = Vec::with_capacity(512 * network.worker_count);

    let mut cur_score = 0;
    let mut avg_score = 0;
    let mut high_score = 0;
    let mut low_score = 0;

    // loop {
        cur_score = network.score();

        // avg_score = network.calculate_average();
    // }

    // loop continuously grabbing stats, analyzing stats
    // Get stats repeatedly in intervals, average them before analyzing to avoid anomalous behavior
    // Based on stats, generate queue of networks
    // After analysis, generate interval, repeat process
    //
    //
    //
    //
    //

}
