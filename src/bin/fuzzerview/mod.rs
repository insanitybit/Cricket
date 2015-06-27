/// FuzzerView
///
/// # Usage
///
/// The FuzzerView Module provides a simple interface to a group of remove fuzzer instances
///
extern crate serde;
extern crate hyper;

use self::hyper::Client;
use self::hyper::client::IntoUrl;
use std::str::FromStr;
use serde::json;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::error::Error;
use std::thread;

mod fuzzererror;
use self::fuzzererror::FuzzerError;


/// Trait for types that represent a [Fuzzer](https://en.wikipedia.org/wiki/Fuzz_testing) across
/// a network.
///
/// FuzzerView
pub trait FuzzerView {
    fn get_stats(&self) -> String;
    fn passq(&self, &str);
}


/// Trait that defines a Genetic type, one that can score itself, and provide a rate of
/// reproduction
pub trait Genetic {
    // Returns a u64 representation of its score - to be replaced with Score trait
    fn score_stats(&self) -> u64;
    // Returns the number of milliseconds representing a rate of reproduction
    fn get_reproduction_rate(&self) -> u32;
}

/// AFLView
///
/// # Examples
/// ```rust
/// let aflopts = AFLOpts {
///     afl_path: "/path/to/afl-fuzz".to_owned(),
///     target_path: "/path/to/target".to_owned(),
///     ..Default::default()
/// }
/// ```
/// AFLView represents a 'view' of an AFL fuzzer across a network.

#[derive(Serialize, Deserialize)]
pub struct AFLView {
    hostname: String,
    neighbors: Vec<String>,
    generation: u64,
    mutation_rate: f64,
    args: Vec<String>,
    reproduction_rate: u32
}

impl FuzzerView for AFLView {
    // Returns a String, representing the stats of the AFL instance behind this AFLView
    fn get_stats(&self) -> String {
        let client = Client::new();
        let mut s = String::with_capacity(512);

        let url =  self.hostname.clone() + &"/stats";
        let url = url.into_url().unwrap();
        let mut res = client.get(url).send().unwrap();
        res.read_to_string(&mut s).unwrap();
        s
    }

    /// Commands the AFL Fuzzer to pass its queue to another host
    fn passq(&self, host: &str) {
        let client = Client::new();
        // let mut s = String::new();

        let url =  self.hostname.clone() + &"/passq";
        let url = url.into_url().unwrap();
        let mut res = client.post(url).body(host).send().unwrap();
        // res.read_to_string(&mut s).unwrap();
    }

}

impl Genetic for AFLView {
    /// Currently adds up the paths_total, paths_found, max_depth and returns it
    /// See AFL official docs for details
    fn score_stats(&self) -> u64 {
        let titles = vec![
        "paths_total".to_owned(),
        "paths_found".to_owned(),
        "max_depth".to_owned()];

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

    /// Returns the AFLView's reproduction rate
    fn get_reproduction_rate(&self) -> u32 {
        self.reproduction_rate
    }

}

/// Network
///
/// # Examples
/// ```rust
/// let aflopts = AFLOpts {
///     afl_path: "/path/to/afl-fuzz".to_owned(),
///     target_path: "/path/to/target".to_owned(),
///     ..Default::default()
/// }
/// ```
/// A Network represents a network of FuzzerViews using a graph-like structure.
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
    /// Returns a new Network<T>
    pub fn new() -> Network<T> {
        Network {
            workers:Vec::new(),
            generation: 0,
            mutation_rate: 500,
            worker_count: 0
        }
    }

    /// Loads a json representation of a Network from 'path'.
    /// Returns a FuzzerError if the file can not be opened, or if it is not valid json.
    pub fn load_network(path: String) -> Result<Network<T>,FuzzerError> {
        let mut s = String::with_capacity(256);
        let mut f = try!(File::open(&path));

        try!(f.read_to_string(&mut s));

        let net : Network<T> = try!(json::from_str(&s));
        Ok(net)
    }

    /// Writes a serialized json representation of a network to 'path'
    pub fn save_network(&self, path: &str) -> Result<(()),FuzzerError> {
        let net = json::to_value(self);
        let jnet = &net.as_string().unwrap();
        let mut f = try!(File::create(&path));
        try!(f.write_all(jnet.as_bytes()));
        Ok(())
    }

    /// The network scores itself by adding the score of every Fuzzer it monitors.
    // Should be moved to Genetic trait impl
    pub fn score(&self) -> u64 {
        let mut score = 0;
        for worker in self.workers.iter() {

            for view in worker.values() {
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
        unimplemented!();
        // let mut intervals : Vec<u64> = Vec::with_capacity(self.worker_count);
        // 15 minutes
        // let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);
        let mut lifespan = lifespan.clone();
        // let interval = lifespan / 5; // Every 3 minutes

        while lifespan > 0 {
            for worker in self.workers.iter() {
                for (key,value) in worker.iter() {
                    let reproduction_rate = value.get_reproduction_rate();
                    let mut interval = lifespan / reproduction_rate;
                    // thread::scoped(move|| {
                        while interval > 0 {
                            value.passq(key);
                            thread::sleep_ms(interval);
                            interval -= reproduction_rate;
                        }
                    // });
                    lifespan -= interval;
                    callback(&key, &value);
                }
            }
        }
    }
}
