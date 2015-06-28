#![feature(scoped)]
/// FuzzerView
///
/// # Usage
///
/// The FuzzerView Module provides a simple interface to a group of remove fuzzer instances
///
extern crate serde;
extern crate hyper;
extern crate threadpool;

use std::sync::mpsc::channel;
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
use self::fuzzererror::*;

/// Trait for types that represent a [Fuzzer](https://en.wikipedia.org/wiki/Fuzz_testing) across
/// a network.
///
/// FuzzerView
pub trait FuzzerView {
    fn get_stats(&self) -> Result<String,FuzzerError>;
    fn passq(&self, &str) -> Result<(), FuzzerError>;
    fn get_neighbors(&self) -> Vec<String>;
    fn get_hostname(&self)  -> String;
}

/// Trait that defines a Genetic<T> type, one that can score itself, and provide a rate of
/// reproduction
pub trait Genetic<T> {
    /// Returns a u64 representation of its score - to be replaced with Score trait
    fn score_stats(&self) -> Result<u64,FuzzerError>;
    /// Returns the number of milliseconds representing a rate of reproduction
    fn get_reproduction_rate(&self) -> u32;
    ///
    fn reproduce_with(mate: T) -> T;

    // mutate(&mut self);
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
#[derive(Serialize, Deserialize, Debug)]
pub struct AFLView {
    pub hostname: String,
    pub neighbors: Vec<String>,
    pub generation: u64,
    pub mutation_rate: f64,
    pub args: Vec<String>,
    pub reproduction_rate: u32,
    pub genes: String
}

impl AFLView {
    // fn new() {
    //     AFLView {
    //         hostname: String,
    //         neighbors: Vec<String>,
    //         generation: u64,
    //         mutation_rate: f64,
    //         args: Vec<String>,
    //         reproduction_rate: u32,
    //         genes: String
    //     }
    // }
}

// impl Default for AFLView {
//     fn default() -> AFLView {
//         AFLView {
//             generation: 0,
//             mutation_rate: 0.0,
//             args: vec!["default"],
//             reproduction_rate: 2,
//             genes: ""
//         }
//     }
// }

impl FuzzerView for AFLView {
    /// Returns a String, representing the stats of the AFL instance behind this AFLView
    fn get_stats(&self) -> Result<String, FuzzerError> {
        let client = Client::new();
        let mut s = String::with_capacity(512);

        let url =  self.hostname.clone() + &"/stats";
        let url = url.into_url().unwrap();

        let mut res = try!(client.get(url).send());
        try!(res.read_to_string(&mut s));
        Ok(s)
    }

    /// Commands the AFL Fuzzer to pass its queue to another host
    fn passq(&self, host: &str) -> Result<(), FuzzerError> {
        let client = Client::new();
        // let mut s = String::new();

        let url =  self.hostname.clone() + &"/passq";
        let url = url.into_url().unwrap();
        let mut res = try!(client.post(url).body(host).send());
        // res.read_to_string(&mut s).unwrap();
        Ok(())
    }


    fn get_neighbors(&self) -> Vec<String> {
        self.neighbors.clone()
    }
    fn get_hostname(&self)  -> String {
        return self.hostname.clone();
    }
}

impl<T:FuzzerView> Genetic<T> for AFLView {
    /// Currently adds up the paths_total, paths_found, max_depth and returns it
    /// See AFL official docs for details
    fn score_stats(&self) -> Result<u64,FuzzerError> {
        unimplemented!();
        // let titles = vec![
        // "paths_total".to_owned(),
        // "paths_found".to_owned(),
        // "max_depth".to_owned()];
        //
        // let stats = try!(&self.get_stats());
        //
        // let stats : Vec<String> = json::from_str(stats).unwrap();
        // let mut score : u64 = 0;
        //
        // for stat in stats.iter() {
        //     let stats : Vec<String> = stat.split("\n")
        //     .map(|s| s.replace(" ", "").to_owned()).collect();
        //
        //     for stat in stats {
        //         let stat : Vec<String> = stat.split(":").map(|s| s.to_owned()).collect();
        //         if stat.len() != 2 {continue};
        //         if titles.contains(&stat[0]) {
        //             let s : Result<u64,_> = FromStr::from_str(&stat[1]);
        //             score += s.unwrap();
        //         }
        //     }
        // }
        // score
    }

    /// Returns the AFLView's reproduction rate
    fn get_reproduction_rate(&self) -> u32 {
        self.reproduction_rate
    }
    /// Takes in a type T where T represents some Fuzzer. First, we send a json representation
    /// of our genetic schema to T : a struct filled with None. T will respond with a modified
    /// version that has a schema with all of the genetic information of T as well as any
    /// additional genes unique to the FuzzerView.
    ///
    /// So, if this FuzzerView has the genes:
    /// "a,b"
    /// and our mate, T has:
    /// 'b,c'
    ///  T will return 'a,b,c' with a modified genetic value of 'b' and 'c'

    /// This allows for cross-speciation where only one species genes are ever expressed at a time.
    /// For example, AFLView can hold the genetic data of a non-AFLView type T. It can't express
    /// these attributes itself, but if another type T reproduces with the AFLView, the type T's
    /// child *will* be able to express those genes.
    /// Possibly make the ability to cross with other species optional, or hide behind Bridge
    fn reproduce_with(mate: T) -> T {
        unimplemented!();
        let host = mate.get_hostname();

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
#[derive(Serialize, Deserialize, Debug)]
pub struct Network<T : FuzzerView + serde::ser::Serialize
                     + serde::de::Deserialize + Genetic<T> + Sync> {
    workers:Vec<BTreeMap<String,T>>,
    worker_count: usize,
    generation: u64,
    mutation_rate: u64
}

impl<T : FuzzerView
+ serde::ser::Serialize
+ serde::de::Deserialize
+ Genetic<T> + Sync> Network<T> {
    /// Returns a new Network<T>
    pub fn new() -> Network<T> {
        Network {
            workers:Vec::new(),
            generation: 0,
            mutation_rate: 500,
            worker_count: 0
        }
    }

    pub fn with_capacity(size: usize) -> Network<T> {
        Network {
            workers:Vec::with_capacity(size),
            generation: 0,
            mutation_rate: 500,
            worker_count: 0
        }
    }

    pub fn add_worker(&mut self, view: T) {
        let hostname = view.get_hostname();
        for worker in self.workers.iter() {
            for key in worker.keys() {
                if *key == hostname {
                    return // provide result eventually
                }
            }
        }
        let mut map = BTreeMap::new();
        map.insert(hostname,view);
        self.workers.push(map);
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
        let jnet = &net.as_string();
        let mut f = try!(File::create(&path));
        try!(f.write_all(jnet.unwrap().as_bytes()));
        Ok(())
    }

    /// The network scores itself by adding the score of every Fuzzer it monitors.
    // Should be moved to Genetic<T> trait impl
    pub fn score(&self) -> u64 {
        let mut score = 0;
        for worker in self.workers.iter() {

            for view in worker.values() {
                // score += view.score_stats();
            }
        }
        score
    }

    /// Commands remote Fuzzer instances to begin work
    /// Takes a callback, which must return a value of PartialEq + Eq
    /// The lifespan is the total running time of this function

    pub fn fuzz(&self, lifespan: &u32) {
        // unimplemented!();
        return;

        let mut reproduction_intervals = Vec::with_capacity(self.worker_count);
        let pool = threadpool::ScopedPool::new(self.worker_count as u32);//replace with thread::scoped

        //
        // calculate each worker's interval
        //
        for worker in self.workers.iter() {
            for view in worker.values() {
                reproduction_intervals.push(lifespan / view.get_reproduction_rate());
            }
        }

        // Spawn a thread for every worker, threads spend most of their time asleep, only waking
        // to pass their queues
        for interval in reproduction_intervals {
            let mut lifespan = lifespan.clone();

            pool.execute(move || {
                    while lifespan > 0 {
                        for worker in self.workers.iter(){
                            for (_,value) in worker.iter(){
                                for neighbor in value.get_neighbors().iter() {
                                    value.passq(neighbor);
                                }
                            }
                        }
                        lifespan -= interval;
                        thread::sleep_ms(interval);
                    }
                });
        }

        let mut lifespan = lifespan.clone() * self.worker_count as u32;
    }
}
