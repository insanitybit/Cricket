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
use std::path::Path;
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
    fn get_stats(&self) -> Result<Vec<String>,FuzzerError>;
    fn passq(&self, &str) -> Result<(), FuzzerError>;
    fn get_pass_rate(&self) -> u32;
    fn start(&self, &str) -> Result<(), FuzzerError>;
    fn stop(&self) -> Result<(), FuzzerError>;
    fn get_neighbors(&self) -> Vec<String>;
    fn get_hostname(&self)  -> String;
    // fn get_json(&self) -> serde::json::Value;
}

// /// Trait that defines a Genetic<T> type, one that can score itself, and provide a rate of
// /// reproduction
// pub trait Genetic<T : Genetic<T> + FuzzerView> {
//     /// Returns the number of milliseconds representing a rate of reproduction
//     fn get_reproduction_rate(&self) -> u32;
//     ///
//     fn reproduce_with(&self, mate: &T) -> T;
//
//     // mutate(&mut self);
// }


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
    pub pass_rate: u32,
    pub args: Vec<String>,
    // pub mutation_rate: f64,
    // pub reproduction_rate: u32,
    // pub genes: String
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
    fn get_stats(&self) -> Result<Vec<String>, FuzzerError> {
        let client = Client::new();
        let mut s = String::with_capacity(512);

        let url =  self.hostname.clone() + &"/stats";
        let url = url.into_url().unwrap();

        let mut res = try!(client.get(url).send());
        try!(res.read_to_string(&mut s));
        let s : Vec<String> = try!(json::from_str(&s));
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

    fn get_pass_rate(&self) -> u32 {
        self.pass_rate.clone()
    }

    /// Commands the AFL Fuzzer to begin the fuzzing process
    fn start(&self, msg: &str) -> Result<(), FuzzerError> {
        let client = Client::new();
        // let mut s = String::new();

        let url =  self.hostname.clone() + &"/start";
        let url = url.into_url().unwrap();
        let mut res = try!(client.post(url).body(msg).send());
        // res.read_to_string(&mut s).unwrap();
        Ok(())
    }

    /// Commands the AFL Fuzzer to end the fuzzing process
    fn stop(&self) -> Result<(), FuzzerError> {
        let client = Client::new();
        // let mut s = String::new();

        let url =  self.hostname.clone() + &"/stop";
        let url = url.into_url().unwrap();
        let mut res = try!(client.get(url).send());
        // res.read_to_string(&mut s).unwrap();
        Ok(())
    }

    fn get_neighbors(&self) -> Vec<String> {
        self.neighbors.clone()
    }
    fn get_hostname(&self)  -> String {
        return self.hostname.clone();
    }

    // fn get_json(&self) -> serde::json::Value {
    //     json::to_value(self)
    // }
}

// impl<T : Genetic<T> + FuzzerView> Genetic<T> for AFLView {
//     /// Returns the AFLView's reproduction rate
//     fn get_reproduction_rate(&self) -> u32 {
//         self.reproduction_rate
//     }
//     /// Takes in a type T where T represents some Fuzzer. First, we send a json representation
//     /// of our genetic schema to T : a struct filled with None. T will respond with a modified
//     /// version that has a schema with all of the genetic information of T as well as any
//     /// additional genes unique to the FuzzerView.
//     ///
//     /// So, if this FuzzerView has the genes:
//     /// "a,b"
//     /// and our mate, T has:
//     /// 'b,c'
//     ///  T will return 'a,b,c' with a modified genetic value of 'b' and 'c'
//
//     /// This allows for cross-speciation where only one species genes are ever expressed at a time.
//     /// For example, AFLView can hold the genetic data of a non-AFLView type T. It can't express
//     /// these attributes itself, but if another type T reproduces with the AFLView, the type T's
//     /// child *will* be able to express those genes.
//     /// Possibly make the ability to cross with other species optional, or hide behind Bridge
//     fn reproduce_with(&self, mate: &T) -> T {
//         unimplemented!();
//         let host = mate.get_hostname();
//
//     }
//
// }

/// A helper struct to manage a recorded history
// I can probably optimize this quite a lot by writing this bit myself but for now, Vecue
#[derive(Serialize, Deserialize, Debug)]
pub struct History  {
    average_queue: Vec<u64>,
    high_queue: Vec<u64>,
    low_queue: Vec<u64>,
    upper_bound: u64,
    lower_bound: u64,
    max_size: usize
}

impl History  {
    pub fn new(size: usize) -> History  {
        History  {
            average_queue: Vec::with_capacity(size * 2),
            high_queue: Vec::with_capacity(size),
            low_queue: Vec::with_capacity(size),
            upper_bound: 25,
            lower_bound: 25,
            max_size: size
        }
    }

    pub fn get_average(&self) -> u64 {
        if self.average_queue.len() == 0 {
            0
        } else {
            let mut total : u64 = 0;
            for item in self.average_queue.iter() {
                total += *item;
            }
            total / self.average_queue.len() as u64
        }
    }

    /// Takes a value and adds it to the end of the vector.
    /// If the vector fills, this history is cleared.
    pub fn push(&mut self, value: Option<u64>) {
        if self.average_queue.len() >= self.max_size {
            self.average_queue.clear();
        }
        if self.high_queue.len() >= self.max_size {
            self.high_queue.clear();
        }
        if self.low_queue.len() >= self.max_size {
            self.low_queue.clear();
        }

        let value = match value {
            Some(v) => v,
            None    => self.get_average()
        };

        let average = self.get_average();
        let upper = ((100 * average) + (average * self.upper_bound)) / 100;
        let lower = ((100 * average) - (average * self.lower_bound)) / 100;

        if value > upper {
            self.high_queue.push(value);
        } else if value < lower {
            self.low_queue.push(value);
        }

        self.average_queue.push(value);
    }

    pub fn get_upper(&self) -> u64 {
        self.upper_bound.clone()
    }
    pub fn get_lower(&self) -> u64 {
        self.lower_bound.clone()
    }

    pub fn save_to_path(&self, path: String) {
        let path = Path::new(&path);

        let mut file = match File::create(&path) {
            Err(why) => panic!("couldn't create history: {}",Error::description(&why)),
            Ok(file) => file,
        };

        let rep = match serde::json::to_string(&self) {
            Ok(r) => r,
            Err(e)    => panic!("couldn't serialize self {}",e),
        };
        // println!("{:#?}",rep);
        // let rep = match rep.as_string() {
        // };

        match file.write_all(&rep.as_bytes()) {
            Err(why) => {
                panic!("couldn't write history: {}", Error::description(&why))
            },
            Ok(_) => println!("successfully wrote to history"),
        }
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
// #[derive(Serialize, Deserialize)]
pub struct Network {
    workers:BTreeMap<String,Box<FuzzerView>>,
    history: History,
    worker_count: usize,
    generation: u64,
    mutation_rate: u64
}

impl Network {
    /// Returns a new Network<T>
    pub fn new() -> Network {
        Network {
            workers:BTreeMap::new(),
            generation: 0,
            history: History::new(100),
            mutation_rate: 500,
            worker_count: 0
        }
    }

    pub fn stop(&self) {
        for view in self.workers.values() {
            view.stop();
        }
    }

    /// Parents are selected for breeding based on their stats
    /// Children are created by Genetic Fuzzer, returned to us
    /// We select parents to die and children to replace them
    fn selection(&self, parents: &BTreeMap<Box<FuzzerView>, u64>) {
        unimplemented!();
        //
        // for (parent,_) in parents.into_iter() {
        //     // alpha = parent;
        //     parent
        // };
        //
        // let mut cur_score = &0;
        //
        // for (parent, score) in parents.into_iter() {
        //     if score > cur_score {
        //         alpha = parent;
        //         cur_score = score;
        //     }
        // }
        //
        // for (key,_) in parents.into_iter() {
        //     key.reproduce_with(alpha);
        // }
    }


    /// Currently adds up the paths_total, paths_found, max_depth and returns it
    /// See AFL official docs for details
    fn score_stats(&self, stats: Option<Vec<String>>) -> u64 {
        // unimplemented!();
        let titles = vec![
        "paths_total".to_owned(),
        "paths_found".to_owned(),
        "max_depth".to_owned()];

        let mut score : u64 = 0;

        for stat in stats.unwrap().iter() {
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

    pub fn add_worker(&mut self, view: Box<FuzzerView>) {
        let hostname = view.get_hostname();
        for key in self.workers.keys() {
            if *key == hostname {
                return // provide result eventually
            }
        }
        self.workers.insert(hostname, view);
        self.worker_count = self.workers.len();
    }

    // /// Loads a json representation of a Network from 'path'.
    // /// Returns a FuzzerError if the file can not be opened, or if it is not valid json.
    // pub fn load_network(path: String) -> Result<Network,FuzzerError> {
    //     let mut s = String::with_capacity(256);
    //     let mut f = try!(File::open(&path));
    //
    //     try!(f.read_to_string(&mut s));
    //
    //     let net = try!(json::from_str(&s));
    //     // Ok(net)
    //     Err(FuzzerError::AlreadyRunning)
    // }

    /// Writes a serialized json representation of a network to 'path'
    pub fn save_network(&self, path: &str) -> Result<(()),FuzzerError> {
        unimplemented!();
        // let net = json::to_value(self);
        // let jnet = &net.as_string();
        // let mut f = try!(File::create(&path));
        // try!(f.write_all(jnet.unwrap().as_bytes()));
        Ok(())
    }

    /// The network scores itself by adding the score of every Fuzzer it monitors.
    // Should be moved to Genetic<T> trait impl
    pub fn score(&self) -> u64 {
        let mut score = 0;
        for view in self.workers.values() {
            // score += view.score_stats();
        }
        score
    }

    /// Returns a vector of optional worker scores. Scores are None when the worker could not
    /// be reached
    pub fn get_worker_scores(&self) -> Vec<Option<u64>> {
        let mut scores : Vec<_> = Vec::with_capacity(self.worker_count);
        for view in self.workers.values() {
            let score = match view.get_stats() {
                Ok(score) => self.score_stats(Some(score)),
                Err(_)        => self.score_stats(None)
            };
            scores.push(Some(score));
        }
        scores
    }

    /// Commands remote Fuzzer instances to begin work
    /// Takes a callback, which must return a value of PartialEq + Eq
    /// The lifespan is the total running time of this function
    /// reimplement callback later, I actually like that idea
    pub fn fuzz(&self, lifespan: &u32) {

        let mut reproduction_intervals = Vec::with_capacity(self.worker_count);
        let pool = threadpool::ScopedPool::new(self.worker_count as u32);//replace with thread::scoped

        // calculate each worker's interval
        for view in self.workers.values() {
            reproduction_intervals.push(lifespan / view.get_pass_rate());
        }

        for view in self.workers.values() {
            view.start(&"default".to_owned());
        }
        // Spawn a thread for every worker, threads spend most of their time asleep, only waking
        // to pass their queues
        for interval in reproduction_intervals {
            let mut lifespan = lifespan.clone();

            while lifespan > 0 {
                for (_,value) in self.workers.iter(){
                    for neighbor in value.get_neighbors().iter() {
                        value.passq(neighbor);
                    }
                }
                lifespan -= interval;
                thread::sleep_ms(interval);
            }
        }
    }

    // pub fn serialize(&self) -> serde::json::Value {
    //     // pub struct Network {
    //     //     workers:BTreeMap<String,Box<FuzzerView>>,
    //     //     history: History,
    //     //     worker_count: usize,
    //     //     generation: u64,
    //     //     mutation_rate: u64
    //     // }
    //     let mut workers = Vec::with_capacity(self.workers.len());
    //     for worker in self.workers.values() {
    //         workers.push(worker.get_json());
    //     }
    //     serde::json::to_value(&workers)
    // }
}
