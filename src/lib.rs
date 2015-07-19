#![feature(custom_derive, plugin,lookup_host,scoped)]
#![plugin(serde_macros)]
// extern crate serde;

/// FuzzerView
///
/// # Usage
///
/// The FuzzerView Module provides a simple interface to a group of remove fuzzer instances
///
extern crate serde;
extern crate hyper;
extern crate threadpool;
extern crate num_cpus;

use std::fs;
use std::{io,error};
use std::convert::From;
use std::fmt;
use self::hyper::Client;
use self::hyper::client::IntoUrl;
use std::str::FromStr;
use self::serde::json;
use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::io::prelude::*;
use std::error::Error;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;
use std::path::PathBuf;
use std::default::Default;
use std::process::{Command, Child, Stdio};

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



/// Trait for types that represent a [Fuzzer](https://en.wikipedia.org/wiki/Fuzz_testing) across
/// a network.
///
/// FuzzerView
pub trait FuzzerView:Send + Sync {
    fn get_stats(&self) -> Result<Vec<String>,FuzzerError>;
    fn passq(&self, &str) -> Result<String, FuzzerError>;
    fn get_pass_rate(&self) -> u32;
    fn start(&self, &str) -> Result<String, FuzzerError>;
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
        let mut client = Client::new();
        let mut s = String::with_capacity(512);

        let url =  self.hostname.clone() + &"/stats";
        let url = url.into_url().unwrap();

        let mut res = try!(client.get(url).send());
        try!(res.read_to_string(&mut s));
        let s : Vec<String> = try!(json::from_str(&s));
        Ok(s)
    }

    /// Commands the AFL Fuzzer to pass its queue to another host
    fn passq(&self, host: &str) -> Result<String, FuzzerError> {
        let mut client = Client::new();
        let mut s = String::new();

        let url =  self.hostname.clone() + &"/passq";
        let url = url.into_url().unwrap();
        let mut res = try!(client.post(url).body(host).send());
        res.read_to_string(&mut s).unwrap();
        Ok(s)
    }

    fn get_pass_rate(&self) -> u32 {
        self.pass_rate.clone()
    }

    /// Commands the AFL Fuzzer to begin the fuzzing process
    fn start(&self, msg: &str) -> Result<String, FuzzerError> {
        let mut client = Client::new();
        let mut s = String::new();

        let url =  self.hostname.clone() + &"/start";
        let url = url.into_url().unwrap();
        let mut res = try!(client.post(url).body(msg).send());
        res.read_to_string(&mut s).unwrap();
        Ok(s)
    }

    /// Commands the AFL Fuzzer to end the fuzzing process
    fn stop(&self) -> Result<(), FuzzerError> {
        let mut client = Client::new();
        // let mut s = String::new();

        let url =  self.hostname.clone() + &"/stop";
        let url = url.into_url().unwrap();
        try!(client.get(url).send());
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
#[allow(dead_code)]
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
        if self.average_queue.is_empty() {
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
/// let structure = vec![("workera".into(),vec!["workerb".into()]),("workerb".into(),vec!["workera".into()])];
///
/// let mut network = Network::new();
///
/// for (host,targets) in structure {
///     network.add_worker(
///         Box::new(
///             AFLView {
///                 hostname: host,
///                 neighbors: targets,
///                 generation: 0,
///                 pass_rate: 10,
///                 args: vec!["default".into()]
///             })
///         )
/// }
/// ```
/// A Network represents a network of FuzzerViews using a graph-like structure.
// #[derive(Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Network {
    workers:BTreeMap<String,Box<FuzzerView>>,
    worker_count: usize,
    generation: u64,
    mutation_rate: u64,
    living: Arc<Mutex<bool>>
}
#[allow(dead_code)]
impl Network {
    /// Returns a new Network<T>
    pub fn new() -> Network {
        Network {
            workers:BTreeMap::new(),
            generation: 0,
            mutation_rate: 500,
            worker_count: 0,
            living: Arc::new(Mutex::new(false))
        }
    }
    /// Commands all workers in the network to end the fuzzing process
    pub fn stop(&self) {
        for view in self.workers.values() {
            view.stop().ok().expect("Fuzzer stop command failed");
        }
        let living = self.living.clone();
        let mut living = living.lock().unwrap();
        *living = false
    }

    /// Parents are selected for breeding based on their stats
    /// Children are created by Genetic Fuzzer, returned to us
    /// We select parents to die and children to replace them
    // fn selection(&self, parents: &BTreeMap<Box<FuzzerView>, u64>) {
    //     unimplemented!();
    //     //
    //     // for (parent,_) in parents.into_iter() {
    //     //     // alpha = parent;
    //     //     parent
    //     // };
    //     //
    //     // let mut cur_score = &0;
    //     //
    //     // for (parent, score) in parents.into_iter() {
    //     //     if score > cur_score {
    //     //         alpha = parent;
    //     //         cur_score = score;
    //     //     }
    //     // }
    //     //
    //     // for (key,_) in parents.into_iter() {
    //     //     key.reproduce_with(alpha);
    //     // }
    // }


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
    // pub fn save_network(&self, path: &str) -> Result<(()),FuzzerError> {
    //     unimplemented!();
    //     // let net = json::to_value(self);
    //     // let jnet = &net.as_string();
    //     // let mut f = try!(File::create(&path));
    //     // try!(f.write_all(jnet.unwrap().as_bytes()));
    //     Ok(())
    // }

    /// The network scores itself by adding the score of every Fuzzer it monitors.
    // Should be moved to Genetic<T> trait impl
    // pub fn score(&self) -> u64 {
    //     let mut score = 0;
    //     for view in self.workers.values() {
    //         score += view.score_stats();
    //     }
    //     score
    // }

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

    pub fn collect_scores_interval(&self, lifetime: &u32, interval: &u32, history: &mut History){
        let interval = *lifetime / interval;
        let mut lifetime = *lifetime;
        while lifetime > 0 {
            let scores = self.get_worker_scores();
            let mut score = 0;

            for s in scores {
                if let Some(s) = s {
                    score += s;
                };
            }

            history.push(Some(score));

            println!("Score:{}", score);
            println!("Average Score:{}", history.get_average());
            lifetime -= interval;
            println!("collect_scores_interval sleeping for: {}", interval);
            thread::sleep_ms(interval);
        }

    }

    /// Commands remote Fuzzer instances to begin work
    /// Takes a callback, which must return a value of PartialEq + Eq
    /// The lifespan is the total running time of this function
    /// reimplement callback later, I actually like that idea
    pub fn fuzz(&self) {
        for view in self.workers.values() {
            view.start(&"default".to_owned()).ok().expect("failed to fuzz");
        }
    }

    pub fn pass(&self, lifespan : &u32) {
        let mut pass_intervals = Vec::with_capacity(self.worker_count);
        // let pool = threadpool::ScopedPool::new(self.worker_count as u32);//replace with thread::scoped

        // calculate each worker's interval
        for view in self.workers.values() {
            let rate = match view.get_pass_rate() {
                0   => *lifespan,
                _   => view.get_pass_rate()
            };

            pass_intervals.push(lifespan / rate);
        }



        // Spawn a thread for every worker, threads spend most of their time asleep, only waking
        // to pass their queues
        for interval in pass_intervals {
            let mut lifespan = lifespan.clone();
            let living = self.living.clone();
            thread::scoped(move || {
                let living = living.lock().unwrap();
                while *living {
                    for (_,value) in self.workers.iter(){
                        for neighbor in value.get_neighbors().iter() {
                            value.passq(neighbor).ok().expect("failed to passq");
                        }
                    }
                    println!("pass sleeping for: {}", interval);
                    thread::sleep_ms(interval);
                }
            });
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

/// Trait for types that represent a [Fuzzer](https://en.wikipedia.org/wiki/Fuzz_testing)
///
/// Fuzzers must be able to send and recieve their synthesized content, provide information on
/// its progress, and be initialized on command.
pub trait Fuzzer {
    /// Returns a Vector of Strings representing the work the fuzzer has done.
    fn get_stats(&self) -> Vec<String>;
    /// Stores newq to disk, newq should represent a map of file names to file content.
    fn putq(&self, newq: &BTreeMap<String,String>);
    /// Returns all of the files in the queue as a BTreeMap of file names to file content.
    fn getq(&self) -> Vec<String>;
    /// Begins the fuzzing process. Takes a &str, which can be used as arguments to the fuzzer.
    fn launch(&mut self, args: &str) -> Result<(),FuzzerError>;
    /// Kills all fuzzers
    fn stop(&mut self);
}

/// AFL Options.
///
/// # Examples
/// ```rust
/// let aflopts = AFLOpts {
///     afl_path: "/path/to/afl-fuzz".to_owned(),
///     target_path: "/path/to/target".to_owned(),
///     ..Default::default()
/// }
/// ```
/// AFLOpts holds the AFL environment data, such as the path to the sync directory,
/// whether AFL is currently running, and the scheme to use when creating fuzzers.
#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub struct AFLOpts {
    pub afl_path: String,
    pub running: bool,
    pub target_path: String,
    pub whatsup: String,
    pub sync_dir: String,
    pub testcases: String, // Change to Option to handle pause
    pub scheme: String,
    pub instance_count: usize
}

impl Default for AFLOpts {
    fn default() -> AFLOpts {
        AFLOpts {
            running: false,
            afl_path: "./AFL/afl-fuzz".to_string(),
            target_path: "./AFL/target".to_string(),
            sync_dir: "./AFL/sync/".to_string(),
            testcases: "./AFL/testcases/".to_string(),
            whatsup: "./AFL/afl-whatsup".to_string(),
            scheme: "fuzzer_".to_string(),
            instance_count: num_cpus::get()
        }
    }
}

/// The AFL struct maintains an AFLOpts 'opts' (see AFLOpts), and a vector of
/// afl process children 'instances'
pub struct AFL {
    opts: AFLOpts,
    instances: Vec<Child>
}

impl AFL {
    /// Takes AFLOpts struct, returns AFL struct.
    pub fn new(opts: AFLOpts) -> AFL {
        AFL {
            instances: Vec::with_capacity(opts.instance_count),
            opts: opts
        }
    }

    /// Returns a copy of the current AFLOpts struct.
    ///
    /// # Example
    /// ```rust
    /// // Example of increasing afl instance_count after launch
    /// let mut opts = afl.get_opts();          // Get mutable copy of current opts
    /// opts.instance_count += 2;               // Modify copy accordingly
    /// let mut new_afl = afl::AFL::new(opts);  // Create new AFL instalce with opts
    /// *afl = new_afl;                         //
    /// ```
    pub fn get_opts(&self) -> AFLOpts {
        self.opts.clone()
    }

    /// Unimplemented
    #[allow(unused_variables,dead_code)]
    pub fn get_config(&mut self, argcsv: &str) -> *mut AFL {
        unimplemented!();
    //     let mut args = Vec::with_capacity(argcsv.len());
    //     for arg in argcsv.split(",") {
    //         println!("{}", arg);
    //         args.push(arg);
    //     }
    //     self
    }

    /// "$ ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]"
    /// Based on 'args', generates arguments for AFL
    /// Should be moved out of afl.rs to the server
    /// Currently only provides a single profile, eventually
    /// there will be an 'add_profile
    #[allow(unused_variables,dead_code)]
    pub fn get_profile(&self, args: &str) -> Vec<Vec< String>>{
        // unimplemented!();
        let mut profile = Vec::with_capacity(self.opts.instance_count);

        profile.push(
            vec!["-i".to_owned(),self.opts.testcases.to_owned(),"-o".to_owned(),
                self.opts.sync_dir.to_owned(), "-M".to_owned(),
                "fuzzer_".to_owned() + &"0".to_string(),self.opts.target_path.to_owned()]
            );
        for it in 1..self.opts.instance_count {
            profile.push(
                vec!["-i".to_owned(),self.opts.testcases.to_owned(),"-o".to_owned(),
                    self.opts.sync_dir.to_owned(), "-S".to_owned(),
                    "fuzzer_".to_owned() + &it.to_string(),self.opts.target_path.to_owned()]
                )
        }
        profile
    }
}

impl Fuzzer for AFL {
    /// Spawns instance_count number of afl fuzzers
    fn launch(&mut self, args: &str) -> Result<(),FuzzerError> {
        if self.opts.running {return Err(FuzzerError::AlreadyRunning)}
        let profile = self.get_profile(&args);
        self.opts.running = true;
        for it in 0..self.opts.instance_count {
            self.instances.push(
                try!(Command::new(self.opts.afl_path.clone())
                         .args(&profile[it])
                         .stdout(Stdio::piped())
                         .spawn())
                );
        }
        self.opts.running = true;
        Ok(())
    }

    /// Stops any running AFL processes
    fn stop(&mut self) {
        for worker in self.instances.iter_mut() {
            worker.kill();
        }
    }

    /// Takes in a BTreeMap of String, String representing Filename, Filedata
    /// Writes the file to each queue folder
    fn putq(&self, newq: &BTreeMap<String,String>) {
        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);

        match fs::read_dir(&self.opts.sync_dir) {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                    pool.execute(move|| {
                        let p = match path {
                            Ok(p) => p,
                            Err(_)    => return
                        };

                        let p = match p.path().to_str() {
                            Some(p)   => p.to_owned() + &"/queue/".to_owned(),
                            None  => return
                        };

                        if p.contains(".cur_input") {return};

                        for (key,value) in newq.iter(){
                            let mut f = match File::create("".to_owned() + &p + &key) {
                                Ok(f) => f,
                                Err(_)    => continue
                            };
                            f.write_all(&value.as_bytes()).unwrap();
                        }
                    });
                },
            }
    }

    /// Returns a BTreeMap of every file in every queue
    /// Keys are the file names, Values are the file contents
    fn getq(&self) -> Vec<String> {
        let (tx, rx) = channel();
        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);

        let mut files = Vec::new();
        match fs::read_dir(&self.opts.sync_dir) {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                let p = match path {
                    Ok(p)   => p,
                    Err(_)  => continue
                };

                let p = match p.path().to_str() {
                    Some(p) => p.to_owned() + &"/queue/".to_owned(),
                    None    => continue
                };
                if p.contains(".cur_input") {continue};

                match fs::read_dir(p) {
                       Err(why) => println!("! {:?}", why.kind()),
                       Ok(paths) =>{
                           // Get lower/ upper bound, assign to vector to reserve files vector
                           let size = match paths.size_hint() {
                               (l,None) =>  l,
                               (_,Some(h))  => h
                           };
                           files.reserve(size);
                           for path in paths {
                               let tx = tx.clone();
                               pool.execute(move|| {
                                   let p = match path {
                                       Ok(p)    => p,
                                       Err(_)   => return
                                   };

                                   let p = match p.path().to_str() {
                                       Some(p)  => p.to_owned(),
                                       None     => return
                                   };
                                    if p.contains(".state") {return};

                                    let mut f = match File::open(&p) {
                                        Ok(f)   => f,
                                        Err(_)  => return
                                    };
                                    let mut s = String::with_capacity(1024); //reasonable file size
                                    match f.read_to_string(&mut s) {
                                        Ok(_)   => (),
                                        Err(_)  => return
                                    };

                                    tx.send(s).unwrap();
                                });
                           }
                       }
                    }},
                }
        for r in rx.iter(){
            files.push(r);
        }
        files
    }

    /// Gets stats from every fuzzer instance, storing them into a vector.
    /// If an error occurs, an empty string is inserted into the Vector
    fn get_stats(&self) -> Vec<String> {
        let (tx, rx) = channel();

        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);
            match fs::read_dir(&self.opts.sync_dir) {
                Err(why) => println!("! {:?}", why.kind()),
                Ok(paths) => for path in paths {
                        let tx = tx.clone();
                        pool.execute(move|| {
                            let p = match path {
                                Ok(p) => p,
                                Err(_)    => {tx.send("".to_owned()).unwrap();return}
                            };

                            let p = match p.path().to_str() {
                                Some(p)   => p.to_owned() + &"/fuzzer_stats".to_owned(),
                                None  => {tx.send("".to_owned()).unwrap();return}
                            };
                            if p.contains(".cur_input") {
                                tx.send("".to_owned()).unwrap();
                                return
                            }
                            let mut f = match File::open(&p) {
                                Ok(f) => f,
                                Err(_)    => {tx.send("".to_owned()).unwrap();return}
                            };
                            // stats file for AFL is about 500 characters
                            let mut stats = String::with_capacity(512);

                            match f.read_to_string(&mut stats) {
                                Ok(_) => tx.send(stats).unwrap(),
                                Err(_)    => {tx.send("".to_owned()).unwrap();return}
                            }

                        });
                    },
                }
            drop(tx);
        let mut stats = Vec::with_capacity(self.opts.instance_count);
        for stat in rx.iter(){
            stats.push(stat);
        }
        stats
    }
}

// Unimplemented
// pub trait Harness<T : Fuzzer + Send + Sync> {
//     fn listen(&self, String);
//     fn sendq(&self, &mut Request, &mut T) -> IronResult<Response>;
//     fn recvq(&self, &mut Request, &mut T) -> IronResult<Response>;
//     fn stats(&self, &mut Request, &mut T) -> IronResult<Response>;
//     fn start(&self, &mut Request, &mut T) -> IronResult<Response>;
// }
//
//
// pub struct AFLHarness <T : Fuzzer + Send + Sync> {
//
// }
//
// impl<T : Fuzzer + Send + Sync,
//      U : FnMut> Harness for AFLHarness<T> {
//     fn listen(&self, name:String) {
//         // self.server = Iron::new(self.router).http(name).unwrap();
//     }
//
//     // fn post(&self, path: &str, fnc: U) {
//     //
//     // }
//
//     // takes CSV of hostnames. first host is key, other nodes are values
//     fn sendq(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
//         println!("SENDQ");
//         let mut payload = String::new();
//         request.body.read_to_string(&mut payload)
//         .unwrap_or_else(|e| panic!("{}",e));
//
//         let payload = payload.split(",").collect::<Vec<&str>>();
//
//         let queue = afl.getq();
//
//         let mut client = Client::new();
//
//         for host in payload {
//             for (_,value) in queue.iter() {
//                 client.post(host).body(value).send().unwrap();
//             }
//         }
//
//         Ok(Response::with(status::Ok))
//     }
//     fn recvq(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
//         println!("RECVQ");
//         let mut payload = String::new();
//         request.body.read_to_string(&mut payload)
//         .unwrap_or_else(|e| panic!("{}",e));
//
//         let payload : Value = json::from_str(&payload).unwrap();
//         let payload = payload.as_object().unwrap();
//
//         let payload : BTreeMap<String,String>
//         = payload.into_iter().map(|(k, v)| ((k.to_owned(), v.as_string().unwrap().to_owned()))).collect();
//
//
//         afl.putq(&payload);
//         Ok(Response::with(status::Ok))
//     }
//
//     fn stats(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
//         println!("STATS");
//         let stats = afl.get_stats();
//         Ok(Response::with(json::to_string(&stats).unwrap()))
//     }
//     //
//     // Receive a message by POST and play it back.
//     fn start(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
//         println!("START");
//         let mut payload = String::new();
//         request.body.read_to_string(&mut payload)
//         .unwrap_or_else(|e| panic!("{}",e));
//
//         let mut opts = afl.get_opts();
//         let mut new_afl = AFL::new(opts);
//         new_afl.launch(&payload);
//
//         *afl = new_afl;
//         Ok(Response::with(status::Ok))
//     }
// }
