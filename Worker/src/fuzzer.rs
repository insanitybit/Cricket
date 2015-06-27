//! AFL
//!
//! # Usage
//!
//! The AFL Module provides a simple interface to a group of running AFL instances
//!
#![allow(unused_features)]
#![allow(unused_variables)]
#![feature(custom_derive, plugin, fs_walk, convert)]
extern crate csv;
// extern crate rustc_serialize;
extern crate iron;
extern crate router;
extern crate serde;
extern crate url;
extern crate num_cpus;
extern crate threadpool;
extern crate hyper;
use std::sync::mpsc::channel;

// extern crate serialize;
use std::collections::BTreeMap;

use hyper::Client;
use std::fs;
use std::path::{Path, PathBuf};
use std::default::Default;
use std::slice;
use iron::prelude::*;
use std::io::prelude::*;
use iron::status;
use router::Router;
use serde::json::{self, Value};
use std::sync::{Arc, Mutex};
use std::process::{Command, Child, Output, Stdio};
use std::thread;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::fs::File;


// trait Fuzzer<T: Fuzzer> {
//     pub fn get_stats(&self) -> Stat;
//
//     pub fn putq(&self, newq: &BTreeMap<String,String>;
//
//     pub fn getq(&self) -> BTreeMap<String,String>;
//
//     pub fn launch(&mut self, msg: &str) -> &T;
// }

pub trait Fuzzer {
    fn get_stats(&self) -> Vec<String>;
    fn putq(&self, newq: &BTreeMap<String,String>);
    fn getq(&self) -> BTreeMap<String,String>;
    fn launch(&mut self, msg: &str);
}

// pub trait Harness<T : Fuzzer + Send + Sync> {
//     fn listen(&self, String);
//     fn sendq(&self, &mut Request, &mut T) -> IronResult<Response>;
//     fn recvq(&self, &mut Request, &mut T) -> IronResult<Response>;
//     fn stats(&self, &mut Request, &mut T) -> IronResult<Response>;
//     fn start(&self, &mut Request, &mut T) -> IronResult<Response>;
// }

/// The AFL struct maintains an AFLOpts 'opts' (see AFLOpts), and a vector of
/// afl process children 'instances'
pub struct AFL {
    opts: AFLOpts,
    instances: Vec<Child>,
    pub test: String
}

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
    pub testcases: String,
    pub scheme: String,
    pub instance_count: usize
}

// #[derive(Serialize, Deserialize)]
// struct Stat {
//     msg: Vec<String>
// }
impl AFL {
    /// Create a new AFL object, requires a fully instantiated AFLOpts
    pub fn new(opts: AFLOpts) -> AFL {
        AFL {
            instances: Vec::new(),
            opts: opts,
            test: "Constructor".to_owned()
        }
    }

    /// Returns a copy of the current AFLOpts struct.
    /// If you wish to change the current options, instead
    /// create a new AFL object and provide the constructor
    /// with get_opts()
    /// ```rust
    /// // Example of increasing afl instance_count after launch
    /// let mut opts = afl.get_opts();
    /// opts.instance_count += 2;
    /// let mut new_afl = afl::AFL::new(opts);
    /// *afl = new_afl;
    /// ```
    pub fn get_opts(&self) -> AFLOpts {
        self.opts.clone()
    }

    /// Unimplemented
    // pub fn get_config(&mut self, argcsv: &str) -> *mut AFL {
    //     let mut msg = Vec::with_capacity(argcsv.len());
    //     for arg in argcsv.split(",") {
    //         println!("{}", arg);
    //         msg.push(arg);
    //     }
    //     self
    // }

    /// "$ ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]"
    /// Based on a 'msg', generates arguments for AFL
    /// Should be moved out of afl.rs to the server
    /// Currently only provides a single profile, eventually
    /// there will be an 'add_profile
    pub fn get_profile(&self, msg: &str) -> Vec<Vec< String>>{
        let mut profile = Vec::new();
        for it in 0..self.opts.instance_count {
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

    /// Spawns instance_count number of instances of afl-fuzz
    /// Returns immutable reference to self.
    fn launch(&mut self, msg: &str) {
        if self.opts.running {return}
        let profile = self.get_profile(&msg);
        self.opts.running = true;
        for it in 0..self.opts.instance_count {
            self.instances.push(
                Command::new(self.opts.afl_path.clone())
                         .args(&profile[it])
                        //  .stdout(Stdio::piped())
                         .spawn()
                         .unwrap_or_else(|e| { panic!("failed to execute process: {}", e) })
                );
        }
        self.opts.running = true;
    }

    /// Takes in a BTreeMap of String, String representing Filename, Filedata
    /// Writes each file to each queue folder
    fn putq(&self, newq: &BTreeMap<String,String>){
        // let (tx, rx) = channel();
        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);

        match fs::read_dir(&self.opts.sync_dir) {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                    // let tx = tx.clone();
                    pool.execute(move|| {

                        let p = path.unwrap().path().to_str()
                        .unwrap().to_owned() + &"/queue/".to_owned();
                        if p.contains(".cur_input") {return};

                        // When selecting files, a genetic trait may determine how many are thrown
                        // away, to determine this species' impact on the environment
                        // For example a '.skip(n)' iterator could reduce the impact by 'n'
                        for (key,value) in newq.iter(){
                            let mut f = File::create("".to_owned() + &p + &key).unwrap();
                            f.write_all(&value.as_bytes());
                        }
                    });
                },
            }
    }

    /// Returns a BTreeMap of every file in every queue
    /// Keys are the file names, Values are the file contents
    fn getq(&self) -> BTreeMap<String,String> {
        let (tx, rx) = channel();
        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);

        let mut files = BTreeMap::new();
        match fs::read_dir(&self.opts.sync_dir) {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                let p = path.unwrap().path().to_str()
                .unwrap().to_owned() + &"/queue/".to_owned();
                if p.contains(".cur_input") {continue};

                match fs::read_dir(p) {
                       Err(why) => println!("! {:?}", why.kind()),
                       Ok(paths) => for path in paths {
                               let tx = tx.clone();
                               pool.execute(move|| {
                                    let p = path.unwrap().path().to_str().unwrap().to_owned();
                                    if p.contains(".state") {return};

                                    let mut f = File::open(&p).unwrap();
                                    let mut s = String::new();
                                    f.read_to_string(&mut s);

                                    tx.send((PathBuf::from(p).file_name().unwrap().to_str()
                                            .unwrap().to_owned(),s)).unwrap();
                                });
                       },
                   }
                },
            }
        for (a,b) in rx.iter(){
            files.insert(a,b);
        }
        files
    }

    /// Unimplemented
    fn get_stats(&self) -> Vec<String> {
        let (tx, rx) = channel();

        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);
            match fs::read_dir(&self.opts.sync_dir) {
                Err(why) => println!("! {:?}", why.kind()),
                Ok(paths) => for path in paths {
                        let tx = tx.clone();
                        pool.execute(move|| {
                            let p = path.unwrap().path().to_str()
                            .unwrap().to_owned() + &"/fuzzer_stats".to_owned();
                            if p.contains(".cur_input") {
                                return
                            }
                            let mut f = File::open(&p).unwrap();

                            let mut stats = String::with_capacity(600);
                            f.read_to_string(&mut stats)
                                        .unwrap_or_else(|e| panic!("fuzzer_stats open{}",e));
                            tx.send(stats).unwrap();
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



// pub struct AFLHarness <T : Fuzzer + Send + Sync>{
//     server:
    // router: Iron::Router,
    // fuzzer: T,

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
