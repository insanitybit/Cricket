//! AFL
//!
//! # Usage
//!
//! The AFL Module provides a simple interface to a group of running AFL instances
//!

#![feature(custom_derive, plugin, fs_walk, convert)]
extern crate csv;
extern crate rustc_serialize;
extern crate iron;
extern crate router;
// extern crate serde;
extern crate url;
extern crate num_cpus;
//
// use hyper::uri::RequestUri;
// extern crate serialize;
use std::collections::BTreeMap;

use std::fs;
use std::path::{Path, PathBuf};
use std::default::Default;
use std::slice;
use iron::prelude::*;
use std::io::prelude::*;
use iron::status;
use router::Router;
// use serde::json;
use std::sync::{Arc, Mutex};
use std::process::{Command, Child, Output, Stdio};
use std::thread;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::fs::File;


/// The AFL struct maintains an AFLOpts 'opts' (see AFLOpts), and a vector of
/// afl process children 'instances'
pub struct AFL {
    opts: AFLOpts,
    instances: Vec<Child>
}

/// AFLOpts holds the AFL environment data, such as the path to the sync directory,
/// whether AFL is currently running, and the scheme to use when creating fuzzers.
#[derive(Clone)]
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

impl AFL {
    /// Create a new AFL object, requires a fully instantiated AFLOpts
    pub fn new(opts: AFLOpts) -> AFL {
        AFL {
            instances: Vec::new(),
            opts: opts
        }
    }

    /// Returns a copy of the current AFLOpts struct.
    /// If you wish to change the current options, instead
    /// create a new AFL object and provide the constructor
    /// with get_opts()
    /// ```
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
    pub fn get_stats(&self) -> String {
        let output = Command::new(&self.opts.whatsup)
                     .args(&vec![&self.opts.sync_dir])
                     .stdout(Stdio::piped())
                     .output()
                     .unwrap_or_else(|e| { panic!("failed to execute process: {}", e) });
         "".to_owned()
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

    /// Takes in a BTreeMap of String, String representing Filename, Filedata
    /// Writes each file to each queue folder
    pub fn putq(&self, newq: &BTreeMap<String,String>){
        match fs::read_dir(&self.opts.sync_dir) {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                    let p = path.unwrap().path().to_str()
                    .unwrap().to_owned() + &"/queue/".to_owned();
                    if p.contains(".cur_input") {continue};

                    // When selecting files, a genetic trait may determine how many are thrown
                    // away, to determine this species' impact on the environment
                    // For example a '.skip(n)' iterator could reduce the impact by 'n'
                    for (key,value) in newq.iter(){
                        let mut f = File::create("".to_owned() + &p + &key).unwrap();
                        f.write_all(&value.as_bytes());
                    }
                },
            }
    }

    /// Returns a BTreeMap of every file in every queue
    /// Keys are the file names, Values are the file contents
    pub fn getq(&self) -> BTreeMap<String,String> {
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
                            let p = path.unwrap().path().to_str().unwrap().to_owned();
                            if p.contains(".state") {continue};

                            let mut f = File::open(&p).unwrap();
                            let mut s = String::new();
                            f.read_to_string(&mut s);
                            files.insert(PathBuf::from(p).file_name().unwrap().to_str()
                            .unwrap().to_owned(),
                            s);
                       },
                   }
                },
            }

        files
    }

    /// Spawns instance_count number of instances of afl-fuzz
    /// Returns immutable reference to self.
    pub fn launch(&mut self, msg: &str) -> &AFL {
        if self.opts.running {return self}
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
        self
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
