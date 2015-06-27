//! Fuzzer
//!
//! # Usage
//!
//! The Fuzzer Module provides a simple interface to a group of locally fuzzer instances
//!
extern crate num_cpus;
extern crate threadpool;

use std::sync::mpsc::channel;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::default::Default;
use std::process::{Command, Child};

mod fuzzererror;
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
    fn getq(&self) -> BTreeMap<String,String>;
    /// Begins the fuzzing process. Takes a &str, which can be used as arguments to the fuzzer.
    fn launch(&mut self, args: &str);
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
        unimplemented!();
        // let mut profile = Vec::new();
        // for it in 0..self.opts.instance_count {
        //     profile.push(
        //         vec!["-i".to_owned(),self.opts.testcases.to_owned(),"-o".to_owned(),
        //             self.opts.sync_dir.to_owned(), "-S".to_owned(),
        //             "fuzzer_".to_owned() + &it.to_string(),self.opts.target_path.to_owned()]
        //         )
        // }
        // profile
    }
}

impl Fuzzer for AFL {
    /// Spawns instance_count number of afl fuzzers
    fn launch(&mut self, args: &str) {
        if self.opts.running {return}
        let profile = self.get_profile(&args);
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
    fn getq(&self) -> BTreeMap<String,String> {
        let (tx, rx) = channel();
        let pool = threadpool::ScopedPool::new(num_cpus::get() as u32);

        let mut files = BTreeMap::new();
        match fs::read_dir(&self.opts.sync_dir) {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                let p = match path {
                    Ok(p) => p,
                    Err(_)    => continue
                };

                let p = match p.path().to_str() {
                    Some(p)   => p.to_owned() + &"/queue/".to_owned(),
                    None  => continue
                };
                if p.contains(".cur_input") {continue};

                match fs::read_dir(p) {
                       Err(why) => println!("! {:?}", why.kind()),
                       Ok(paths) => for path in paths {
                               let tx = tx.clone();
                               pool.execute(move|| {
                                   let p = match path {
                                       Ok(p) => p,
                                       Err(_)    => return
                                   };

                                   let p = match p.path().to_str() {
                                       Some(p)   => p.to_owned(),
                                       None  => return
                                   };
                                    if p.contains(".state") {return};

                                    let mut f = match File::open(&p) {
                                        Ok(f) => f,
                                        Err(_)    => return
                                    };
                                    let mut s = String::new();
                                    match f.read_to_string(&mut s) {
                                        Ok(_) => (),
                                        Err(_)    => return
                                    };
                                    let name = PathBuf::from(p);

                                    let name = match name.file_name() {
                                        Some(name)    => name,
                                        None      => return
                                    };

                                    let name = match name.to_str() {
                                        Some(name)  => name,
                                        None        => return
                                    };

                                    tx.send((name.to_owned(),s)).unwrap();
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
                                Err(_)    => return
                            };

                            let p = match p.path().to_str() {
                                Some(p)   => p.to_owned() + &"/fuzzer_stats".to_owned(),
                                None  => return
                            };
                            if p.contains(".cur_input") {
                                return
                            }
                            let mut f = match File::open(&p) {
                                Ok(f) => f,
                                Err(_)    => return
                            };

                            let mut stats = String::with_capacity(600);

                            match f.read_to_string(&mut stats) {
                                Ok(_) => tx.send(stats).unwrap(),
                                Err(_)    => return
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
