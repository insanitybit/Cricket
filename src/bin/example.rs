#![feature(custom_derive, plugin, fs_walk, convert)]
#![plugin(serde_macros)]
extern crate serde;
mod fuzzerview;
use serde::json::{self, Value};
use fuzzerview::{Network,AFLView,FuzzerView};

// This is an example of using the Network structure of AFLView's to control AFL Fuzzing instances
// from across the network.
// In this example, the fuzzers are arranged in a circular linked list, with the queues being
// waterfalled periodifically (40x per network lifetime, based on reproduction_rate) over the
// the course of each Network's lifetime.
// The network's lifetime in this case is one day, as indicated by the 'lifetime' variable.
// This program will run 5 lifetimes of this network, so it should take 5 days.

fn main() {

    // Because Network's and FuzzerView's are Serializable they can be loaded from disk or sent
    // across a network. However, for the purposes of demonstration, we're going to just construct
    // it manually.

    let mut network : Network<AFLView> = Network::new();

    // This is a json representation of the network being built
    // {
    //    "generation":0,
    //    "mutation_rate":500,
    //    "worker_count":0,
    //    "workers":{
    //       "http://localhost:3000":{
    //          "args":[
    //             "default"
    //          ],
    //          "generation":0,
    //          "genes":"",
    //          "hostname":"http://localhost:3000",
    //          "mutation_rate":0.0,
    //          "neighbors":[
    //             "http://localhost:3001"
    //          ],
    //          "reproduction_rate":40
    //       },
    //       "http://localhost:3001":{
    //          "args":[
    //             "default"
    //          ],
    //          "generation":0,
    //          "genes":"",
    //          "hostname":"http://localhost:3001",
    //          "mutation_rate":0.0,
    //          "neighbors":[
    //             "http://localhost:3002"
    //          ],
    //          "reproduction_rate":40
    //       },
    //       "http://localhost:3002":{
    //          "args":[
    //             "default"
    //          ],
    //          "generation":0,
    //          "genes":"",
    //          "hostname":"http://localhost:3002",
    //          "mutation_rate":0.0,
    //          "neighbors":[
    //             "http://localhost:3000"
    //          ],
    //          "reproduction_rate":40
    //       }
    //    }
    // }

    let hostnames = vec![("http://localhost:3000".to_owned(),"http://localhost:3001".to_owned()),
                        ("http://localhost:3001".to_owned(),"http://localhost:3002".to_owned()),
                        ("http://localhost:3002".to_owned(),"http://localhost:3000".to_owned())];

    for (host,neighbor) in hostnames {
        network.add_worker(
            AFLView {
                hostname: host,
                neighbors: vec![neighbor],
                generation: 0,
                mutation_rate: 0.0,
                args: vec!["default".to_owned()],
                reproduction_rate: 40,
                genes: "".to_owned()
            });
    }

    println!("{:?}",serde::json::value::to_value(&network));

    let mut generation = 0;
    let max_generations = 5;
    let lifetime = 86400000; // lifetime determines how long a generation lasts in ms
    while generation < max_generations {
        network.fuzz(&lifetime);
    }

}
