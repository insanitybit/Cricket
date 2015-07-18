#![feature(custom_derive, plugin, fs_walk, convert)]
#![plugin(serde_macros)]
#[macro_use]
extern crate mopa;
extern crate serde;
extern crate hyper;
mod fuzzerview;
use serde::json::{self, Value};
use serde::json::value::to_value;
use serde::json::ser::to_string_pretty;
use std::str::FromStr;
use fuzzerview::{Network,AFLView,FuzzerView,History};
use std::sync::{Arc, Mutex};
use self::hyper::Client;
use self::hyper::client::IntoUrl;
// This is an example of using the Network structure of AFLView's to control AFL Fuzzing instances
// from across the network.
// In this example, the fuzzers are arranged in a circular linked list, with the queues being
// waterfalled periodifically (40x per network lifetime, based on reproduction_rate) over the
// the course of each Network's lifetime.
// The network's lifetime in this case is one day, as indicated by the 'lifetime' variable.
// This program will run 5 lifetimes of this network, so it should take 5 days.

fn main() {
    // let client = Client::new();
    // let res = client.get("http://ec2-52-5-167-142.compute-1.amazonaws.com/stats".to_owned().into_url().unwrap()).send();
    // // println!("{:#?}", res);
    // //
    // let res = client.get("http://ec2-54-86-18-211.compute-1.amazonaws.com/stats".to_owned().into_url().unwrap()).send();
    // // println!("{:#?}", res);
    // //
    // // return;


    let structure = vec![("workera".into(),vec!["workerb".into()]),("workerb".into(),vec!["workera".into()])];

    let mut network = Network::new();

    for (host,targets) in structure {
        network.add_worker(
            Box::new(
                AFLView {
                    hostname: host,
                    neighbors: targets,
                    generation: 0,
                    pass_rate: 10,
                    args: vec!["default".into()]
                })
            )
    }

    // println!("{:#?}", &network);

    let lifetime = 86400000; // lifetime determines how long a generation lasts in ms
                             // currently set to 1 day in ms
    let lifetime = 6000;
    let mut history = History::new(1000);

    // This test will go for 5 days, stats will be collected once every day
    let mut generation = 0;
    let max_generations = 5;
    while generation < max_generations {
        println!("Fuzzing next generation");
        network.fuzz(&lifetime);

        let scores = network.get_worker_scores();
        let mut score = 0;

        for s in scores {
            match s {
                Some(s) => score += s,
                _   => ()
            }
        }

        history.push(Some(score));

        println!("Score:{}", score);
        println!("Average Score:{}", history.get_average());

        generation += 1;
        history.save_to_path("./history/afl_waterfall.history".into());
    }
    network.stop();

    println!("Done");
}
