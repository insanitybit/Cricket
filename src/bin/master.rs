#![feature(custom_derive, plugin, fs_walk, convert, scoped)]
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
use std::thread;
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


    let structure = vec![
                        ("http://workera".into(), vec!["http://workerb".into()]),
                        ("http://workerb".into(), vec!["http://workera".into()])
                    ];

    let network = Arc::new(Mutex::new(Network::new()));
    let history = Arc::new(Mutex::new(History::new(1000)));

    {
        let network_build = network.clone();

        for (host,targets) in structure {
            let mut network_build = network_build.lock().unwrap();
            network_build.add_worker(
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
    }
    // println!("{:#?}", &network);

    let lifetime = 86400000; // lifetime determines how long a generation lasts in ms
                             // currently set to 1 day in ms
    let lifetime = 6000;

    // This test will go for 5 days, stats will be collected once every day
    let mut generation = 0;
    let max_generations = 5;
    while generation < max_generations {
        println!("Fuzzing next generation");

        {
            let network_fuzz = network.clone();
            //
            thread::spawn(move || {
                let network_fuzz = network_fuzz.lock().unwrap();
                network_fuzz.fuzz();
            });
        }
        {
            let network_pass = network.clone();
            //
            thread::spawn(move || {
                let network_pass = network_pass.lock().unwrap();
                network_pass.pass(&lifetime);
            });
        }
        {
            let network_score = network.clone();
            let history_handle = history.clone();

            //
            thread::spawn(move || {
                let network_score = network_score.lock().unwrap();
                let mut history_handle = history_handle.lock().unwrap();
                network_score.collect_scores_interval(&lifetime, &100, &mut history_handle);
            });
        }

        thread::sleep_ms(lifetime);

        // history.save_to_path("./history/afl_waterfall.history".into());
    }
    // network.stop();

    println!("Done");
}
