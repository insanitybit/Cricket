#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]
extern crate serde;

use std::collections::VecDeque;
use std::fs;
mod fuzzerview;
use fuzzerview::{Network,AFLView,FuzzerView};
use std::sync::{Arc,Mutex};

fn fill_population(population : &mut VecDeque<Network<AFLView>>, population_size : &u64) -> u64 {
    let cur = population.len() as u64;
        match fs::read_dir("./population/") {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                if population.len() as u64 >= *population_size {return population.len() as u64 - cur}

                let path = path.unwrap().path().to_str()
                .unwrap().to_owned();

                match Network::<AFLView>::load_network(path) {
                    Ok(network)     => population.push_back(network),
                    Err(_)        => continue
                }
            }
        }
    population.len() as u64 - cur
}

#[derive(PartialEq,Eq)]
struct Score {
    average: u64,
    total: u64,
    individuals: Vec<u64>
}


#[allow(unused_variables, unused_assignments)]
fn main() {
    let population_size : u64= 5;
    let lifespan : u32 = 900000;
    let mut population = VecDeque::with_capacity(population_size as usize);

    fill_population(&mut population, &population_size);

    let mut cur_score = 0;
    let mut tot_score = 0;
    let mut avg_score = 0;
    // let mut high_score = 0;
    // let mut low_score = 0;
    let mut generation = 1;

    loop {
        for network in population.iter() {
            let real_network = population.front().unwrap();

            let score = Arc::new(Mutex::new(Score {
                average: 0,
                total: 0,
                individuals: Vec::new()
            }));

            let score_lck = score.clone();

            real_network.fuzz(&lifespan, move |host:&str, fuzzview: &AFLView| {
                     let score_lck = score_lck.lock().unwrap();

                });

            // After lifespan is 0
            // scoring should be handled internally, or, a callback should be taken to
            // execute every iteration
            cur_score = real_network.score();
            println!("Current network score: {}", cur_score );
            tot_score += cur_score;
            avg_score = tot_score / generation;

            generation += 1;
            // population.
        }
    }

    // loop continuously grabbing stats, analyzing stats
    // Get stats repeatedly in intervals, average them before analyzing to avoid anomalous behavior
    // Based on stats, generate queue of networks
    // After analysis, generate interval, repeat process

}
