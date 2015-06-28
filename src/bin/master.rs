#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]
extern crate serde;

mod fuzzerview;
use fuzzerview::{Network,AFLView,FuzzerView};
use std::sync::{Arc,Mutex};
use std::collections::VecDeque;
use std::fs;

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
    let mut population : VecDeque<Network<AFLView>>
    = VecDeque::with_capacity(population_size as usize);

    fill_population(&mut population, &population_size);

    let mut cur_score = 0;
    let mut tot_score = 0;
    let mut avg_score = 0;
    // let mut high_score = 0;
    // let mut low_score = 0;
    let mut generation = 1;

    for network in population {
        println!("{:?}",network);

        network.fuzz(&100);
        cur_score = network.score();
        println!("Current network score: {}", cur_score );
        tot_score += cur_score;
        avg_score = tot_score / generation;

        generation += 1;
        // population.

        break;
    }
    println!("End");

}
