#![feature(custom_derive, plugin, fs_walk, convert)]
#![plugin(serde_macros)]
extern crate serde;

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::io::prelude::*;
use std::fs;
mod master;
use master::{Network,AFLView};

fn fill_population(population : &mut VecDeque<Network<AFLView>>, population_size : &u64) -> u64 {
    let cur = population.len() as u64;
        match fs::read_dir("./population/") {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {

                if population.len() as u64 >= *population_size {return population.len() as u64 - cur}

                let path = path.unwrap().path().to_str()
                .unwrap().to_owned();
                population.push_back(
                    Network::<AFLView>::load_network(path)
                    );
            }
        }
    population.len() as u64 - cur
}

fn main() {
    let gen_speed_ms : u32 = 900000;
    let mut population_size : u64= 5;

    let mut population : VecDeque<Network<AFLView>> = VecDeque::with_capacity(population_size as usize);

    fill_population(&mut population, &population_size);
    let real_network = population.front().unwrap();
    real_network.launch(&gen_speed_ms);

    let mut cur_score = 0;
    let mut tot_score = 0;
    let mut avg_score = 0;
    let mut high_score = 0;
    let mut low_score = 0;
    let mut generation = 1;

    loop {
        for network in population.iter() {
            std::thread::sleep_ms(gen_speed_ms);
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
