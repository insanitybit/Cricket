#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]
extern crate serde;

mod fuzzerview;
use fuzzerview::{Network,AFLView,FuzzerView,History};
use std::sync::{Arc,Mutex};
use std::collections::VecDeque;
use std::fs;

fn fill_population(population : &mut VecDeque<Network<AFLView>>, population_size : &usize) -> usize {
    let cur = population.len();
        match fs::read_dir("./population/") {
            Err(why) => println!("! {:?}", why.kind()),
            Ok(paths) => for path in paths {
                if population.len() >= *population_size {return population.len() - cur}

                let path = path.unwrap().path().to_str()
                .unwrap().to_owned();

                match Network::<AFLView>::load_network(path) {
                    Ok(network)     => population.push_back(network),
                    Err(_)          => continue
                }
            }
        }
    population.len() - cur
}

#[derive(PartialEq,Eq)]
struct Score {
    average: u64,
    total: u64,
    individuals: Vec<u64>
}


#[allow(unused_variables, unused_assignments)]
fn main() {
    let population_size : usize = 5;
    let lifespan : u32 = 900000;
    let mut population : VecDeque<Network<AFLView>>
    = VecDeque::with_capacity(population_size);

    fill_population(&mut population, &population_size);

    let mut history = 100;
    let mut net_history = History ::new(population_size * history);
    let mut fuz_history = History ::new(population_size * history);
    let mut fuz_min_score = History ::new(population_size * history);
    let mut fuz_max_score = History ::new(population_size * history);

    let mut generation = 1;

    for network in population.iter() {
        // Launch network, Begin fuzzing
        network.fuzz(&100);
        // Get scores for each worker
        // The average total is stored
        let worker_scores = network.get_worker_scores();

        // If the score of a worker is upper_bound% higher than the average, it is stored in
        // 'hi', if it is lower than lower_bound% relative to the average, it is stored in low
        // Everything else will be stored in avg
        let mut hi   =   Vec::with_capacity(worker_scores.len());
        let mut avg  =   Vec::with_capacity(worker_scores.len());
        let mut low  =   Vec::with_capacity(worker_scores.len());

        let average = fuz_history.get_average();
        let upper = ((100 * average) + (average * fuz_history.get_upper())) / 100;
        let lower = ((100 * average) - (average * fuz_history.get_lower())) / 100;

        for worker in worker_scores.iter() {

            let worker = match *worker {
                Some(w) => Some(w),
                None    => Some(average)
            };

            if worker.unwrap() > upper {
                hi.push(worker);
            } else if worker.unwrap() < lower {
                low.push(worker);
            } else {
                avg.push(worker);
            }
            fuz_history.push(worker);
        }

        break;
    }



    for network in population {
        // println!("{:?}",network);
        //
        // network.fuzz(&100);
        // cur_score = network.score();
        // println!("Current network score: {}", cur_score );
        // tot_score += cur_score;
        // avg_score = tot_score / generation;
        //
        // generation += 1;
        // population.

        break;
    }
    println!("End");

}
