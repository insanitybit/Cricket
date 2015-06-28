#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]
extern crate serde;

mod fuzzerview;
use fuzzerview::{Network,AFLView,FuzzerView};
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

// I can probably optimize this quite a lot by writing this bit myself but for now, vecdequeue
struct History  {
    average_queue: VecDeque<u64>,
    high_queue: VecDeque<u64>,
    low_queue: VecDeque<u64>,
    upper_bound: u64,
    lower_bound: u64,
    max_size: usize
}

impl History  {
    fn new(size: usize) -> History  {
        History  {
            average_queue: VecDeque::with_capacity(size * 2),
            high_queue: VecDeque::with_capacity(size),
            low_queue: VecDeque::with_capacity(size),
            upper_bound: 25,
            lower_bound: 25,
            max_size: size
        }
    }

    fn get_average(&self) -> u64 {
        if self.average_queue.len() == 0 {
            0
        } else {
            let mut total : u64 = 0;
            for item in self.average_queue.iter() {
                total += *item;
            }
            total / self.average_queue.len() as u64
        }
    }

    /// Takes a value and adds it to the end of the queue, popping off the front value if the queue
    /// length is equal to the queue max_size
    fn push(&mut self, value: Option<u64>) {

        let value = match value {
            Some(v) => v,
            None    => self.get_average()
        };

        let average = self.get_average();
        let upper = ((100 * average) + (average * self.upper_bound)) / 100;
        let lower = ((100 * average) - (average * self.lower_bound)) / 100;

        while self.average_queue.len() >= self.max_size {
            self.average_queue.pop_front();
        }
        while self.high_queue.len() >= self.max_size {
            self.high_queue.pop_front();
        }
        while self.low_queue.len() >= self.max_size {
            self.low_queue.pop_front();
        }

        if value > upper {
            self.high_queue.push_back(value);
        } else if value < lower {
            self.low_queue.push_back(value);
        }

        self.average_queue.push_back(value);
    }
}

#[allow(unused_variables, unused_assignments)]
fn main() {
    let population_size : usize = 5;
    let lifespan : u32 = 900000;
    let mut population : VecDeque<Network<AFLView>>
    = VecDeque::with_capacity(population_size);

    fill_population(&mut population, &population_size);

    let mut history = 100;
    let mut net_avg_score = History ::new(population_size * history);
    let mut fuz_avg_score = History ::new(population_size * history);
    let mut fuz_min_score = History ::new(population_size * history);
    let mut fuz_max_score = History ::new(population_size * history);

    let mut generation = 1;

    for network in population.iter() {
        // Launch network, Begin fuzzing
        network.fuzz(&100);
        // Get scores for each worker
        // The average total is stored
        let worker_scores = network.get_worker_scores();
        let average = fuz_avg_score.get_average();

        // If the score of a worker is upper_bound% higher than the average, it is stored in
        // 'hi', if it is lower than lower_bound% relative to the average, it is stored in low
        // Everything else will be stored in average
        let mut hi   =    Vec::with_capacity(worker_scores.len());
        let mut avg  =   Vec::with_capacity(worker_scores.len());
        let mut low  =   Vec::with_capacity(worker_scores.len());


        for worker in worker_scores.iter() {

        }


        // Sort workers into high, medium, low vectors


        for worker in worker_scores.iter() {
            fuz_avg_score.push(*worker);
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
