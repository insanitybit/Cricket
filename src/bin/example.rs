/// This example shows a waterfall structure using a Network of AFLView
/// These AFLViews will send each other queue data 40 times over the course of a day

mod fuzzerview;
use fuzzerview::{Network,AFLView,FuzzerView};

fn main() {

    let mut network : Network<AFLView> = Network::with_capacity(5);

    // Networks can automatically be loaded with load_network, but for demonstration purposes
    // I'm creating each worker from a list of host->neighbor pairs

    let hostnames = vec![("http://localhost:3000".to_owned(),"http://localhost:3001".to_owned()),
                        ("http://localhost:3001".to_owned(),"http://localhost:3002".to_owned()),
                        ("http://localhost:3002".to_owned(),"http://localhost:3003".to_owned()),
                        ("http://localhost:3003".to_owned(),"http://localhost:3004".to_owned()),
                        ("http://localhost:3004".to_owned(),"http://localhost:3000".to_owned())];

    for (host,neighbor) in hostnames.iter() {
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
    let mut generation = 0;
    let max_generations = 5;
    let lifetime = 86400000; // lifetime determines how long a generation lasts in ms
    while generation < max_generations {
        network.fuzz(lifetime);
    }

}
