
#[macro_use] extern crate nickel;

use nickel::{Nickel, HttpRouter};
use std::sync::{Arc, Mutex};

fn main() {
    let mut server = Nickel::new();
    let reservations = Arc::new(Mutex::new(Vec::new()));

    server.post("/reservations/", middleware! { |request, response|
        reservations.lock().unwrap().push(5);
    });
    server.post("/other_reservations/", middleware! { |request, response|
        reservations.lock().unwrap().push(6);
    });
    server.listen("127.0.0.1:3000");
}
