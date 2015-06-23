#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate iron;
extern crate router;
extern crate serde;

use iron::prelude::*;
use iron::status;
use router::Router;
use serde::json;
use std::io::Read;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize)]
struct Greeting {
    msg: String
}

fn main() {
    let greeting = Arc::new(Mutex::new(Greeting { msg: "Hello, World".to_string() }));
    println!("{}",*greeting.lock().unwrap());

    let greeting_clone = greeting.clone();
    let mut router = Router::new();

    router.post("/set", move |r: &mut Request| set_greeting(r, &mut greeting_clone.lock().unwrap()));


    // Receive a message by POST and play it back.
    fn set_greeting(request: &mut Request, greeting: &mut Greeting) -> IronResult<Response> {
        let mut payload = String::new();
        request.body.read_to_string(&mut payload).unwrap();
        println!("{}", payload);
        *greeting = json::from_str(&payload).unwrap();
        Ok(Response::with(status::Ok))
    }
    println!("{}",*greeting.lock().unwrap());

    Iron::new(router).http("localhost:3000").unwrap();
}
