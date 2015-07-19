#![feature(custom_derive, plugin,lookup_host)]
#![plugin(serde_macros)]

extern crate iron;
extern crate router;
extern crate serde;
extern crate hyper;
extern crate cricket;

use std::net;
use hyper::Client;
use self::hyper::client::IntoUrl;
use iron::status;
use iron::prelude::*;
use router::Router;
use serde::json::{self, Value};
use std::io::Read;
use std::collections::BTreeMap;
use std::default::Default;
use std::sync::{Arc, Mutex};
use cricket::*;
// use cricket::{Network,AFL,Fuzzer,History};

fn sendq(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
    println!("SENDQ");
    let mut client = Client::new();
    let mut payload = String::with_capacity(64); // Around how long my AFLArgs are
    request.body.read_to_string(&mut payload)
    .unwrap_or_else(|e| panic!("{}",e));

    let queue = afl.getq();

    for value in queue.iter() {
        let url =  payload.clone() + &"/recvq";
        let url = url.into_url().unwrap();
        client.post(url).body(value).send().unwrap();
    }

    Ok(Response::with(status::Ok))
}

fn recvq(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
    println!("RECVQ");
    let mut payload = String::with_capacity(1024); // Reasonably sized file
    request.body.read_to_string(&mut payload)
    .unwrap_or_else(|e| panic!("{}",e));

    let payload : Value = json::from_str(&payload).unwrap();
    let payload = payload.as_object().unwrap();

    let payload : BTreeMap<String,String>
    = payload.into_iter().map(|(k, v)| ((k.to_owned(), v.as_string().unwrap().to_owned()))).collect();

    afl.putq(&payload);
    Ok(Response::with(status::Ok))
}

/// Should send back json encoded array of stats files
fn stats(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
    println!("STATS");
    let stats = afl.get_stats();
    println!("{:#?}",stats);
    Ok(Response::with(json::to_string(&stats).unwrap()))
}
//
// Receive a message by POST and play it back.
fn start(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
    println!("START");
    let mut payload = String::with_capacity(64);
    request.body.read_to_string(&mut payload)
    .unwrap_or_else(|e| panic!("{}",e));

    let opts = afl.get_opts();
    let mut new_afl = AFL::new(opts);
    new_afl.launch(&payload);

    *afl = new_afl;
    Ok(Response::with(status::Ok))
}

/// Ends the fuzzing process
fn stop(request: &mut Request, afl: &mut AFL) -> IronResult<Response> {
    println!("STOP");
    afl.stop();
    Ok(Response::with("Stopped"))
}

fn main() {
    let afl = Arc::new(Mutex::new(
        AFL::new(
            AFLOpts {
            ..Default::default()
            })
        ));

    let afl_start = afl.clone();
    let afl_stats = afl.clone();
    let afl_passq = afl.clone();
    let afl_recvq = afl.clone();
    let afl_stop = afl.clone();

    let mut router = Router::new();

    router.post("/start", move |r: &mut Request| start(r, &mut afl_start.lock().unwrap()));
    router.get("/stats", move |r: &mut Request| stats(r, &mut afl_stats.lock().unwrap()));
    router.post("/sendq", move |r: &mut Request| sendq(r, &mut afl_passq.lock().unwrap()));
    router.post("/recvq", move |r: &mut Request| recvq(r, &mut afl_recvq.lock().unwrap()));
    router.get("/stop", move |r: &mut Request| recvq(r, &mut afl_stop.lock().unwrap()));

    println!("Server up");
    Iron::new(router).http("172.31.15.165:80").unwrap();

}
