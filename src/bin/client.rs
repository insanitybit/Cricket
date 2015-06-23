extern crate hyper;
extern crate rustc_serialize;


use rustc_serialize::json::{self, Json, Object, ToJson};
use hyper::*;
use std::io::Read;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs::File;

// static netviewpath: &'static str = "./queue/";

fn get_queue() {// -> VecDeque<BTreeMap<String, String>> {


    // VecDeque::new().push_back(BTreeMap::new())
}

fn main() {

    // let mut queue = VecDeque::new();
    //     // fs::read_dir(&self.opts.sync_dir)
    // let dir = "./queue/".to_owned();
    // let files = std::fs::read_dir(&dir).unwrap();
    //
    // for file in files {
    //     let file = file.unwrap().path().to_str()
    //     .unwrap().to_owned();
    //     let mut file = File::open(&file).unwrap();
    //     file.read_to_string(&mut s);
    //     let s = Json::from_str(&s).unwrap();
    //
    //     if s.is_object(){
    //         // let s = s.as_object();
    //         queue.push_back(s.as_object());
    //     }
    // }

    // for q in queue {
    //     let currentview = q.clone();
    //
    //
    //
    // }
    // let netview : BTreeMap<String, String> = BTreeMap::new();

    let mut client = Client::new();
    println!("Calling stats");
    let mut res = client.get("http://localhost:3000/stats")
    .send().unwrap();
    println!("Received stats");
    let mut s = String::with_capacity(600);
    res.read_to_string(&mut s).unwrap();
    println!("String stats");
    println!("{}",s);

    // let mut res = client.post("http://localhost:3000/start").send().unwrap();
    // let res = client.post("http://localhost:3000/sendq")
    // .body(r#"http://localhost:3000/qetq"#).send().unwrap();

    // let mut res = client.post("http://localhost:3000/recvq")
    // .body(r#"{"key":"value"}"#).send().unwrap();

    // let mut s = String::new();
    //
    // res.read_to_string(&mut s).unwrap();
    // println!("{}", s);
}
