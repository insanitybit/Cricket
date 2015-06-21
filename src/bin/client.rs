extern crate hyper;

use hyper::*;
use std::io::Read;
use std::collections::BTreeMap;

fn main() {

    let netview : BTreeMap<String, String> = BTreeMap::new();

    let mut client = Client::new();

    // let mut res = client.post("http://localhost:3000/start").send().unwrap();
    let res = client.post("http://localhost:3000/sendq")
    .body(r#"http://localhost:3000/qetq"#).send().unwrap();

    let mut res = client.post("http://localhost:3000/recvq")
    .body(r#"{"key":"value"}"#).send().unwrap();

    let mut s = String::new();

    res.read_to_string(&mut s).unwrap();
    println!("{}", s);
}
