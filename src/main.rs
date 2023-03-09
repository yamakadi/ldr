#![feature(c_variadic)]

mod functions;
mod parser;

use std::process::exit;
use std::{env, fs};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("[!] Please provide a path to a BOF/COFF file");

        exit(1)
    }

    println!("[+] Running `{}`", args[1]);

    let mut file_content_ipconfig = fs::read(&args[1]).expect("[!] Error opening the file");

    match parser::parse(file_content_ipconfig.as_mut_slice()) {
        Ok(_) => {}
        Err(e) => println!("[!] Error while running: {}", e),
    };
}
