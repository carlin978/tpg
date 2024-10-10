#![forbid(unsafe_code)]
#![allow(unused)]
//imports
use clap::Parser;
use colored::Colorize;
//modules
mod cli;
use cli::{Cli, Commands};

fn main() {
    //get cli args
    let cli = Cli::parse();
    //match command
    match &cli.command {
        Commands::License => {
            println!(include_str!("res/notice.txt"));
        }
        _ => println!("Unknown Command"),
    }
}
