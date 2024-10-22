#![forbid(unsafe_code)]
#![allow(unused)]
//imports
use clap::Parser;
use colored::Colorize;
use pgp::{
    ser::Serialize,
    types::{EskType, PkeskBytes, PublicKeyTrait},
};
use rand::thread_rng;
use std::{env, fs};
//modules
mod cli;
use cli::{Cli, Commands};
mod crypt;
use crypt::{gen_priv_key, read_priv_key};

fn main() {
    //get cli args
    let cli = Cli::parse();
    //match command
    match &cli.command {
        Commands::License => {
            println!(include_str!("res/notice.txt"));
        }
        Commands::Generate { file, public_only } => {
            if *public_only {
                //
            } else {
                let key = gen_priv_key("Test", "test@example.com");
                let mut file_path = env::current_dir().unwrap();
                file_path.push(file);
                println!("Path: {}", file_path.display());
                fs::write(
                    file_path.as_path(),
                    key.to_bytes()
                        .expect("Failed to convert key to bytes")
                        .as_slice(),
                )
                .expect("Failed to Write");
            }
        }
        Commands::Load { file, public_only } => {
            if *public_only {
                //
            } else {
                let mut file_path = env::current_dir().unwrap();
                file_path.push(file);
                println!("Path: {}", file_path.display());
                if file_path.exists() {
                    let data = fs::read(file_path.as_path()).expect("Failed to read file");
                    let key = read_priv_key(data).expect("Failed to read private key");
                    println!("Success!");
                    let encrypted = key
                        .encrypt(thread_rng(), "Test String".as_bytes(), EskType::V3_4)
                        .expect("Failed to Encrypt");
                    match encrypted {
                        PkeskBytes::Rsa { mpi } => {
                            let mut file_path = env::current_dir().unwrap();
                            file_path.push("encryption");
                            fs::write(file_path.as_path(), mpi.as_bytes());
                        }
                        _ => println!("{}", "Unknown encryption method".red()),
                    }
                }
            }
        }
        _ => println!("Unknown Command"),
    }
}
