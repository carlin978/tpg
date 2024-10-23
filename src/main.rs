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
use crypt::{encrypt_text_to_binary, gen_priv_key, read_priv_key};

fn main() {
    let cwd = env::current_dir().unwrap();
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
                let mut file_path = cwd.clone();
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
        Commands::Encrypt { file, text, public } => {
            if *public {
                //
            } else {
                let mut file_path = cwd.clone();
                file_path.push(file);
                println!("Path: {}", file_path.display());
                if file_path.exists() {
                    let data = fs::read(file_path.as_path()).expect("Failed to read file");
                    let key = read_priv_key(data).expect("Failed to read private key");
                    match encrypt_text_to_binary(key.into(), text.clone()) {
                        Ok(encrypted) => {
                            let mut file_path = cwd.clone();
                            file_path.push("encrypted");
                            fs::write(file_path.as_path(), encrypted.as_slice());
                        }
                        Err(err) => println!("{}", err.red()),
                    }
                }
            }
        }
        _ => println!("Unknown Command"),
    }
}
