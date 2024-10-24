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
        Commands::License { full } => {
            if *full {
                println!(include_str!("../LICENSE"));
            } else {
                println!(include_str!("res/notice.txt"));
            }
        }
        Commands::Generate {
            name,
            email,
            armor,
            output,
        } => {
            let key = gen_priv_key(name, email);
            let mut file_path = cwd.clone();
            file_path.push(output);
            println!("Path: {}", file_path.display());
            if *armor {
                todo!("Armor not implemented");
            } else {
                fs::write(
                    file_path.as_path(),
                    key.to_bytes()
                        .expect("Failed to convert key to bytes")
                        .as_slice(),
                )
                .expect("Failed to Write");
            }
        }
        Commands::Encrypt {
            file,
            text,
            armor,
            output,
        } => {
            let mut file_path = cwd.clone();
            file_path.push(file);
            println!("Key: {}", file_path.display());
            if file_path.exists() {
                let data = fs::read(file_path.as_path()).expect("Failed to read file");
                let key = read_priv_key(data).expect("Failed to read private key");
                if *armor {
                    todo!("Armor not implemented");
                } else {
                    match encrypt_text_to_binary(key.into(), text.clone()) {
                        Ok(encrypted) => {
                            let mut file_path = cwd.clone();
                            file_path.push(output);
                            println!("Output: {}", file_path.display());
                            fs::write(file_path.as_path(), encrypted.as_slice())
                                .expect("Failed to Write file");
                        }
                        Err(err) => println!("{}", err.red()),
                    }
                }
            }
        }
        _ => println!("Unknown Command"),
    }
}
