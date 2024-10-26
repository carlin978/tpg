#![forbid(unsafe_code)]
#![allow(unused)]
//imports
use clap::Parser;
use colored::Colorize;
use pgp::ser::Serialize;
use std::{env, fs};
//modules
mod cli;
use cli::{Cli, Commands};
mod crypt;
use crypt::{encrypt_bytes_to_binary, encrypt_text_to_binary, gen_key, read_priv_key};

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
            let key = gen_key(name, email);
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
            key_file,
            text,
            armor,
            output,
            input,
        } => {
            let mut file_path = cwd.clone();
            file_path.push(key_file);
            println!("Key: {}", file_path.display());
            if file_path.exists() {
                let data = fs::read(file_path.as_path()).expect("Failed to read key file");
                let key = read_priv_key(data).expect("Failed to read key");
                if *armor {
                    todo!("Armor not implemented");
                } else {
                    if let Some(input_path) = input {
                        todo!("Broken");
                        // let mut file_path = cwd.clone();
                        // file_path.push(input_path);
                        // if file_path.exists() {
                        //     let input_content =
                        //         fs::read(file_path).expect("Failed to read input file");
                        //     match encrypt_bytes_to_binary(key.into(), input_content) {
                        //         Ok(encrypted) => {
                        //             let mut file_path = cwd.clone();
                        //             file_path.push(output);
                        //             println!("Output: {}", file_path.display());
                        //             fs::write(file_path.as_path(), encrypted.as_slice())
                        //                 .expect("Failed to Write file");
                        //         }
                        //         Err(err) => println!("{}", err.red()),
                        //     }
                        // }
                    } else if let Some(text) = text {
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
                    } else {
                        println!(
                            "{}",
                            "You must pass either an input file or text to be encrypted".red()
                        );
                    }
                }
            }
        }
        _ => println!("Unknown Command"),
    }
}
