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
use crypt::{
    decrypt_from_binary, encrypt_to_binary, gen_key, read_armored_priv_key, read_priv_key,
};

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
                println!(include_str!("../res/notice.txt"));
            }
        }
        Commands::Generate {
            name,
            email,
            armor,
            output,
        } => {
            let key = gen_key(name, email).expect("Failed to generate key");
            let mut file_path = cwd.clone();
            file_path.push(output);
            println!("Path: {}", file_path.display());
            if *armor {
                fs::write(
                    file_path.as_path(),
                    key.to_armored_bytes(Default::default())
                        .expect("Failed to convert key to armored bytes")
                        .as_slice(),
                )
                .expect("Failed to Write");
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
                let key = if *armor {
                    read_armored_priv_key(data).expect("Failed to read key")
                } else {
                    read_priv_key(data).expect("Failed to read key")
                };
                if let Some(input_path) = input {
                    let mut file_path = cwd.clone();
                    file_path.push(input_path);
                    if file_path.exists() {
                        let input_content = fs::read(file_path).expect("Failed to read input file");
                        match encrypt_to_binary(key.into(), input_content) {
                            Ok(encrypted) => {
                                let mut file_path = cwd.clone();
                                file_path.push(output);
                                println!("Output: {}", file_path.display());
                                fs::write(file_path.as_path(), encrypted.as_slice())
                                    .expect("Failed to Write file");
                            }
                            Err(err) => println!("{}", err.to_string().red()),
                        }
                    }
                } else if let Some(text) = text {
                    match encrypt_to_binary(key.into(), text.as_bytes().into()) {
                        Ok(encrypted) => {
                            let mut file_path = cwd.clone();
                            file_path.push(output);
                            println!("Output: {}", file_path.display());
                            fs::write(file_path.as_path(), encrypted.as_slice())
                                .expect("Failed to Write file");
                        }
                        Err(err) => println!("{}", err.to_string().red()),
                    }
                } else {
                    println!(
                        "{}",
                        "You must pass either an input file or text to be encrypted".red()
                    );
                }
            }
        }
        Commands::Decrypt {
            key_file,
            armor,
            output,
            input,
        } => {
            let mut file_path = cwd.clone();
            file_path.push(key_file);
            println!("Key: {}", file_path.display());
            if file_path.exists() {
                let data = fs::read(file_path.as_path()).expect("Failed to read key file");
                let key = if *armor {
                    read_armored_priv_key(data)
                } else {
                    read_priv_key(data)
                }
                .expect("Failed to read key");

                let mut file_path = cwd.clone();
                file_path.push(input);
                let input_contents = fs::read(file_path).expect("Failed to read input file");
                match decrypt_from_binary(key, input_contents) {
                    Ok(decrypted) => {
                        let mut file_path = cwd.clone();
                        file_path.push(output);
                        println!("Output: {}", file_path.display());
                        fs::write(file_path.as_path(), decrypted.as_slice())
                            .expect("Failed to Write file");
                    }
                    Err(err) => println!("{}", err.to_string().red()),
                }
            }
        }
        _ => println!("Unknown Command"),
    }
}
