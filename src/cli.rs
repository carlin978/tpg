use std::path::Path;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "tpg is an experimental PGP command line utility")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    ///Show License and Copyright info
    License,
    ///Generate a PGP key
    Generate {
        ///Output file
        file: String,
        ///Don't generate a private key
        #[arg(long)]
        public_only: bool,
    },
    //Load PGP
    Load {
        ///Key file
        file: String,
        ///Load a public key instead
        #[arg(long)]
        public_only: bool,
    },
}
