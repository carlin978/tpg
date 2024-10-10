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
}
