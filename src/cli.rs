use std::path::{Path, PathBuf};

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
    License {
        ///Show full License text
        #[arg(long)]
        full: bool,
    },
    ///Generate a PGP key
    Generate {
        ///Name for key identification
        #[arg(short, long)]
        name: String,
        ///Email for key identification
        #[arg(short, long)]
        email: String,
        ///ASCII Armor the output
        #[arg(short, long)]
        armor: bool,
        ///File to output the generated key to
        #[arg(short, long)]
        output: PathBuf,
    },
    ///Encrypt Text
    Encrypt {
        ///Key file
        file: PathBuf,
        ///Text to be encrypted
        text: String,
        ///ASCII Armor the output
        #[arg(short, long)]
        armor: bool,
        ///File to output encrypted text to
        #[arg(short, long)]
        output: PathBuf,
    },
}
