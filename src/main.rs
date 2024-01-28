use clap::{Parser, ValueEnum};

use std::io;
use std::fs::File;

use extendables::attack::LengthExtend;
use extendables::hash::md5::MD5;

#[derive(Parser, Debug)]
#[command(name = "hash-extender")]
#[command(author = "Moorts")]
#[command(about = "Performs Length Extension Attacks on Hash Functions (currently only MD5)")]
struct Args {
    /// MD5 Digest to extend
    #[arg(long)]
    base_digest: String,

    /// Length of Pre-Image of base_digest
    #[arg(long)]
    base_length: u64,

    /// Pre-Image of base_digest
    #[arg(long)]
    base_str: Option<String>,
    
    /// Encoding for parsing base_str and extension
    #[arg(long, value_enum, default_value_t = Encoding::Raw)]
    encoding: Encoding,

    #[arg(long)]
    output_file: Option<String>,

    /// Hex-encoded bytes to extend
    #[arg(long)]
    extension: String
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Encoding {
    /// Hex encoded bytes
    Hex,

    /// UTF-8 encoded string
    Raw
}

impl Encoding {
    fn decode(&self, s: String) -> Vec<u8> {
        match self {
            Self::Hex => {
                hex::decode(s).expect("Invalid hex data")
            },
            Self::Raw => {
                s.as_bytes().to_vec()
            }
        }
    }
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let n = args.base_length;

    let base_bytes = args.base_str.map(|s| {
        args.encoding.decode(s)
    }).unwrap_or(b"\x00".repeat(n as usize));

    let extension_bytes = args.encoding.decode(args.extension);

    let mut writer: Box<dyn io::Write> = match args.output_file {
        Some(path) => Box::new(File::open(path)?),
        None => Box::new(io::stdout().lock())
    };

    write!(writer, "{:?}\n", MD5::extend_bytes(base_bytes, &args.base_digest, extension_bytes))?;

    Ok(())
}
