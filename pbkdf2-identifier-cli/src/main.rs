use std::str::FromStr;

/// Uses pbkdf2-identifier to identify the parameters used to generate a pbkdf2 hash
use base64;
use clap::{ArgEnum, Parser};

#[derive(Debug)]
struct AlgorithmsArg(Vec<pbkdf2_identifier::hash_primitive::HashPrimitive>);

impl FromStr for AlgorithmsArg {
    type Err = std::fmt::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let items: Result<Vec<_>, _> = s
            .split(",")
            .map(|x| pbkdf2_identifier::hash_primitive::HashPrimitive::from_str(x.trim()))
            .collect();

        match items {
            Ok(i) => Ok(AlgorithmsArg(i)),
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug, Clone, ArgEnum)]
enum InputFormat {
    Base64,
    Hex,
}

impl InputFormat {
    fn decode(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(match self {
            Self::Base64 => base64::decode(data)?,
            Self::Hex => hex::decode(data)?,
        })
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long)]
    /// The cleartext password
    password: String,

    #[clap(short, long)]
    /// The hash of the password to identify
    hash: String,

    #[clap(short, long)]
    /// The salt used to hash the password
    salt: String,

    #[clap(
        short,
        long,
        default_value = "hmacsha1, hmacsha224, hmacsha256, hmacsha384, hmacsha512"
    )]
    /// The hashing algorithms to try
    algorithms: AlgorithmsArg,

    #[clap(short, long, arg_enum, default_value = "base64")]
    /// The encoding format used for the hash and the salt
    format: InputFormat,

    #[clap(short, long)]
    /// The max number of iterations to try.
    /// By default there will not be a maximum and the bruteforce will run forever.
    max: Option<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut primitive_names = vec!["all"];
    for primitive in pbkdf2_identifier::hash_primitive::PRIMITIVES {
        primitive_names.push(primitive.name());
    }

    let args = Args::parse();

    let hash_enc = args.hash;
    let salt_enc = args.salt;

    let format = args.format;

    let hash = format.decode(hash_enc.as_bytes())?;
    let salt = format.decode(salt_enc.as_bytes())?;

    match pbkdf2_identifier::identify_algorithms(
        args.password.as_bytes(),
        &hash,
        &salt,
        args.max,
        args.algorithms.0,
    ) {
        Some((algorithm, iterations)) => {
            println!(
                "Found!\nAlgorithm: {}\nIterations: {}",
                algorithm.name(),
                iterations
            );
        }
        None => println!("Not found!"),
    }

    Ok(())
}
