use std::str::FromStr;

/// Uses pbkdf2-identifier to identify the parameters used to generate a pbkdf2 hash
use base64;
use clap::Parser;

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

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(short, long)]
    password: String,

    #[clap(short, long)]
    hash: String,

    #[clap(short, long)]
    salt: String,

    #[clap(short, long, default_value = "hmacsha1, hmacsha224, hmacsha256, hmacsha384, hmacsha512")]
    algorithms: AlgorithmsArg,

    #[clap(short, long, default_value = "base64")]
    format: String,

    #[clap(short, long)]
    max: Option<usize>,
}

fn main() {
    let mut primitive_names = vec!["all"];
    for primitive in pbkdf2_identifier::hash_primitive::PRIMITIVES {
        primitive_names.push(primitive.name());
    }

    let args = Args::parse();

    let hash_enc = args.hash;
    let salt_enc = args.salt;

    let format = args.format;

    let hash;
    let salt;

    if format == "hex" {
        hash = if let Ok(hash) = hex::decode(hash_enc) {
            hash
        } else {
            println!("Please enter an hex encoded value for the 'hash' parameter");
            return;
        };

        salt = if let Ok(salt) = hex::decode(salt_enc) {
            salt
        } else {
            println!("Please enter an hex encoded value for the 'salt' parameter");
            return;
        };
    } else {
        hash = if let Ok(hash) = base64::decode(&hash_enc) {
            hash
        } else {
            println!("Please enter an base64 encoded value for the 'hash' parameter");
            return;
        };

        salt = if let Ok(salt) = base64::decode(&salt_enc) {
            salt
        } else {
            println!("Please enter an base64 encoded value for the 'salt' parameter");
            return;
        };
    }

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
}
