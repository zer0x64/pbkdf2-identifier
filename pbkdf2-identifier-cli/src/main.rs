/// Uses pbkdf2-identifier to identify the parameters used to generate a pbkdf2 hash
use base64;
use clap::{App, Arg};

fn main() {
    let mut primitive_names = vec!["all"];
    for primitive in pbkdf2_identifier::hash_primitive::PRIMITIVES {
        primitive_names.push(primitive.name());
    }

    let matches = App::new("PBKDF2 Identifier")
        .version(env!("CARGO_PKG_VERSION"))
        .author("zer0x64")
        .about(
            "Helps you find the parameters used to generate a PBKDF2 hash to break the \
             security by obscurity.",
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .value_name("password")
                .help("The password that was used to generate the hash.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("hash")
                .short("H")
                .long("hash")
                .value_name("hash")
                .help("The PBKDF2 hash.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("salt")
                .short("s")
                .long("salt")
                .value_name("salt")
                .help("The salt that was used to generate the hash. Can be empty.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("max")
                .short("m")
                .long("max")
                .value_name("max")
                .help("The max number of iteration to check.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("format")
                .short("f")
                .long("format")
                .value_name("format")
                .help("The max number of iteration to check.")
                .possible_values(&["base64", "hex"])
                .takes_value(true)
                .default_value("base64"),
        )
        .arg(
            Arg::with_name("algorithm")
                .short("a")
                .long("algorithm")
                .value_name("algorithm")
                .help("The algorithm to verify")
                .possible_values(&primitive_names)
                .takes_value(true)
                .default_value("all"),
        )
        .get_matches();

    let max = match matches.value_of("max") {
        Some(max) => match max.parse() {
            Ok(max) => Some(max),
            Err(_) => {
                println!("Please enter an integer value for the 'max' parameter");
                return;
            }
        },
        None => None,
    };

    let password = matches.value_of("password").unwrap();
    let hash_enc = matches.value_of("hash").unwrap();
    let salt_enc = matches.value_of("salt").unwrap();
    let algorithm_name = matches.value_of("algorithm").unwrap();

    let format = matches.value_of("format").unwrap();

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
        hash = if let Ok(hash) = base64::decode(hash_enc) {
            hash
        } else {
            println!("Please enter an base64 encoded value for the 'hash' parameter");
            return;
        };

        salt = if let Ok(salt) = base64::decode(salt_enc) {
            salt
        } else {
            println!("Please enter an base64 encoded value for the 'salt' parameter");
            return;
        };
    }

    if algorithm_name == "all" {
        // Brute-force the algorithm
        match pbkdf2_identifier::identify_all(password.as_bytes(), &hash, &salt, max) {
            Some((algorithm, iterations)) => {
                println!(
                    "Found!\nAlgorithm: {}\nIterations: {}",
                    algorithm.name(),
                    iterations
                );
            },
            None => println!("Not found!")
        }
    } else {
        // Finds the corresponding value
        let mut algorithm = None;

        for alg in pbkdf2_identifier::hash_primitive::PRIMITIVES {
            if alg.name() == algorithm_name {
                algorithm = Some(alg);
                break;
            }
        }

        let algorithm = algorithm.expect("clap shouldn't let an invalid value pass here");

        // Get the closure for the primitive and run it.
        match algorithm.get_identifier()(password.as_bytes(), &hash, &salt, max) {
            Some(iterations) => {
                println!(
                    "Found!\nAlgorithm: {}\nIterations: {}",
                    algorithm.name(),
                    iterations
                );
            },
            None => println!("Not found!")
        }
    }
}
