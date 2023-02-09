use clap::{crate_version, App, AppSettings, Arg, ArgGroup, ArgMatches, SubCommand};
use rand_core::OsRng;
use regex::Regex;
use x25519_dalek::{PublicKey, StaticSecret};

use std::collections::HashSet;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process;
use std::str::FromStr;

use libmorscrypta as morscrypta;
use libmorscrypta::{GenPBKDF2, PemExport, PemImport, ReadFully};

fn main() {
    process::exit(match execute() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    });
}

fn execute() -> morscrypta::Result<()> {
    let matches = arg_matches();
    match matches.subcommand() {
        ("prvsec", Some(m)) => prv_sec(m.value_of("output")),
        ("prvkdf", Some(m)) => prv_kdf(
            m.value_of("output"),
            m.value_of("password").unwrap(),
            m.value_of("iteration_count").unwrap(),
        ),
        ("pubkey", Some(m)) => pub_key(m.value_of("input"), m.value_of("output")),
        ("encrypt", Some(m)) => match (
            m.value_of("input"),
            m.value_of("output"),
            m.value_of("public_key"),
            m.value_of("password"),
            m.value_of("iteration_count"),
        ) {
            (input, output, Some(path), None, None) => encrypt_key(input, output, path),
            (input, output, None, Some(password), Some(iteration_count)) => {
                encrypt_kdf(input, output, password, iteration_count)
            }
            _ => panic!(),
        },
        ("decrypt", Some(m)) => match (
            m.value_of("input"),
            m.value_of("output"),
            m.value_of("private_key"),
            m.value_of("password"),
            m.value_of("iteration_count"),
        ) {
            (input, output, Some(path), None, None) => decrypt_key(input, output, path),
            (input, output, None, Some(password), Some(iteration_count)) => {
                decrypt_kdf(input, output, password, iteration_count)
            }
            _ => panic!(),
        },
        _ => panic!(),
    }
}

fn prv_sec(dst: Option<&str>) -> morscrypta::Result<()> {
    let mut output: Box<dyn Write> = match dst {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };
    let key = StaticSecret::new(OsRng);
    output.write_all(key.pem_export().as_bytes())?;
    Ok(())
}

fn prv_kdf(output: Option<&str>, password: &str, iteration_count: &str) -> morscrypta::Result<()> {
    let password = password.as_bytes();
    let iteration_count = u32::from_str(iteration_count).unwrap();
    let mut output: Box<dyn Write> = match output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };
    let key = StaticSecret::gen_pbkdf2(password, iteration_count);
    output.write_all(key.pem_export().as_bytes())?;
    Ok(())
}

fn pub_key(src: Option<&str>, dst: Option<&str>) -> morscrypta::Result<()> {
    let mut input: Box<dyn Read> = match src {
        Some(path) => Box::new(File::open(path)?),
        None => Box::new(io::stdin()),
    };
    let prv_key = load_prv_key(&mut input)?;
    let pub_key = PublicKey::from(&prv_key);

    let mut output: Box<dyn Write> = match dst {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };
    output.write_all(pub_key.pem_export().as_bytes())?;
    Ok(())
}

fn encrypt_key(
    input: Option<&str>,
    output: Option<&str>,
    key_path: &str,
) -> morscrypta::Result<()> {
    let mut src = File::open(key_path)?;
    let pub_key = load_pub_key(&mut src)?;
    encrypt(input, output, &pub_key)
}

fn encrypt_kdf(
    input: Option<&str>,
    output: Option<&str>,
    password: &str,
    iteration_count: &str,
) -> morscrypta::Result<()> {
    let password = password.as_bytes();
    let iteration_count = u32::from_str(iteration_count).unwrap();
    let prv_key = StaticSecret::gen_pbkdf2(password, iteration_count);
    let pub_key = PublicKey::from(&prv_key);
    encrypt(input, output, &pub_key)
}

fn encrypt(
    input: Option<&str>,
    output: Option<&str>,
    pub_key: &PublicKey,
) -> morscrypta::Result<()> {
    let mut input: Box<dyn Read> = match input {
        Some(path) => Box::new(File::open(path)?),
        None => Box::new(io::stdin()),
    };
    let mut output: Box<dyn Write> = match output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };
    morscrypta::encrypt(&mut input, &mut output, pub_key)
}

fn decrypt_key(
    input: Option<&str>,
    output: Option<&str>,
    key_path: &str,
) -> morscrypta::Result<()> {
    let mut src = File::open(key_path)?;
    let prv_key = load_prv_key(&mut src)?;
    decrypt(input, output, &prv_key)
}

fn decrypt_kdf(
    input: Option<&str>,
    output: Option<&str>,
    password: &str,
    iteration_count: &str,
) -> morscrypta::Result<()> {
    let password = password.as_bytes();
    let iteration_count = u32::from_str(iteration_count).unwrap();
    let prv_key = StaticSecret::gen_pbkdf2(password, iteration_count);
    decrypt(input, output, &prv_key)
}

fn decrypt(
    input: Option<&str>,
    output: Option<&str>,
    prv_key: &StaticSecret,
) -> morscrypta::Result<()> {
    let mut input: Box<dyn Read> = match input {
        Some(path) => Box::new(File::open(path)?),
        None => Box::new(io::stdin()),
    };
    let mut output: Box<dyn Write> = match output {
        Some(path) => Box::new(File::create(path)?),
        None => Box::new(io::stdout()),
    };
    morscrypta::decrypt(&mut input, &mut output, prv_key)
}

fn load_pub_key<R: Read>(src: &mut R) -> morscrypta::Result<PublicKey> {
    let mut buf = [0u8; 1024];
    let n = load_key(src, &mut buf)?;
    PublicKey::pem_import(&buf[..n])
}

fn load_prv_key<R: Read>(src: &mut R) -> morscrypta::Result<StaticSecret> {
    let mut buf = [0u8; 1024];
    let n = load_key(src, &mut buf)?;
    StaticSecret::pem_import(&buf[..n])
}

fn load_key<R: Read>(src: &mut R, buf: &mut [u8]) -> morscrypta::Result<usize> {
    let n = src.read_fully(buf)?;
    if n == buf.len() {
        return Err(morscrypta::Error::KeyImport("key buffer overflow".into()));
    }
    Ok(n)
}

fn arg_matches() -> ArgMatches<'static> {
    App::new("morscrypta")
        .version(crate_version!())
        .author("Vin Singh <github.com/shampoofactory>")
        .about("AES-256 file encryption")
        .after_help("See 'morscrypta help <command>' for more information on a specific command.")
        .subcommand(
            SubCommand::with_name("prvsec")
                .about("Generate a secure random private key.")
                .after_help("With no key FILE write to standard output.")
                .arg(
                    Arg::with_name("output")
                        .help("output file")
                        .takes_value(true)
                        .long("out_key")
                        .value_name("FILE"),
                ),
        )
        .subcommand(
            SubCommand::with_name("prvkdf")
                .about("Generate a password derived private key.")
                .after_help("With no key FILE write to standard output.")
                .arg(
                    Arg::with_name("password")
                        .help("complex password")
                        .required(true)
                        .takes_value(true)
                        .validator(is_complex)
                        .short("p")
                        .long("password")
                        .value_name("PASSWORD"),
                )
                .arg(
                    Arg::with_name("iteration_count")
                        .help("iteration count")
                        .default_value("100000")
                        .takes_value(true)
                        .validator(is_iter)
                        .long("iter")
                        .value_name("NUM"),
                )
                .arg(
                    Arg::with_name("output")
                        .help("output file")
                        .takes_value(true)
                        .long("out_key")
                        .value_name("FILE"),
                ),
        )
        .subcommand(
            SubCommand::with_name("pubkey")
                .about("Generate a private key's corresponding public key.")
                .after_help(
                    "With no input/output key FILE/s read/write from/to standard input/output.",
                )
                .arg(
                    Arg::with_name("input")
                        .help("input private key file")
                        .takes_value(true)
                        .long("in_key")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("output")
                        .help("output private key file")
                        .takes_value(true)
                        .long("out_key")
                        .value_name("FILE"),
                ),
        )
        .subcommand(
            SubCommand::with_name("encrypt")
                .about("Encrypt a file.")
                .after_help("With no input/output FILE/s read/write from/to standard input/output.")
                .arg(
                    Arg::with_name("input")
                        .help("input file")
                        .takes_value(true)
                        .short("i")
                        .long("in")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("output")
                        .help("output file")
                        .takes_value(true)
                        .short("o")
                        .long("out")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("public_key")
                        .conflicts_with("iteration_count")
                        .help("public key file")
                        .takes_value(true)
                        .short("k")
                        .long("key")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("password")
                        .help("complex password")
                        .takes_value(true)
                        .validator(is_complex)
                        .short("p")
                        .long("password")
                        .value_name("PASSWORD"),
                )
                .arg(
                    Arg::with_name("iteration_count")
                        .help("iteration count")
                        .default_value_if("password", None, "100000")
                        .takes_value(true)
                        .validator(is_iter)
                        .long("iter")
                        .value_name("NUM"),
                )
                // Awaiting for tidier output:
                // https://github.com/clap-rs/clap/issues/1605
                // .arg(
                //     Arg::with_name("iteration_count")
                //         .help("iteration count")
                //         .default_value("100000")
                //         .takes_value(true)
                //         .validator(is_iter)
                //         .long("iter")
                //         .value_name("NUM"),
                // )
                .group(
                    ArgGroup::with_name("key_input")
                        .required(true)
                        .args(&["public_key", "password"]),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("Decrypt a file.")
                .after_help("With no input/output FILE/s read/write from/to standard input/output.")
                .arg(
                    Arg::with_name("input")
                        .help("input file")
                        .takes_value(true)
                        .short("i")
                        .long("in")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("output")
                        .help("output file")
                        .takes_value(true)
                        .short("o")
                        .long("out")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("private_key")
                        .conflicts_with("password iteration_count")
                        .help("private key file")
                        .takes_value(true)
                        .short("k")
                        .long("key")
                        .value_name("FILE"),
                )
                .arg(
                    Arg::with_name("password")
                        .help("complex password")
                        .takes_value(true)
                        .short("p")
                        .long("password")
                        .value_name("PASSWORD"),
                )
                .arg(
                    Arg::with_name("iteration_count")
                        .help("password iteration count")
                        .default_value_if("password", None, "100000")
                        .takes_value(true)
                        .validator(is_iter)
                        .long("iter")
                        .value_name("NUM"),
                )
                // Awaiting for tidier output:
                // https://github.com/clap-rs/clap/issues/1605
                // .arg(
                //     Arg::with_name("iteration_count")
                //         .help("iteration count")
                //         .default_value("100000")
                //         .takes_value(true)
                //         .validator(is_iter)
                //         .long("iter")
                //         .value_name("NUM"),
                // )
                .group(
                    ArgGroup::with_name("key_input")
                        .required(true)
                        .args(&["private_key", "password"]),
                ),
        )
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .get_matches()
}

fn is_iter(v: String) -> Result<(), String> {
    match u32::from_str(&v) {
        Ok(v) if v >= 100_000 => Ok(()),
        Ok(_) => Err("iteration count: minimum of 100000".into()),
        Err(e) => Err(format!("{e}")),
    }
}

fn is_complex(v: String) -> Result<(), String> {
    let mut vec = Vec::new();
    if v.len() < 8 {
        vec.push("a minimum of length of 8");
    }
    if !Regex::new(r"[A-Z]+").unwrap().is_match(&v) {
        vec.push("an uppercase character");
    }
    if !Regex::new(r"[a-z]+").unwrap().is_match(&v) {
        vec.push("a lowercase character");
    }
    if !Regex::new(r"[0-9]+").unwrap().is_match(&v) {
        vec.push("a numerical character");
    }
    if char_usage(&v) < 5 {
        vec.push("at least 5 distinct characters");
    }
    if vec.is_empty() {
        Ok(())
    } else {
        Err(format!("password needs: {}", vec.join(", ")))
    }
}

fn char_usage(v: &str) -> usize {
    v.chars().collect::<HashSet<char>>().len()
}
