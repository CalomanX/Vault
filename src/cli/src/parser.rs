use std::{
    env::{self, Args},
    path::{Path, PathBuf},
};

use clap::{builder::ValueParser, value_parser, ArgMatches, Command, Subcommand};

use vault::{
    abstractions::{VaultEmptyResult, VaultError},
    store::abstractions::StoreType,
};

use crate::default_values;

/// Parse the command line arguments
pub(crate) fn try_parse_and_run(args: Args) -> VaultEmptyResult {
    let stty = clap::arg!(--"store-type" <STRING>)
        .value_parser(["memory", "disk"])
        .help("The store type to implement")
        .required(true);

    let cmd = clap::Command::new("service")
        .author("CalomanX")
        .subcommand_required(true)
        .subcommands(vec![
            clap::command!("init")
                .about("Initializes a new Vault.")
                .arg(
                    clap::arg!(-p --"password" <STRING>)
                        .value_parser(clap::value_parser!(String))
                        .help("The password for administrative functions.")
                        .required(true),
                )
                .arg(
                    clap::arg!(-t --"store-type" <STRING>)
                        .value_parser(clap::value_parser!(String))
                )   
                .arg(
                    clap::arg!(--"target" <PATH>)
                        .value_parser(clap::value_parser!(String))
                        .help("The target for the new vault.")
                        .required(false),
                ),
            clap::command!(default_values::ADMIN_COMMAND)
                .about("Administrative access.")
                .subcommand_required(true)
                .subcommands(vec![clap::command!(default_values::ADD_PROFILE)
                    .about("Adds a new consumer profile, either service or app.")
                    .arg(
                        clap::arg!(--"security-key" <STRING>)
                            .value_parser(clap::value_parser!(String))
                            .help("The password for the administrative functions.")
                            .required(true),
                    )
                    .arg(
                        clap::arg!(--"name" <STRING>)
                            .value_parser(clap::value_parser!(String))
                            .help("The name for the new profile.")
                            .required(true),
                    )])
                .subcommands(vec![clap::command!(default_values::LIST_PROFILES)
                    .about("List all profiles.")
                    .arg(
                        clap::arg!(--"security-key" <STRING>)
                            .value_parser(clap::value_parser!(String))
                            .help("The password for the administrative functions.")
                            .required(true),
                    )]),
        ]);
    let matches = cmd.get_matches_from(args);

    let (command, args) = match matches.subcommand() {
        Some(sc) => sc,
        None => return Err(VaultError::from("Command is invalid!")),
    };

    match command {
        default_values::INIT_COMMAND => parse_init(args)?,
        default_values::ADMIN_COMMAND => parse_admin(args),
        _ => panic!("Ups! Will have that command in the near future. Just not right now!"),
    };
    Ok(())
}

fn parse_init(cmd: &ArgMatches) -> VaultEmptyResult {
    let password = cmd.get_one::<String>("password").unwrap();

    let store_type = match cmd.get_one::<String>("store-type") {
        Some(st) => StoreType::from(st),
        None => return Err(VaultError::from("Invalid store type!")),
    };

    let target = match cmd.get_one::<String>("target") {
        Some(target) => Some(target.as_str()),
        None => None,
    };

    let (profile_key, auth_key) = vault::init_vault(&password, store_type, target)?;

    println!("Vault created successfully!");
    println!("\tProfile key is       : {:?}", profile_key);
    println!("\tAuthorization key is : {:?}", auth_key);

    Ok(())
}

fn parse_admin(subcommand_matches: &ArgMatches) {
    let cmd = subcommand_matches.subcommand().unwrap();

    match cmd.0 {
        default_values::ADD_PROFILE => parse_admin_add_profile(cmd.1),
        default_values::LIST_PROFILES => parse_admin_list_profiles(cmd.1),
        _ => panic!("Ups! Will have that command in the near future. Just not right now!"),
    };
}

fn parse_admin_list_profiles(args: &ArgMatches) {
    let security_key = args
        .get_one::<String>(default_values::SECURITY_KEY)
        .unwrap();

    todo!()
    //vault::list_profiles(security_key);
}

fn parse_admin_add_profile(args: &ArgMatches) {
    let security_key = args
        .get_one::<String>(default_values::SECURITY_KEY)
        .unwrap();

    let name = args.get_one::<String>(default_values::NAME).unwrap();

    todo!()
    //vault::add_profile(security_key, name);
}
