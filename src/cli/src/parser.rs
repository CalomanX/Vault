use std::path::{Path, PathBuf};

use clap::{ArgMatches, Command, Subcommand, Args};

use vault::abstractions::{Result, EmptyResult};

use crate::default_values;

/// Parse the command line arguments
pub(crate) fn parse_args() {
    let cmd = clap::Command::new("service")
        .author("CalomanX")
        .subcommand_required(true)
        .subcommands(vec![
            clap::command!(default_values::INIT_COMMAND)
                .about("Initializes a new Vault.")
                .arg(
                    clap::arg!(--"security-key" <STRING>)
                        .value_parser(clap::value_parser!(String))
                        .help("The password for the administrative functions.")
                        .required(true),
                )
                .arg(
                    clap::arg!(--"target-path" <PATH>)
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("The target location and name for the new Vault.")
                        .required(false),
                ),
            clap::command!(default_values::ADMIN_COMMAND)
                .about("Administrative access.")
                .subcommand_required(true)
                .subcommands(vec![
                    clap::command!(default_values::ADD_PROFILE)
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
                        )
                ])  
                .subcommands(vec![
                    clap::command!(default_values::LIST_PROFILES)
                        .about("List all profiles.")
                        .arg(
                    clap::arg!(--"security-key" <STRING>)
                        .value_parser(clap::value_parser!(String))
                        .help("The password for the administrative functions.")
                        .required(true),                            
                        ),                        
                ])
        ]);
    let matches = cmd.get_matches();

    let scmd = matches.subcommand().unwrap();

    match scmd.0 {
        default_values::INIT_COMMAND => parse_init(scmd.1),
        default_values::ADMIN_COMMAND => parse_admin(scmd.1),
        _ => panic!("Ups! Will have that command in the near future. Just not right now!"),
    };

}

fn parse_init(cmd: &ArgMatches) {
    let security_key =cmd.get_one::<String>(default_values::SECURITY_KEY).unwrap();

    let mut target_path = match cmd.get_one::<PathBuf>(default_values::TARGET_PATH) {
        Some(v) => v.to_owned(),
        None => std::path::Path::new("./").to_path_buf(),
    };

    if !Path::exists(&target_path) {
        panic!("target-path should be an existing directory.");
    }

    if Path::is_dir(&target_path) {
        target_path = target_path.join(default_values::VAULT_FILE_NAME);
    }

    todo!()
    // vault::init_vault(security_key)
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
