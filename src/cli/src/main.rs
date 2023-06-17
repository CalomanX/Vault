use std::env;

mod default_values;
mod parser;
mod helpers;



fn main() {
    let args = env::args();
    parser::try_parse_and_run(args);
}
