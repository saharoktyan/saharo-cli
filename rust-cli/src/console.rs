use owo_colors::OwoColorize;

pub fn info(msg: &str) {
    println!("{} {}", "•".cyan().bold(), msg);
}

pub fn ok(msg: &str) {
    println!("{} {}", "OK".green().bold(), msg);
}

pub fn warn(msg: &str) {
    eprintln!("{} {}", "WARN".yellow().bold(), msg);
}

pub fn err(msg: &str) {
    eprintln!("{} {}", "ERR".red().bold(), msg);
}
