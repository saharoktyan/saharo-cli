use owo_colors::OwoColorize;
use serde_json::{Map, Value};

pub fn print_value(value: &Value) {
    print_value_with_indent(value, 0);
}

fn print_object_with_indent(obj: &Map<String, Value>, indent: usize) {
    let mut keys = obj.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    for key in keys {
        if let Some(value) = obj.get(&key) {
            print_kv_line(&key, value, indent);
        }
    }
}

fn print_kv_line(key: &str, value: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => {
            println!(
                "{}{} {}{}",
                pad,
                "•".cyan().bold(),
                key.cyan().bold(),
                ":".bright_black()
            );
            print_object_with_indent(map, indent + 2);
        }
        Value::Array(arr) => {
            if is_simple_array(arr) {
                println!(
                    "{}{} {}{} {}",
                    pad,
                    "•".cyan().bold(),
                    key.cyan().bold(),
                    ":".bright_black(),
                    format_simple_array(arr).bright_cyan()
                );
            } else {
                println!(
                    "{}{} {}{}",
                    pad,
                    "•".cyan().bold(),
                    key.cyan().bold(),
                    ":".bright_black()
                );
                for (i, item) in arr.iter().enumerate() {
                    let idx = format!("[{i}]");
                    match item {
                        Value::Object(map) => {
                            println!(
                                "{}  {} {}{}",
                                pad,
                                "•".cyan().bold(),
                                idx.cyan().bold(),
                                ":".bright_black()
                            );
                            print_object_with_indent(map, indent + 4);
                        }
                        _ => {
                            println!(
                                "{}  {} {}{} {}",
                                pad,
                                "•".cyan().bold(),
                                idx.cyan().bold(),
                                ":".bright_black(),
                                color_value(item)
                            );
                        }
                    }
                }
            }
        }
        _ => {
            println!(
                "{}{} {}{} {}",
                pad,
                "•".cyan().bold(),
                key.cyan().bold(),
                ":".bright_black(),
                color_value(value)
            );
        }
    }
}

fn print_value_with_indent(value: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    match value {
        Value::Object(map) => print_object_with_indent(map, indent),
        Value::Array(arr) => {
            for (i, item) in arr.iter().enumerate() {
                println!(
                    "{}{} {}",
                    pad,
                    "•".cyan().bold(),
                    format!("[{i}]").cyan().bold()
                );
                print_value_with_indent(item, indent + 2);
            }
        }
        _ => println!("{}{}", pad, color_value(value)),
    }
}

fn is_simple_array(arr: &[Value]) -> bool {
    arr.iter().all(|v| {
        matches!(
            v,
            Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null
        )
    })
}

fn format_simple_array(arr: &[Value]) -> String {
    let parts = arr.iter().map(simple_string).collect::<Vec<_>>().join(", ");
    format!("[{parts}]")
}

fn simple_string(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => value.to_string(),
    }
}

fn color_value(value: &Value) -> String {
    match value {
        Value::Null => "None".magenta().to_string(),
        Value::Bool(b) => b.to_string().yellow().to_string(),
        Value::Number(n) => n.to_string().bright_cyan().to_string(),
        Value::String(s) => s.bright_cyan().to_string(),
        _ => value.to_string().bright_cyan().to_string(),
    }
}
