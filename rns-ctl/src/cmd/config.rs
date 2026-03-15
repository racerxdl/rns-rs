//! Inspect and update runtime configuration on a running daemon.

use std::path::Path;
use std::process;

use crate::args::Args;
use rns_net::config;
use rns_net::pickle::PickleValue;
use rns_net::rpc::derive_auth_key;
use rns_net::storage;
use rns_net::{RpcAddr, RpcClient};
use serde_json::{json, Value};

pub fn run(args: Args) {
    if args.has("version") {
        println!("rns-ctl {}", env!("FULL_VERSION"));
        return;
    }

    if args.has("help") || args.positional.is_empty() {
        print_usage();
        return;
    }

    let json_output = args.has("j");
    let action = args.positional.first().map(|s| s.as_str()).unwrap_or_default();

    let mut client = connect(args.config_path());

    match action {
        "list" => {
            let response = rpc_call(
                &mut client,
                PickleValue::Dict(vec![(
                    PickleValue::String("get".into()),
                    PickleValue::String("runtime_config".into()),
                )]),
            );
            let response = if let Some(prefix) = args.get("prefix") {
                filter_list_by_prefix(response, prefix)
            } else {
                response
            };
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&pickle_to_json(&response)).unwrap_or_default()
                );
            } else {
                print_list(&response);
            }
        }
        "get" => {
            let key = match args.positional.get(1) {
                Some(key) => key,
                None => {
                    eprintln!("Missing runtime-config key");
                    process::exit(1);
                }
            };
            let response = rpc_call(
                &mut client,
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("get".into()),
                        PickleValue::String("runtime_config_entry".into()),
                    ),
                    (
                        PickleValue::String("key".into()),
                        PickleValue::String(key.clone()),
                    ),
                ]),
            );
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&pickle_to_json(&response)).unwrap_or_default()
                );
            } else {
                print_entry_or_none(&response, key);
            }
        }
        "set" => {
            let key = match args.positional.get(1) {
                Some(key) => key,
                None => {
                    eprintln!("Missing runtime-config key");
                    process::exit(1);
                }
            };
            let raw_value = match args.positional.get(2) {
                Some(value) => value,
                None => {
                    eprintln!("Missing runtime-config value");
                    process::exit(1);
                }
            };
            let response = rpc_call(
                &mut client,
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("set".into()),
                        PickleValue::String("runtime_config".into()),
                    ),
                    (
                        PickleValue::String("key".into()),
                        PickleValue::String(key.clone()),
                    ),
                    (
                        PickleValue::String("value".into()),
                        parse_scalar_value(raw_value),
                    ),
                ]),
            );
            handle_mutation_response(&response, json_output);
        }
        "reset" => {
            let key = match args.positional.get(1) {
                Some(key) => key,
                None => {
                    eprintln!("Missing runtime-config key");
                    process::exit(1);
                }
            };
            let response = rpc_call(
                &mut client,
                PickleValue::Dict(vec![
                    (
                        PickleValue::String("reset".into()),
                        PickleValue::String("runtime_config".into()),
                    ),
                    (
                        PickleValue::String("key".into()),
                        PickleValue::String(key.clone()),
                    ),
                ]),
            );
            handle_mutation_response(&response, json_output);
        }
        _ => {
            eprintln!("Unknown config subcommand: {}", action);
            print_usage();
            process::exit(1);
        }
    }
}

fn connect(config_path: Option<&str>) -> RpcClient {
    let config_dir = storage::resolve_config_dir(config_path.map(Path::new));
    let config_file = config_dir.join("config");
    let rns_config = if config_file.exists() {
        match config::parse_file(&config_file) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading config: {}", e);
                process::exit(1);
            }
        }
    } else {
        match config::parse("") {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
    };

    let paths = match storage::ensure_storage_dirs(&config_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let identity = match storage::load_or_create_identity(&paths.identities) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error loading identity: {}", e);
            process::exit(1);
        }
    };

    let auth_key = derive_auth_key(&identity.get_private_key().unwrap_or([0u8; 64]));
    let rpc_addr = RpcAddr::Tcp("127.0.0.1".into(), rns_config.reticulum.instance_control_port);
    match RpcClient::connect(&rpc_addr, &auth_key) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Could not connect to rnsd: {}", e);
            eprintln!("Is rnsd running?");
            process::exit(1);
        }
    }
}

fn rpc_call(client: &mut RpcClient, request: PickleValue) -> PickleValue {
    match client.call(&request) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("RPC error: {}", e);
            process::exit(1);
        }
    }
}

fn parse_scalar_value(raw: &str) -> PickleValue {
    match raw {
        "true" => PickleValue::Bool(true),
        "false" => PickleValue::Bool(false),
        _ => {
            if let Ok(v) = raw.parse::<i64>() {
                PickleValue::Int(v)
            } else if let Ok(v) = raw.parse::<f64>() {
                PickleValue::Float(v)
            } else {
                PickleValue::String(raw.to_string())
            }
        }
    }
}

fn print_list(response: &PickleValue) {
    let Some(entries) = response.as_list() else {
        eprintln!("Unexpected response");
        process::exit(1);
    };
    for entry in entries {
        print_entry(entry);
    }
}

fn print_entry_or_none(response: &PickleValue, key: &str) {
    if matches!(response, PickleValue::None) {
        println!("No runtime config entry for {}", key);
        return;
    }
    print_entry(response);
}

fn filter_list_by_prefix(response: PickleValue, prefix: &str) -> PickleValue {
    match response {
        PickleValue::List(entries) => PickleValue::List(
            entries
                .into_iter()
                .filter(|entry| {
                    entry
                        .get("key")
                        .and_then(|v| v.as_str())
                        .map(|key| key.starts_with(prefix))
                        .unwrap_or(false)
                })
                .collect(),
        ),
        other => other,
    }
}

fn handle_mutation_response(response: &PickleValue, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&pickle_to_json(response)).unwrap_or_default()
        );
    } else if response.get("error").is_some() {
        let message = response
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown runtime-config error");
        eprintln!("{}", message);
        process::exit(1);
    } else {
        print_entry(response);
    }
}

fn print_entry(entry: &PickleValue) {
    let key = entry.get("key").and_then(|v| v.as_str()).unwrap_or("<unknown>");
    let value = format_pickle_scalar(entry.get("value").unwrap_or(&PickleValue::None));
    let default = format_pickle_scalar(entry.get("default").unwrap_or(&PickleValue::None));
    let source = entry
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let apply_mode = entry
        .get("apply_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    println!(
        "{} = {}  [default: {}, source: {}, apply: {}]",
        key, value, default, source, apply_mode
    );
    if let Some(description) = entry.get("description").and_then(|v| v.as_str()) {
        println!("  {}", description);
    }
}

fn format_pickle_scalar(value: &PickleValue) -> String {
    match value {
        PickleValue::None => "null".into(),
        PickleValue::Bool(v) => v.to_string(),
        PickleValue::Int(v) => v.to_string(),
        PickleValue::Float(v) => v.to_string(),
        PickleValue::String(v) => v.clone(),
        _ => "<complex>".into(),
    }
}

fn pickle_to_json(value: &PickleValue) -> Value {
    match value {
        PickleValue::None => Value::Null,
        PickleValue::Bool(v) => json!(v),
        PickleValue::Int(v) => json!(v),
        PickleValue::Float(v) => json!(v),
        PickleValue::String(v) => json!(v),
        PickleValue::Bytes(v) => json!(v),
        PickleValue::List(values) => Value::Array(values.iter().map(pickle_to_json).collect()),
        PickleValue::Dict(pairs) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    PickleValue::String(s) => s.clone(),
                    _ => format!("{:?}", k),
                };
                obj.insert(key, pickle_to_json(v));
            }
            Value::Object(obj)
        }
    }
}

fn print_usage() {
    println!("Usage: rns-ctl config <COMMAND> [OPTIONS]");
    println!();
    println!("Commands:");
    println!("    list [--prefix PREFIX]      List supported runtime config keys");
    println!("    get <key>                   Get one runtime config entry");
    println!("    set <key> <value>           Set one runtime config value");
    println!("    reset <key>                 Reset one runtime config value");
    println!();
    println!("Options:");
    println!("    -c, --config PATH           Config directory");
    println!("    -j                          JSON output");
}
