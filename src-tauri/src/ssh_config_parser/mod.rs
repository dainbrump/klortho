pub mod ssh_host_config;

use std::fs;
//use std::io::Write;
use std::collections::HashMap;
use serde_json::{json, Value};
use ssh_host_config::SSHHostConfig;

fn process_config_file(file_path: &str, groups: &mut HashMap<String, Vec<Value>>, current_group: &mut String) -> Result<(), Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(file_path)?;
    let mut current_obj = SSHHostConfig::new();

    for line in contents.lines() {
        let line = line.trim();

        if line.starts_with("#@") && line.ends_with("@#") {
            let new_group = line.trim_start_matches("#@").trim_end_matches("@#").trim().to_string();
            if new_group != *current_group {
                if !current_obj.host.is_empty() {
                  groups.entry(current_group.clone())
                    .or_insert_with(Vec::new)
                    .push(json!(current_obj));
                }
                *current_group = new_group;
                current_obj = SSHHostConfig::new();
            }
        } else if line.starts_with('#') || line.is_empty() {
            continue;
        } else if line.starts_with("Include") {
            let include_path = line.split_whitespace().nth(1).unwrap_or("");
            let expanded_path = shellexpand::tilde(include_path);
            let path = expanded_path.to_string().parse::<std::path::PathBuf>();
            if path.is_ok() {
                let path = path.unwrap();
                if path.is_file() {
                    process_config_file(path.to_str().unwrap(), groups, current_group)?;
                }
            }
        } else if line.starts_with("Host ") {
            if !current_obj.host.is_empty() {
                groups.entry(current_group.clone())
                    .or_insert_with(Vec::new)
                    .push(json!(current_obj));
            }
            current_obj = SSHHostConfig::new();
            current_obj.set_property("Host", line.trim_start_matches("Host ").trim().to_string());
        } else if !current_obj.host.is_empty() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                current_obj.set_property(parts[0], parts[1..].join(" "));
            }
        }
    }

    if !current_obj.host.is_empty() {
        groups.entry(current_group.clone())
            .or_insert_with(Vec::new)
            .push(json!(current_obj));
    }

    Ok(())
}

pub fn parse_ssh_config(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut groups: HashMap<String, Vec<Value>> = HashMap::new();
    let mut current_group: String = "Default".to_string();

    process_config_file(&shellexpand::tilde(file_path), &mut groups, &mut current_group)?;

    let json_string = serde_json::to_string_pretty(&groups)?;
    Ok(json_string)
}

// TODO: Implement generating an ssh configuration file from a JSON object. Perhaps a public function in the impl?
/* pub fn generate_ssh_config(json_data: &HashMap<String, Vec<SSHHostConfig>>, output_file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut output_file = fs::File::create(output_file_path)?;
    for (group, hosts) in json_data.iter() {
        writeln!(output_file, "#@ {} @#", group)?;
        for host_config in hosts {
            writeln!(output_file, "Host {}", host_config.host)?;
            if let Some(hostname) = &host_config.hostname {
                writeln!(output_file, "  Hostname {}", hostname)?;
            }
            if let Some(identity_file) = &host_config.identity_file {
                writeln!(output_file, "  IdentityFile {}", identity_file)?;
            }
            if let Some(proxy_command) = &host_config.proxy_command {
                writeln!(output_file, "  ProxyCommand {}", proxy_command)?;
            }
            if let Some(user) = &host_config.user {
                writeln!(output_file, "  User {}", user)?;
            }
            // Add other fields as needed
        }
    }
    Ok(())
} */
