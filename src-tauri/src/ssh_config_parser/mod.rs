pub mod host_record;
pub mod ssh_config;
pub mod utils;

use host_record::HostRecord;
use serde_json;
use ssh_config::ClientConfiguration;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use utils::load_tree_from_config_file;

pub fn load_file(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client_config: ClientConfiguration = load_tree_from_config_file(file_path)?;
    let json_string = serde_json::to_string_pretty(&client_config)?;
    Ok(json_string)
}

// TODO: Implement the save_file function
pub fn save_file(
    json: String,
    output_file_path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let json_data: HashMap<String, Vec<HostRecord>> = match serde_json::from_str(&json) {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to parse JSON: {}", e).into()),
    };

    let mut output_file = fs::File::create(output_file_path)?;
    for (group, hosts) in json_data.iter() {
        writeln!(output_file, "#@ {} @#", group)?;
        for host_config in hosts {
            writeln!(output_file, "Host {}", host_config.host)?;
            if let Some(hostname) = &host_config.host_name {
                writeln!(output_file, "\tHostname {}", hostname)?;
            }
            if let Some(identity_file) = &host_config.identity_file {
                writeln!(output_file, "\tIdentityFile {}", identity_file)?;
            }
            if let Some(proxy_command) = &host_config.proxy_command {
                writeln!(output_file, "\tProxyCommand {}", proxy_command)?;
            }
            if let Some(user) = &host_config.user {
                writeln!(output_file, "\tUser {}", user)?;
            }
            // Add other fields as needed
            // Insert a blank line between each host
            writeln!(output_file, "\n")?;
        }
    }
    let json_string = serde_json::to_string_pretty(&json_data)?;
    Ok(json_string)
}
