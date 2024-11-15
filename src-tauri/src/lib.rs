mod ssh_config_parser;
use ssh_config_parser::{parse_ssh_config};

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
fn load_config(filepath: &str) -> Result<String, String> {
    match parse_ssh_config(filepath) {
        Ok(json_string) => Ok(json_string),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![greet, load_config])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
