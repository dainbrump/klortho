mod ssh_config;
mod theme_fetcher;
use ssh_config::{load_file,save_file};
use theme_fetcher::get_kde_theme;

// Tarui command to feature map
// SSH Client features:
// 'T_load_client_config' - Load SSH client configuration from file(s)
// 'T_save_client_config' - Save SSH client configuration to file(s)
// SSH Server features:
// 'T_load_server_config' - Load SSH server configuration from file(s)
// 'T_save_server_config' - Save SSH server configuration to file(s)
// Key Management features:
// 'T_generate' - Generate a new SSH key pair
// 'T_import' - Import an existing SSH key pair
// UI features:
// 'fetch_theme' - Fetch the current DE theme colors

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn fetch_theme() -> Result<String, String> {
    match get_kde_theme() {
        Ok(theme_data) => Ok(theme_data),
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
fn load_client_config(filepath: &str) -> Result<String, String> {
    match load_file(filepath) {
        Ok(ssh_configuration) => Ok(ssh_configuration),
        Err(error) => Err(error.to_string()),
    }
}

#[tauri::command]
fn save_client_config(json: String, filepath: &str) -> Result<String, String> {
    match save_file(json, filepath) {
        Ok(ssh_configuration) => Ok(ssh_configuration),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![fetch_theme, load_client_config, save_client_config])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
