mod theme_fetcher;
use ssh_config_parser::{load_file, save_file};
use theme_fetcher::get_kde_theme;

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
        .invoke_handler(tauri::generate_handler![
            fetch_theme,
            load_client_config,
            save_client_config
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
