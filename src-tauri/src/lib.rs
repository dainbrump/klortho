mod ssh_config_parser;
mod theme_fetcher;
use ssh_config_parser::{parse_ssh_config};
use theme_fetcher::{get_kde_theme};

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn fetch_theme() -> Result<String, String> {
  match get_kde_theme() {
    Ok(theme_data) => Ok(theme_data),
    Err(error) => Err(error.to_string()),
  }
}

#[tauri::command]
fn load_config(filepath: &str) -> Result<String, String> {
  match parse_ssh_config(filepath) {
    Ok(ssh_configuration) => Ok(ssh_configuration),
    Err(error) => Err(error.to_string()),
  }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_shell::init())
    .invoke_handler(tauri::generate_handler![load_config, fetch_theme])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
