use serde_json;
use std::process::Command;
use std::collections::HashMap;
use palette::{FromColor, Hsl, Srgb};

// Rounds up the mantissa of a floating point number to a specified number of decimal places.
//
// It does this by first splitting the number into its integral and mantissa. The mantissa is then
// multiplied by 10^`max_places` and rounded up to the nearest integer. The mantissa is then divided
// by 10^`max_places` and added to the integral part.
fn round_up_mantissa(number: f32, max_places: usize) -> f32 {
  let integral_part = number.trunc();
  let mut fractional_part = number.fract();
  let mut divisor = 1.0;
  for _ in 0..max_places {
    fractional_part *= 10.0;
    divisor *= 10.0;
    fractional_part = (fractional_part.ceil() / divisor) * divisor;
  }
  integral_part + (fractional_part.ceil() / divisor)
}

// Checks if a command-line executable is present in the system.
fn command_present(command_name: &str) -> bool {
  Command::new("which").arg(command_name).status().map_or(false, |status| status.success())
}

// Reads and returns the value of a key from a group in the current KDE configuration. If the key is
// not found, an error is returned.
fn read_kdeconfig(config_reader: &str, group: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
  let output = Command::new(config_reader).arg("--file").arg("kdeglobals").arg("--group").arg(group).arg("--key").arg(key).output()?;

  if !output.status.success() {
    return Err(format!("Failed to read group {} and key {} from KDE config.", group, key).into());
  }

  let kde_var = String::from_utf8_lossy(&output.stdout);
  Ok(kde_var.trim().to_string())
}

// Reads the current KDE configuration and returns JSON. The JSON contains the values converted for use with Tailwind CSS
// and related ShadCN.
pub fn get_kde_theme() -> Result<String, Box<dyn std::error::Error>> {
  let mut cssvar_to_kdecfg: HashMap<String, String> = HashMap::new();
  cssvar_to_kdecfg.insert("font-sans".to_string(), "General.font".to_string());
  cssvar_to_kdecfg.insert("font-mono".to_string(), "General.fixed".to_string());
  cssvar_to_kdecfg.insert("background".to_string(), "Colors:Window.BackgroundNormal".to_string());
  cssvar_to_kdecfg.insert("foreground".to_string(), "Colors:Window.ForegroundNormal".to_string());
  cssvar_to_kdecfg.insert("card".to_string(), "Colors:Window.BackgroundNormal".to_string());
  cssvar_to_kdecfg.insert("card-foreground".to_string(), "Colors:Window.ForegroundNormal".to_string());
  cssvar_to_kdecfg.insert("popover".to_string(), "Colors:Window.BackgroundNormal".to_string());
  cssvar_to_kdecfg.insert("popover-foreground".to_string(), "Colors:Window.ForegroundNormal".to_string());
  cssvar_to_kdecfg.insert("primary".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("primary-foreground".to_string(), "Colors:Window.ForegroundLink".to_string());
  cssvar_to_kdecfg.insert("secondary".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("secondary-foreground".to_string(), "Colors:Window.DecorationFocus".to_string());
  cssvar_to_kdecfg.insert("muted".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("muted-foreground".to_string(), "Colors:Window.ForegroundInactive".to_string());
  cssvar_to_kdecfg.insert("accent".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("accent-foreground".to_string(), "Colors:Window.ForegroundNeutral".to_string());
  cssvar_to_kdecfg.insert("destructive".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("destructive-foreground".to_string(), "Colors:Window.ForegroundNegative".to_string());
  cssvar_to_kdecfg.insert("border".to_string(), "Colors:Button.DecorationFocus".to_string());
  cssvar_to_kdecfg.insert("input".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("ring".to_string(), "Colors:Button.DecorationFocus".to_string());
  cssvar_to_kdecfg.insert("sidebar-background".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("sidebar-foreground".to_string(), "Colors:Window.ForegroundNormal".to_string());
  cssvar_to_kdecfg.insert("sidebar-primary".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("sidebar-primary-foreground".to_string(), "Colors:Window.ForegroundLink".to_string());
  cssvar_to_kdecfg.insert("sidebar-accent".to_string(), "Colors:Window.BackgroundAlternate".to_string());
  cssvar_to_kdecfg.insert("sidebar-accent-foreground".to_string(), "Colors:Window.DecorationFocus".to_string());
  cssvar_to_kdecfg.insert("sidebar-border".to_string(), "Colors:Button.DecorationFocus".to_string());
  cssvar_to_kdecfg.insert("sidebar-ring".to_string(), "Colors:Button.DecorationFocus".to_string());

  let mut theme_data: HashMap<String, String> = HashMap::new();
  let kreadconfig = if command_present("kreadconfig6") {
    "kreadconfig6"
  } else if command_present("kreadconfig5") {
    "kreadconfig5"
  } else {
    return Err("Neither kreadconfig5 nor kreadconfig6 exists".into());
  };

  for (css_var, kde_key) in &cssvar_to_kdecfg {
    let cfgtree: Vec<&str> = kde_key.split('.').collect();
    if cfgtree.len() == 2 {
      match read_kdeconfig(kreadconfig, cfgtree[0], cfgtree[1]) {
        Ok(setting) => {
          let parameters: Vec<&str> = setting.split(',').collect();
          if parameters.len() == 3 {
            match (parameters[0].parse::<i32>(), parameters[1].parse::<i32>(), parameters[2].parse::<i32>()) {
              (Ok(r), Ok(g), Ok(b)) => {
                let rgb = Srgb::new(r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0);
                let hsl = Hsl::from_color(rgb);
                let rounded: [f32; 3] = [
                  round_up_mantissa(hsl.hue.to_positive_degrees(), 2),
                  round_up_mantissa(hsl.saturation * 100.0, 2),
                  round_up_mantissa(hsl.lightness * 100.0, 2)
                ];
                theme_data.insert(
                  css_var.to_string(),
                  format!("{} {}% {}%", rounded[0], rounded[1], rounded[2])
                );
              }
              _ => { return Err((format!("Error parsing '{}' as RGB values", kde_key)).into()); }
            }
          } else {
            theme_data.insert(css_var.to_string(), parameters[0].to_string());
          }
        },
        Err(e) => { return Err(e); }
      }
    }
  }

  let json_string = serde_json::to_string_pretty(&theme_data)?;
  Ok(json_string)
}
