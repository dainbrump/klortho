//! This module contains parsing logic and structures for configuration files used by
//! <a href="https://linux.die.net/man/8/sshd" target="_blank"><strong>sshd(8)</strong></a>.
//! The goal of this module is to provide a way to parse and save configuration files for the SSH
//! server into and from a JSON format. The JSON format uses a nested tree structure to represent
//! the configuration file to include any parameters and values starting at the root level of the
//! file and incorporating any nested blocks or sections parsed as a result of "Include" statements.
//!
//! The structure and values of the parsed data is "validated" through the use of strongly typed
//! properties, including enumerated values for certain parameters. This is to ensure that the
//! configuration file can be saved back to disk in a format that is compatible with the original
//! file. The JSON format is also used to provide a way to interact with the parsed data in a
//! structured way, allowing for easy manipulation and querying of the configuration data.
//!
//! This module and the corresponding ssh_config_parser module are designed to be used together for
//! the purpose of managing SSH configuration files for both the client and server. The two modules
//! share a similar structure and design, with the main difference being the parameters and values.
//! Development of these modules began as an effort to provide a standard structure for supplying
//! the configuration data to a Tauri front-end application, which can then be used to display and
//! edit the configuration data in a user-friendly way.
pub mod server_record;
