type AddressFamily = 'any' | 'inet' | 'inet6';

type YesNo = 'yes' | 'no';

type YesNoAsk = 'yes' | 'no' | 'ask';

type YesNoAskAutoAutoask = 'yes' | 'no' | 'ask' | 'auto' | 'autoask';

type LogLevels = 'QUIET' | 'FATAL' | 'ERROR' | 'INFO' | 'VERBOSE' | 'DEBUG' | 'DEBUG1' |
  'DEBUG2' | 'DEBUG3';

type TunnelOptions = 'yes' | 'no' | 'point-to-point' | 'ethernet';

/**
 * Defines a structure for an ssh client Host record as defined in ssh_config(5).
 * 
 * This type definition attemps to replicate the structure of a valid SSH client host record as closely as possible using the same property names as defined by
 * ssh_config(5). The type definition also attempts to provide type safety and value constraints where possible.
 * 
 * For more information:
 * @see https://linux.die.net/man/5/ssh_config
 */
export type HostRecord = {
  host: string;
  address_family?: AddressFamily;
  batch_mode?: YesNo;
  bind_address?: string;
  challenge_response_authentication?: YesNo;
  check_host_ip?: YesNo;
  cipher?: string;
  ciphers?: string;
  clear_all_forwardings?: YesNo;
  compression?: YesNo;
  compression_level?: number;
  connection_attempts?: number;
  connect_timeout?: number;
  control_master?: YesNoAskAutoAutoask;
  control_path?: string;
  dynamic_forward?: string;
  enable_ssh_keysign?: YesNo;
  escape_char?: string;
  exit_on_forward_failure?: YesNo;
  forward_agent?: YesNo;
  forward_x11?: YesNo;
  forward_x11_trusted?: YesNo;
  gateway_ports?: YesNo;
  global_known_hosts_file?: string;
  gssapi_authentication?: YesNo;
  gssapi_key_exchange?: YesNo;
  gssapi_client_identity?: string;
  gssapi_delegate_credentials?: YesNo;
  gssapi_renewal_forces_rekey?: YesNo;
  gssapi_trust_dns?: YesNo;
  hash_known_hosts?: YesNo;
  hostbased_authentication?: YesNo;
  host_key_algorithms?: string;
  host_key_alias?: string;
  host_name?: string;
  identities_only?: YesNo;
  identity_file?: string;
  include?: string;
  kbd_interactive_authentication?: YesNo;
  kbd_interactive_devices?: string;
  local_command?: string;
  local_forward?: string;
  log_level?: LogLevels;
  macs?: string;
  no_host_authentication_for_localhost?: YesNo;
  number_of_password_prompts?: number;
  password_authentication?: YesNo;
  permit_local_command?: YesNo;
  port?: number;
  preferred_authentications?: string;
  protocol?: string;
  proxy_command?: string;
  pubkey_authentication?: YesNo;
  rekey_limit?: string;
  remote_forward?: string;
  r_hosts_rsa_authentication?: YesNo;
  rsa_authentication?: YesNo;
  send_env?: string;
  server_alive_count_max?: number;
  server_alive_interval?: number;
  smartcard_device?: string?;
  strict_host_key_checking?: YesNoAsk;
  tcp_keep_alive?: YesNo;
  tunnel?: TunnelOptions;
  tunnel_device?: string;
  use_privileged_port?: YesNo;
  user?: string;
  user_known_hosts_file?: string;
  verify_host_key_dns?: YesNoAsk;
  visual_host_key?: YesNo;
  x_auth_location?: string;
  unknown?: {[key: string]: string};
};