use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SSHHostConfig {
    #[serde(rename = "Host")]
    pub host: String,
    #[serde(rename = "Match")]
    pub match_: Option<String>,
    #[serde(rename = "AddressFamily")]
    pub address_family: Option<String>,
    #[serde(rename = "BatchMode")]
    pub batch_mode: Option<String>,
    #[serde(rename = "BindAddress")]
    pub bind_address: Option<String>,
    #[serde(rename = "BindInterface")]
    pub bind_interface: Option<String>,
    #[serde(rename = "CanonicalDomains")]
    pub canonical_domains: Option<String>,
    #[serde(rename = "CanonicalizeFallbackLocal")]
    pub canonicalize_fallback_local: Option<String>,
    #[serde(rename = "CanonicalizeHostname")]
    pub canonicalize_hostname: Option<String>,
    #[serde(rename = "CanonicalizeMaxDots")]
    pub canonicalize_max_dots: Option<u32>,
    #[serde(rename = "CanonicalizePermittedCNAMEs")]
    pub canonicalize_permitted_cnames: Option<String>,
    #[serde(rename = "CASignatureAlgorithms")]
    pub ca_signature_algorithms: Option<String>,
    #[serde(rename = "CertificateFile")]
    pub certificate_file: Option<String>,
    #[serde(rename = "ChallengeResponseAuthentication")]
    pub challenge_response_authentication: Option<String>,
    #[serde(rename = "CheckHostIP")]
    pub check_host_ip: Option<String>,
    #[serde(rename = "Ciphers")]
    pub ciphers: Option<Vec<String>>,
    #[serde(rename = "ClearAllForwardings")]
    pub clear_all_forwardings: Option<String>,
    #[serde(rename = "Compression")]
    pub compression: Option<String>,
    #[serde(rename = "CompressionLevel")]
    pub compression_level: Option<u32>,
    #[serde(rename = "ConnectionAttempts")]
    pub connection_attempts: Option<u32>,
    #[serde(rename = "ConnectTimeout")]
    pub connect_timeout: Option<u32>,
    #[serde(rename = "ControlMaster")]
    pub control_master: Option<String>,
    #[serde(rename = "ControlPath")]
    pub control_path: Option<String>,
    #[serde(rename = "ControlPersist")]
    pub control_persist: Option<String>,
    #[serde(rename = "DynamicForward")]
    pub dynamic_forward: Option<String>,
    #[serde(rename = "EnableSSHKeysign")]
    pub enable_ssh_keysign: Option<String>,
    #[serde(rename = "EscapeChar")]
    pub escape_char: Option<String>,
    #[serde(rename = "ExitOnForwardFailure")]
    pub exit_on_forward_failure: Option<String>,
    #[serde(rename = "FingerprintHash")]
    pub fingerprint_hash: Option<String>,
    #[serde(rename = "ForwardAgent")]
    pub forward_agent: Option<String>,
    #[serde(rename = "ForwardX11")]
    pub forward_x11: Option<String>,
    #[serde(rename = "ForwardX11Timeout")]
    pub forward_x11_timeout: Option<u32>,
    #[serde(rename = "ForwardX11Trusted")]
    pub forward_x11_trusted: Option<String>,
    #[serde(rename = "GatewayPorts")]
    pub gateway_ports: Option<String>,
    #[serde(rename = "GlobalKnownHostsFile")]
    pub global_known_hosts_file: Option<String>,
    #[serde(rename = "GSSAPIAuthentication")]
    pub gssapi_authentication: Option<String>,
    #[serde(rename = "GSSAPIDelegateCredentials")]
    pub gssapi_delegate_credentials: Option<String>,
    #[serde(rename = "GSSAPIKeyExchange")]
    pub gssapi_key_exchange: Option<String>,
    #[serde(rename = "GSSAPIName")]
    pub gssapi_name: Option<String>,
    #[serde(rename = "GSSAPIServerIdentity")]
    pub gssapi_server_identity: Option<String>,
    #[serde(rename = "GSSAPITrustDNS")]
    pub gssapi_trust_dns: Option<String>,
    #[serde(rename = "HashKnownHosts")]
    pub hash_known_hosts: Option<String>,
    #[serde(rename = "HostbasedAuthentication")]
    pub hostbased_authentication: Option<String>,
    #[serde(rename = "HostbasedKeyTypes")]
    pub hostbased_key_types: Option<String>,
    #[serde(rename = "HostKeyAlgorithms")]
    pub host_key_algorithms: Option<Vec<String>>,
    #[serde(rename = "HostKeyAlias")]
    pub host_key_alias: Option<String>,
    #[serde(rename = "HostName")]
    pub hostname: Option<String>,
    #[serde(rename = "IdentitiesOnly")]
    pub identities_only: Option<String>,
    #[serde(rename = "IdentityAgent")]
    pub identity_agent: Option<String>,
    #[serde(rename = "IdentityFile")]
    pub identity_file: Option<String>,
    #[serde(rename = "IgnoreUnknown")]
    pub ignore_unknown: Option<String>,
    #[serde(rename = "Include")]
    pub include: Option<String>,
    #[serde(rename = "IPQoS")]
    pub ip_qos: Option<String>,
    #[serde(rename = "KbdInteractiveAuthentication")]
    pub kbd_interactive_authentication: Option<String>,
    #[serde(rename = "KbdInteractiveDevices")]
    pub kbd_interactive_devices: Option<String>,
    #[serde(rename = "KexAlgorithms")]
    pub kex_algorithms: Option<String>,
    #[serde(rename = "LocalCommand")]
    pub local_command: Option<String>,
    #[serde(rename = "LocalForward")]
    pub local_forward: Option<String>,
    #[serde(rename = "LogLevel")]
    pub log_level: Option<String>,
    #[serde(rename = "MACs")]
    pub macs: Option<Vec<String>>,
    #[serde(rename = "NoHostAuthenticationForLocalhost")]
    pub no_host_authentication_for_localhost: Option<String>,
    #[serde(rename = "NumberOfPasswordPrompts")]
    pub number_of_password_prompts: Option<u32>,
    #[serde(rename = "PasswordAuthentication")]
    pub password_authentication: Option<String>,
    #[serde(rename = "PermitLocalCommand")]
    pub permit_local_command: Option<String>,
    #[serde(rename = "PermitRemoteOpen")]
    pub permit_remote_open: Option<String>,
    #[serde(rename = "PKCS11Provider")]
    pub pkcs11_provider: Option<String>,
    #[serde(rename = "Port")]
    pub port: Option<u32>,
    #[serde(rename = "PreferredAuthentications")]
    pub preferred_authentications: Option<String>,
    #[serde(rename = "ProxyCommand")]
    pub proxy_command: Option<String>,
    #[serde(rename = "ProxyJump")]
    pub proxy_jump: Option<String>,
    #[serde(rename = "ProxyUseFdpass")]
    pub proxy_use_fdpass: Option<String>,
    #[serde(rename = "PubkeyAcceptedKeyTypes")]
    pub pubkey_accepted_key_types: Option<String>,
    #[serde(rename = "PubkeyAuthentication")]
    pub pubkey_authentication: Option<String>,
    #[serde(rename = "RekeyLimit")]
    pub rekey_limit: Option<String>,
    #[serde(rename = "RemoteCommand")]
    pub remote_command: Option<String>,
    #[serde(rename = "RemoteForward")]
    pub remote_forward: Option<String>,
    #[serde(rename = "RequestTTY")]
    pub request_tty: Option<String>,
    #[serde(rename = "RevokedHostKeys")]
    pub revoked_host_keys: Option<String>,
    #[serde(rename = "SendEnv")]
    pub send_env: Option<String>,
    #[serde(rename = "ServerAliveCountMax")]
    pub server_alive_count_max: Option<u32>,
    #[serde(rename = "ServerAliveInterval")]
    pub server_alive_interval: Option<u32>,
    #[serde(rename = "StreamLocalBindMask")]
    pub stream_local_bind_mask: Option<String>,
    #[serde(rename = "StreamLocalBindUnlink")]
    pub stream_local_bind_unlink: Option<String>,
    #[serde(rename = "StrictHostKeyChecking")]
    pub strict_host_key_checking: Option<String>,
    #[serde(rename = "SyslogFacility")]
    pub syslog_facility: Option<String>,
    #[serde(rename = "TCPKeepAlive")]
    pub tcp_keep_alive: Option<String>,
    #[serde(rename = "Tunnel")]
    pub tunnel: Option<String>,
    #[serde(rename = "TunnelDevice")]
    pub tunnel_device: Option<String>,
    #[serde(rename = "UpdateHostKeys")]
    pub update_host_keys: Option<String>,
    #[serde(rename = "UseKeychain")]
    pub use_keychain: Option<String>,
    #[serde(rename = "User")]
    pub user: Option<String>,
    #[serde(rename = "UserKnownHostsFile")]
    pub user_known_hosts_file: Option<String>,
    #[serde(rename = "VerifyHostKeyDNS")]
    pub verify_host_key_dns: Option<String>,
    #[serde(rename = "VisualHostKey")]
    pub visual_host_key: Option<String>,
    #[serde(rename = "XAuthLocation")]
    pub x_auth_location: Option<String>,
}

impl SSHHostConfig {
    pub fn new() -> Self {
        Self {
            host: "".to_string(),
            match_: None,
            address_family: None,
            batch_mode: None,
            bind_address: None,
            bind_interface: None,
            canonical_domains: None,
            canonicalize_fallback_local: None,
            canonicalize_hostname: None,
            canonicalize_max_dots: None,
            canonicalize_permitted_cnames: None,
            ca_signature_algorithms: None,
            certificate_file: None,
            challenge_response_authentication: None,
            check_host_ip: None,
            ciphers: None,
            clear_all_forwardings: None,
            compression: None,
            compression_level: None,
            connection_attempts: None,
            connect_timeout: None,
            control_master: None,
            control_path: None,
            control_persist: None,
            dynamic_forward: None,
            enable_ssh_keysign: None,
            escape_char: None,
            exit_on_forward_failure: None,
            fingerprint_hash: None,
            forward_agent: None,
            forward_x11: None,
            forward_x11_timeout: None,
            forward_x11_trusted: None,
            gateway_ports: None,
            global_known_hosts_file: None,
            gssapi_authentication: None,
            gssapi_delegate_credentials: None,
            gssapi_key_exchange: None,
            gssapi_name: None,
            gssapi_server_identity: None,
            gssapi_trust_dns: None,
            hash_known_hosts: None,
            hostbased_authentication: None,
            hostbased_key_types: None,
            host_key_algorithms: None,
            host_key_alias: None,
            hostname: None,
            identities_only: None,
            identity_agent: None,
            identity_file: None,
            ignore_unknown: None,
            include: None,
            ip_qos: None,
            kbd_interactive_authentication: None,
            kbd_interactive_devices: None,
            kex_algorithms: None,
            local_command: None,
            local_forward: None,
            log_level: None,
            macs: None,
            no_host_authentication_for_localhost: None,
            number_of_password_prompts: None,
            password_authentication: None,
            permit_local_command: None,
            permit_remote_open: None,
            pkcs11_provider: None,
            port: None,
            preferred_authentications: None,
            proxy_command: None,
            proxy_jump: None,
            proxy_use_fdpass: None,
            pubkey_accepted_key_types: None,
            pubkey_authentication: None,
            rekey_limit: None,
            remote_command: None,
            remote_forward: None,
            request_tty: None,
            revoked_host_keys: None,
            send_env: None,
            server_alive_count_max: None,
            server_alive_interval: None,
            stream_local_bind_mask: None,
            stream_local_bind_unlink: None,
            strict_host_key_checking: None,
            syslog_facility: None,
            tcp_keep_alive: None,
            tunnel: None,
            tunnel_device: None,
            update_host_keys: None,
            use_keychain: None,
            user: None,
            user_known_hosts_file: None,
            verify_host_key_dns: None,
            visual_host_key: None,
            x_auth_location: None
        }
    }

    pub fn set_property(&mut self, key: &str, value: String) {
        match key.to_lowercase().as_str() {
            "host" => self.host = value,
            "hostname" => self.hostname = Some(value),
            "identityfile" => self.identity_file = Some(value),
            "user" => self.user = Some(value),
            "match" => self.match_ = Some(value),
            "addressfamily" => self.address_family = Some(value),
            "batchmode" => self.batch_mode = Some(value),
            "bindaddress" => self.bind_address = Some(value),
            "bindinterface" => self.bind_interface = Some(value),
            "canonicaldomains" => self.canonical_domains = Some(value),
            "canonicalizefallbacklocal" => self.canonicalize_fallback_local = Some(value),
            "canonicalizehostname" => self.canonicalize_hostname = Some(value),
            "canonicalizemaxdots" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.canonicalize_max_dots = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for CanonicalizeMaxDots", value);
              }
            },
            "canonicalizepermitted_cnames" => self.canonicalize_permitted_cnames = Some(value),
            "casignaturealgorithms" => self.ca_signature_algorithms = Some(value),
            "certificatefile" => self.certificate_file = Some(value),
            "challengeresponseauthentication" => self.challenge_response_authentication = Some(value),
            "checkhostip" => self.check_host_ip = Some(value),
            "ciphers" => {
              let values: Vec<String> = value.split(' ').map(|s| s.trim().to_string()).collect();
              self.ciphers = Some(values);
            },
            "clearallforwardings" => self.clear_all_forwardings = Some(value),
            "compression" => self.compression = Some(value),
            "compressionlevel" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.compression_level = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for CompressionLevel", value);
              }
            },
            "connectionattempts" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.connection_attempts = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for ConnectionAttempts", value);
              }
            },
            "connecttimeout" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.connect_timeout = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for ConnectTimeout", value);
              }
            },
            "controlmaster" => self.control_master = Some(value),
            "controlpath" => self.control_path = Some(value),
            "controlpersist" => self.control_persist = Some(value),
            "dynamicforward" => self.dynamic_forward = Some(value),
            "enablesshkeysign" => self.enable_ssh_keysign = Some(value),
            "escapechar" => self.escape_char = Some(value),
            "exitonforwardfailure" => self.exit_on_forward_failure = Some(value),
            "fingerprinthash" => self.fingerprint_hash = Some(value),
            "forwardagent" => self.forward_agent = Some(value),
            "forwardx11" => self.forward_x11 = Some(value),
            "forwardx11timeout" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.forward_x11_timeout = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for ForwardX11Timeout", value);
              }
            },
            "forwardx11trusted" => self.forward_x11_trusted = Some(value),
            "gatewayports" => self.gateway_ports = Some(value),
            "globalknownhostsfile" => self.global_known_hosts_file = Some(value),
            "gssapiauthentication" => self.gssapi_authentication = Some(value),
            "gssapidelegatecredentials" => self.gssapi_delegate_credentials = Some(value),
            "gssapikeyexchange" => self.gssapi_key_exchange = Some(value),
            "gssapiname" => self.gssapi_name = Some(value),
            "gssapiserveridentity" => self.gssapi_server_identity = Some(value),
            "gssapitrustdns" => self.gssapi_trust_dns = Some(value),
            "hashknownhosts" => self.hash_known_hosts = Some(value),
            "hostbasedauthentication" => self.hostbased_authentication = Some(value),
            "hostbasedkeytypes" => self.hostbased_key_types = Some(value),
            "hostkeyalgorithms" => {
              let values: Vec<String> = value.split(' ').map(|s| s.trim().to_string()).collect();
              self.host_key_algorithms = Some(values);
            },
            "hostkeyalias" => self.host_key_alias = Some(value),
            "identitiesonly" => self.identities_only = Some(value),
            "identityagent" => self.identity_agent = Some(value),
            "ignoreunknown" => self.ignore_unknown = Some(value),
            "include" => self.include = Some(value),
            "ipqos" => self.ip_qos = Some(value),
            "kbdinteractiveauthentication" => self.kbd_interactive_authentication = Some(value),
            "kbdinteractivedevices" => self.kbd_interactive_devices = Some(value),
            "kexalgorithms" => self.kex_algorithms = Some(value),
            "localcommand" => self.local_command = Some(value),
            "localforward" => self.local_forward = Some(value),
            "loglevel" => self.log_level = Some(value),
            "macs" => {
              let values: Vec<String> = value.split(' ').map(|s| s.trim().to_string()).collect();
              self.macs = Some(values);
            },
            "nohostauthenticationforlocalhost" => self.no_host_authentication_for_localhost = Some(value),
            "numberofpasswordprompts" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.number_of_password_prompts = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for NumberOfPasswordPrompts", value);
              }
            },
            "passwordauthentication" => self.password_authentication = Some(value),
            "permitlocal_command" => self.permit_local_command = Some(value),
            "permitremoteopen" => self.permit_remote_open = Some(value),
            "pkcs11provider" => self.pkcs11_provider = Some(value),
            "port" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.port = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for Port", value);
              }
            },
            "preferredauthentications" => self.preferred_authentications = Some(value),
            "proxycommand" => self.proxy_command = Some(value),
            "proxyjump" => self.proxy_jump = Some(value),
            "proxyusefdpass" => self.proxy_use_fdpass = Some(value),
            "pubkeyacceptedkeytypes" => self.pubkey_accepted_key_types = Some(value),
            "pubkeyauthentication" => self.pubkey_authentication = Some(value),
            "rekeylimit" => self.rekey_limit = Some(value),
            "remotecommand" => self.remote_command = Some(value),
            "remoteforward" => self.remote_forward = Some(value),
            "requesttty" => self.request_tty = Some(value),
            "revokedhostkeys" => self.revoked_host_keys = Some(value),
            "sendenv" => self.send_env = Some(value),
            "serveralivecountmax" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.server_alive_count_max = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for ServerAliveCountMax", value);
              }
            },
            "serveraliveinterval" => {
              if let Ok(parsed_value) = value.parse::<u32>() {
                self.server_alive_interval = Some(parsed_value);
              } else {
                eprintln!("Error: Could not parse {} as u32 for ServerAliveInterval", value);
              }
            },
            "streamlocalbindmask" => self.stream_local_bind_mask = Some(value),
            "streamlocalbindunlink" => self.stream_local_bind_unlink = Some(value),
            "stricthostkeychecking" => self.strict_host_key_checking = Some(value),
            "syslogfacility" => self.syslog_facility = Some(value),
            "tcpkeepalive" => self.tcp_keep_alive = Some(value),
            "tunnel" => self.tunnel = Some(value),
            "tunneldevice" => self.tunnel_device = Some(value),
            "updatehostkeys" => self.update_host_keys = Some(value),
            "usekeychain" => self.use_keychain = Some(value),
            "userknownhostsfile" => self.user_known_hosts_file = Some(value),
            "verifyhostkeydns" => self.verify_host_key_dns = Some(value),
            "visualhostkey" => self.visual_host_key = Some(value),
            "xauthlocation" => self.x_auth_location = Some(value),
            _ => {} // Ignore unknown keys
        }
    }
}
