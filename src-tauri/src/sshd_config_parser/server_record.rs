use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
/// Enumerator to support yes/no values in the configuration file.
pub enum YesNo {
    Yes,
    No,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
/// Enumerator to support yes/delayed/no values in the configuration file.
pub enum YesNoDelayed {
    Yes,
    Delayed,
    No,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
/// Enumerator to support yes/no/client-specified values in the configuration file.
pub enum YesNoClientspecified {
    Yes,
    No,
    Clientspecified,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
/// Enumerator to support yes/no/forced-commands-only values in the configuration file.
pub enum RootLogin {
    Yes,
    WithoutPassword,
    ForcedCommandsOnly,
    No,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
/// Enumerator to support log levels in the configuration file.
pub enum LogLevels {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug,
    Debug1,
    Debug2,
    Debug3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
/// Enumerator to support address family values in the configuration file.
pub enum AddressFamily {
    Any,
    Inet,
    Inet6,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
/// Enumerator to support tunnel options in the configuration file.
pub enum TunnelOptions {
    Yes,
    PointToPoint,
    Ethernet,
    No,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerRecord {
    /// ## AcceptEnv
    ///
    /// Specifies what environment variables sent by the client will be copied into the session's
    /// **environ(7)**. See **SendEnv** in ssh_config(5) for how to configure the client. Note that
    /// environment passing is only supported for protocol 2. Variables are specified by name, which
    /// may contain the wildcard characters `*` and `?`. Multiple environment variables may be
    /// separated by whitespace or spread across multiple **AcceptEnv** directives. Be warned that
    /// some environment variables could be used to bypass restricted user environments. For this
    /// reason, care should be taken in the use of this directive. The default is not to accept any
    /// environment variables.
    #[serde(rename = "AcceptEnv", skip_serializing_if = "Option::is_none")]
    pub accept_env: Option<String>,
    /// ## AddressFamily
    ///
    /// Specifies which address family should be used by **sshd(8)**. Valid arguments are `any`,
    /// `inet` (use IPv4 only), or `inet6` (use IPv6 only). The default is `any`.
    #[serde(rename = "AddressFamily", skip_serializing_if = "Option::is_none")]
    pub address_family: Option<AddressFamily>,
    /// ## AllowAgentForwarding
    ///
    /// Specifies whether **ssh-agent(1)** forwarding is permitted. The default is `yes`. Note that
    /// disabling agent forwarding does not improve security unless users are also denied shell
    /// access, as they can always install their own forwarders.
    #[serde(
        rename = "AllowAgentForwarding",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_agent_forwarding: Option<YesNo>,
    /// ## AllowGroups
    ///
    /// This keyword can be followed by a list of group name patterns, separated by spaces. If
    /// specified, login is allowed only for users whose primary group or supplementary group list
    /// matches one of the patterns. Only group names are valid; a numerical group ID is not
    /// recognized. By default, login is allowed for all groups. The allow/deny directives are
    /// processed in the following order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.
    ///
    /// See PATTERNS in **ssh_config(5)** for more information on patterns.
    #[serde(rename = "AllowGroups", skip_serializing_if = "Option::is_none")]
    pub allow_groups: Option<String>,
    /// ## AllowTcpForwarding
    ///
    /// Specifies whether TCP forwarding is permitted. The default is `yes`. Note that disabling TCP
    /// forwarding does not improve security unless users are also denied shell access, as they can
    /// always install their own forwarders.
    #[serde(rename = "AllowTcpForwarding", skip_serializing_if = "Option::is_none")]
    pub allow_tcp_forwarding: Option<YesNo>,
    /// ## AllowUsers
    ///
    /// This keyword can be followed by a list of user name patterns, separated by spaces. If
    /// specified, login is allowed only for user names that match one of the patterns. Only user
    /// names are valid; a numerical user ID is not recognized. By default, login is allowed for all
    /// users. If the pattern takes the form `USER@HOST` then `USER` and `HOST` are separately
    /// checked, restricting logins to particular users from particular hosts. The allow/deny
    /// directives are processed in the following order: DenyUsers, AllowUsers, DenyGroups, and
    /// finally AllowGroups.
    ///
    /// See PATTERNS in **ssh_config(5)** for more information on patterns.
    #[serde(rename = "AllowUsers", skip_serializing_if = "Option::is_none")]
    pub allow_users: Option<String>,
    /// ## AuthorizedKeysFile
    ///
    /// Specifies the file that contains the public keys that can be used for user authentication.
    /// AuthorizedKeysFile may contain tokens of the form %T which are substituted during connection
    /// setup. The following tokens are defined: %% is replaced by a literal '%', %h is replaced by
    /// the home directory of the user being authenticated, and %u is replaced by the username of
    /// that user. After expansion, AuthorizedKeysFile is taken to be an absolute path or one
    /// relative to the user's home directory. The default is `.ssh/authorized_keys`.
    #[serde(rename = "AuthorizedKeysFile", skip_serializing_if = "Option::is_none")]
    pub authorized_keys_file: Option<String>,
    /// ## Banner
    ///
    /// The contents of the specified file are sent to the remote user before authentication is
    /// allowed. If the argument is `none` then no banner is displayed. This option is only available
    /// for protocol version 2. By default, no banner is displayed.
    #[serde(rename = "Banner", skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// ## ChallengeResponseAuthentication
    ///
    /// Specifies whether challenge-response authentication is allowed (e.g. via PAM or though
    /// authentication styles supported in login.conf(5)) The default is `yes`.
    #[serde(
        rename = "ChallengeResponseAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub challenge_response_authentication: Option<YesNo>,
    /// ## ChrootDirectory
    ///
    /// Specifies a path to **chroot(2)** to after authentication. This path, and all its components,
    /// must be root-owned directories that are not writable by any other user or group. After the
    /// chroot, **sshd(8)** changes the working directory to the user's home directory.
    ///
    /// The path may contain the following tokens that are expanded at runtime once the connecting
    /// user has been authenticated: %% is replaced by a literal '%', %h is replaced by the home
    /// directory of the user being authenticated, and %u is replaced by the username of that user.
    ///
    /// The **ChrootDirectory** must contain the necessary files and directories to support the
    /// user's session. For an interactive session this requires at least a shell, typically
    /// **sh(1)**, and basic /dev nodes such as null(4), zero(4), stdin(4), stdout(4), stderr(4),
    /// arandom(4) and tty(4) devices. For file transfer sessions using `sftp`, no additional
    /// configuration of the environment is necessary if the in-process sftp server is used, though
    /// sessions which use logging do require /dev/log inside the chroot directory (see
    /// **sftp-server(8)** for details).
    ///
    /// The default is not to **chroot(2)**.
    #[serde(rename = "ChrootDirectory", skip_serializing_if = "Option::is_none")]
    pub chroot_directory: Option<String>,
    /// ## Ciphers
    ///
    /// Specifies the ciphers allowed for protocol version 2. Multiple ciphers must be
    /// comma-separated. The supported ciphers are `3des-cbc`, `aes128-cbc`, `aes192-cbc`,
    /// `aes256-cbc`, `aes128-ctr`, `aes192-ctr`, `aes256-ctr`, `arcfour128`, `arcfour256`,
    /// `arcfour`, `blowfish-cbc`, and `cast128-cbc`. The default is:
    ///
    /// ```
    /// aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,
    /// aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,
    /// aes256-cbc,arcfour
    /// ```
    #[serde(rename = "Ciphers", skip_serializing_if = "Option::is_none")]
    pub ciphers: Option<String>,
    /// ## ClientAliveCountMax
    ///
    /// Sets the number of client alive messages (see below) which may be sent without **sshd(8)**
    /// receiving any messages back from the client. If this threshold is reached while client alive
    /// messages are being sent, sshd will disconnect the client, terminating the session. It is
    /// important to note that the use of client alive messages is very different from
    /// **TCPKeepAlive** (below). The client alive messages are sent through the encrypted channel
    /// and therefore will not be spoofable. The TCP keepalive option enabled by **TCPKeepAlive** is
    /// spoofable. The client alive mechanism is valuable when the client or server depend on knowing
    /// when a connection has become inactive.
    ///
    /// The default value is 3. If **ClientAliveInterval** (see below) is set to 15, and
    /// **ClientAliveCountMax** is left at the default, unresponsive SSH clients will be disconnected
    /// after approximately 45 seconds. This option applies to protocol version 2 only.
    #[serde(
        rename = "ClientAliveCountMax",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_alive_count_max: Option<u32>,
    /// ## ClientAliveInterval
    ///
    /// Sets a timeout interval in seconds after which if no data has been received from the client,
    /// **sshd(8)** will send a message through the encrypted channel to request a response from the
    /// client. The default is 0, indicating that these messages will not be sent to the client. This
    /// option applies to protocol version 2 only.
    #[serde(
        rename = "ClientAliveInterval",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_alive_interval: Option<u32>,
    /// ## Compression
    ///
    /// Specifies whether compression is allowed, or delayed until the user has authenticated
    /// successfully. The argument must be `yes`, `delayed`, or `no`. The default is `delayed`.
    #[serde(rename = "Compression", skip_serializing_if = "Option::is_none")]
    pub compression: Option<YesNoDelayed>,
    /// ## DenyGroups
    ///
    /// This keyword can be followed by a list of group name patterns, separated by spaces. Login is
    /// disallowed for users whose primary group or supplementary group list matches one of the
    /// patterns. Only group names are valid; a numerical group ID is not recognized. By default,
    /// login is allowed for all groups. The allow/deny directives are processed in the following
    /// order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.
    ///
    /// See PATTERNS in **ssh_config(5)** for more information on patterns.
    #[serde(rename = "DenyGroups", skip_serializing_if = "Option::is_none")]
    pub deny_groups: Option<String>,
    /// ## DenyUsers
    ///
    /// This keyword can be followed by a list of user name patterns, separated by spaces. Login is
    /// disallowed for user names that match one of the patterns. Only user names are valid; a
    /// numerical user ID is not recognized. By default, login is allowed for all users. If the
    /// pattern takes the form `USER@HOST` then `USER` and `HOST` are separately checked, restricting
    /// logins to particular users from particular hosts. The allow/deny directives are processed in
    /// the following order: DenyUsers, AllowUsers, DenyGroups, and finally AllowGroups.
    ///
    /// See PATTERNS in **ssh_config(5)** for more information on patterns.
    #[serde(rename = "DenyUsers", skip_serializing_if = "Option::is_none")]
    pub deny_users: Option<String>,
    /// ## ForceCommand
    ///
    /// Forces the execution of the command specified by **ForceCommand**, ignoring any command
    /// supplied by the client and `~/.ssh/rc` if present. The command is invoked by using the user's
    /// login shell with the -c option. This applies to shell, command, or subsystem execution. It is
    /// most useful inside a **Match** block. The command originally supplied by the client is
    /// available in the SSH_ORIGINAL_COMMAND environment variable. Specifying a command of
    /// `internal-sftp` will force the use of an in-process sftp server that requires no support
    /// files when used with **ChrootDirectory**.
    #[serde(rename = "ForceCommand", skip_serializing_if = "Option::is_none")]
    pub force_command: Option<String>,
    /// ## GatewayPorts
    ///
    /// Specifies whether remote hosts are allowed to connect to ports forwarded for the client. By
    /// default, **sshd(8)** binds remote port forwardings to the loopback address. This prevents
    /// other remote hosts from connecting to forwarded ports. **GatewayPorts** can be used to
    /// specify that sshd should allow remote port forwardings to bind to non-loopback addresses,
    /// thus allowing other hosts to connect. The argument may be `no` to force remote port
    /// forwardings to be available to the local host only, `yes` to force remote port forwardings to
    /// bind to the wildcard address, or `clientspecified` to allow the client to select the address
    /// to which the forwarding is bound. The default is `no`.
    #[serde(rename = "GatewayPorts", skip_serializing_if = "Option::is_none")]
    pub gateway_ports: Option<YesNoClientspecified>,
    /// ## GSSAPIAuthentication
    ///
    /// Specifies whether user authentication based on GSSAPI is allowed. The default is `no`. Note
    /// that this option applies to protocol version 2 only.
    #[serde(
        rename = "GSSAPIAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub gssapi_authentication: Option<YesNo>,
    /// ## GSSAPIKeyExchange
    ///
    /// Specifies whether key exchange based on GSSAPI is allowed. GSSAPI key exchange doesn't rely
    /// on ssh keys to verify host identity. The default is `no`. Note that this option applies to
    /// protocol version 2 only.
    #[serde(rename = "GSSAPIKeyExchange", skip_serializing_if = "Option::is_none")]
    pub gssapi_key_exchange: Option<YesNo>,
    /// ## GSSAPICleanupCredentials
    ///
    /// Specifies whether to automatically destroy the user's credentials cache on logout. The
    /// default is `yes`. Note that this option applies to protocol version 2 only.
    #[serde(
        rename = "GSSAPICleanupCredentials",
        skip_serializing_if = "Option::is_none"
    )]
    pub gssapi_cleanup_credentials: Option<YesNo>,
    /// ## GSSAPIStrictAcceptorCheck
    ///
    /// Determines whether to be strict about the identity of the GSSAPI acceptor a client
    /// authenticates against. If `yes` then the client must authenticate against the host service on
    /// the current hostname. If `no` then the client may authenticate against any service key stored
    /// in the machine's default store. This facility is provided to assist with operation on multi
    /// homed machines. The default is `yes`. Note that this option applies only to protocol version
    /// 2 GSSAPI connections, and setting it to `no` may only work with recent Kerberos GSSAPI
    /// libraries.
    #[serde(
        rename = "GSSAPIStrictAcceptorCheck",
        skip_serializing_if = "Option::is_none"
    )]
    pub gssapi_strict_acceptor_check: Option<YesNo>,
    /// ## GSSAPIStoreCredentialsOnRekey
    ///
    /// Controls whether the user's GSSAPI credentials should be updated following a successful
    /// connection rekeying. This option can be used to accepted renewed or updated credentials from
    /// a compatible client. The default is `no`.
    #[serde(
        rename = "GSSAPIStoreCredentialsOnRekey",
        skip_serializing_if = "Option::is_none"
    )]
    pub gssapi_store_credentials_on_rekey: Option<YesNo>,
    /// ## HostbasedAuthentication
    ///
    /// Specifies whether rhosts or `/etc/hosts`.equiv authentication together with successful
    /// public key client host authentication is allowed (host-based authentication). This option
    /// is similar to **RhostsRSAAuthentication** and applies to protocol version 2 only.
    /// The default is `no`.
    #[serde(
        rename = "HostbasedAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub hostbased_authentication: Option<YesNo>,
    /// ## HostbasedUsesNameFromPacketOnly
    ///
    /// Specifies whether or not the server will attempt to perform a reverse name lookup when
    /// matching the name in the `~/.shosts`, `~/.rhosts`, and `/etc/hosts`.equiv files during
    /// **HostbasedAuthentication**. A setting of `yes` means that **sshd(8)** uses the name
    /// supplied by the client rather than attempting to resolve the name from the TCP connection
    /// itself. The default is `no`.
    #[serde(
        rename = "HostbasedUsesNameFromPacketOnly",
        skip_serializing_if = "Option::is_none"
    )]
    pub hostbased_uses_name_from_packet_only: Option<YesNo>,
    /// ## HostKey
    ///
    /// Specifies a file containing a private host key used by SSH. The default is
    /// `/etc/ssh/ssh_host_key` for protocol version 1, and `/etc/ssh/ssh_host_rsa_key` and
    /// `/etc/ssh/ssh_host_dsa_key` for protocol version 2. Note that **sshd(8)** will refuse to
    /// use a file if it is group/world-accessible. It is possible to have multiple host key files.
    /// `rsa1` keys are used for version 1 and `dsa` or `rsa` are used for version 2 of the
    /// SSH protocol.
    #[serde(rename = "HostKey", skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
    /// ## IgnoreRhosts
    ///
    /// Specifies that .rhosts and .shosts files will not be used in **RhostsRSAAuthentication** or
    /// **HostbasedAuthentication**.
    /// `/etc/hosts.equiv` and `/etc/ssh/shosts.equiv` are still used. The default is `yes`.
    #[serde(rename = "IgnoreRhosts", skip_serializing_if = "Option::is_none")]
    pub ignore_rhosts: Option<YesNo>,
    /// ## IgnoreUserKnownHosts
    ///
    /// Specifies whether **sshd(8)** should ignore the user's `~/.ssh/known_hosts` during
    /// **RhostsRSAAuthentication** or **HostbasedAuthentication**. The default is `no`.
    #[serde(
        rename = "IgnoreUserKnownHosts",
        skip_serializing_if = "Option::is_none"
    )]
    pub ignore_user_known_hosts: Option<YesNo>,
    /// ## KerberosAuthentication
    ///
    /// Specifies whether the password provided by the user for **PasswordAuthentication** will be
    /// validated through the Kerberos KDC. To use this option, the server needs a Kerberos servtab
    /// which allows the verification of the KDC's identity. The default is `no`.
    #[serde(
        rename = "KerberosAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub kerberos_authentication: Option<YesNo>,
    /// ## KerberosGetAFSToken
    ///
    /// If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before
    /// accessing the user's home directory. The default is `no`.
    #[serde(
        rename = "KerberosGetAFSToken",
        skip_serializing_if = "Option::is_none"
    )]
    pub kerberos_get_afs_token: Option<YesNo>,
    /// ## KerberosOrLocalPasswd
    ///
    /// If password authentication through Kerberos fails then the password will be validated via
    /// any additional local mechanism such as `/etc/passwd`. The default is `yes`.
    #[serde(
        rename = "KerberosOrLocalPasswd",
        skip_serializing_if = "Option::is_none"
    )]
    pub kerberos_or_local_passwd: Option<YesNo>,
    /// ## KerberosTicketCleanup
    ///
    /// Specifies whether to automatically destroy the user's ticket cache file on logout. The
    /// default is `yes`.
    #[serde(
        rename = "KerberosTicketCleanup",
        skip_serializing_if = "Option::is_none"
    )]
    pub kerberos_ticket_cleanup: Option<YesNo>,
    /// ## KerberosUseKuserok
    ///
    /// Specifies whether to look at `.k5login` file for user's aliases. The default is `yes`.
    #[serde(rename = "KerberosUseKuserok", skip_serializing_if = "Option::is_none")]
    pub kerberos_use_kuserok: Option<YesNo>,
    /// ## KeyRegenerationInterval
    ///
    /// In protocol version 1, the ephemeral server key is automatically regenerated after this
    /// many seconds (if it has been used). The purpose of regeneration is to prevent decrypting
    /// captured sessions by later breaking into the machine and stealing the keys. The key is
    /// never stored anywhere. If the value is 0, the key is never regenerated. The default is
    /// 3600 (seconds).
    #[serde(
        rename = "KeyRegenerationInterval",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_regeneration_interval: Option<u32>,
    /// ## ListenAddress
    ///
    /// Specifies the local addresses **sshd(8)** should listen on. The following forms may be used:
    ///
    /// ```
    /// ListenAddress host|IPv4_addr|IPv6_addr
    /// ListenAddress host|IPv4_addr:port
    /// ListenAddress [
    /// host|IPv6_addr]:port
    /// ```
    ///
    /// If port is not specified, sshd will listen on the address and all prior **Port** options
    /// specified. The default is to listen on all local addresses. Multiple ListenAddress options
    /// are permitted. Additionally, any Port options must precede this option for non-port
    /// qualified addresses.
    #[serde(rename = "ListenAddress", skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<String>,
    /// ## LoginGraceTime
    ///
    /// The server disconnects after this time if the user has not successfully logged in. If the
    /// value is 0, there is no time limit. The default is 120 seconds.
    #[serde(rename = "LoginGraceTime", skip_serializing_if = "Option::is_none")]
    pub login_grace_time: Option<u32>,
    /// ## LogLevel
    ///
    /// Gives the verbosity level that is used when logging messages from **sshd(8)**. The possible
    /// values are: QUIET, FATAL, ERROR, INFO, VERBOSE, DEBUG, DEBUG1, DEBUG2, and DEBUG3. The
    /// default is INFO. DEBUG and DEBUG1 are equivalent. DEBUG2 and DEBUG3 each specify higher
    /// levels of debugging output. Logging with a DEBUG level violates the privacy of users and is
    /// not recommended.
    #[serde(rename = "LogLevel", skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevels>,
    /// ## MACs
    ///
    /// Specifies the available MAC (message authentication code) algorithms. The MAC algorithm is
    /// used in protocol version 2 for data integrity protection. Multiple algorithms must be
    /// comma-separated. The default is:
    ///
    /// ```
    /// hmac-md5,hmac-sha1,umac-64@openssh.com,
    /// hmac-ripemd160,hmac-sha1-96,hmac-md5-96
    /// ```
    #[serde(rename = "MACs", skip_serializing_if = "Option::is_none")]
    pub macs: Option<String>,
    /// ## Match
    ///
    /// Introduces a conditional block. If all of the criteria on the **Match** line are satisfied,
    /// the keywords on the following lines override those set in the global section of the config
    /// file, until either another **Match** line or the end of the file.
    ///
    /// The arguments to **Match** are one or more criteria-pattern pairs. The available criteria
    /// are User, Group, Host, and Address. The match patterns may consist of single entries or
    /// comma-separated lists and may use the wildcard and negation operators described in the
    /// PATTERNS section of **ssh_config(5)**.
    ///
    /// The patterns in an **Address** criteria may additionally contain addresses to match in
    /// CIDR address/masklen format, e.g. `192.0.2.0/24` or `3ffe:ffff::/32`. Note that the
    /// mask length provided must be consistent with the address - it is an error to specify a mask
    /// length that is too long for the address or one with bits set in this host portion of the
    /// address. For example, `192.0.2.0/33` and `192.0.2.0/8` respectively.
    ///
    /// Only a subset of keywords may be used on the lines following a **Match** keyword. Available
    /// keywords are **AllowAgentForwarding**, **AllowTcpForwarding**, **Banner**,
    /// **ChrootDirectory**, **ForceCommand**, **GatewayPorts**, **GSSAPIAuthentication**,
    /// **HostbasedAuthentication**, **KbdInteractiveAuthentication**, **KerberosAuthentication**,
    /// **KerberosUseKuserok**, **MaxAuthTries**, **MaxSessions**, **PubkeyAuthentication**,
    /// **AuthorizedKeysCommand**, **AuthorizedKeysCommandRunAs**, **PasswordAuthentication**,
    /// **PermitEmptyPasswords**, **PermitOpen**, **PermitRootLogin**, **RequiredAuthentications1**,
    /// **RequiredAuthentications2**, **RhostsRSAAuthentication**, **RSAAuthentication**,
    /// **X11DisplayOffset**, **X11Forwarding** and **X11UseLocalHost**.
    #[serde(rename = "Match", skip_serializing_if = "Option::is_none")]
    pub match_: Option<String>,
    /// ## MaxAuthTries
    ///
    /// Specifies the maximum number of authentication attempts permitted per connection. Once the
    /// number of failures reaches half this value, additional failures are logged. The default is
    /// 6.
    #[serde(rename = "MaxAuthTries", skip_serializing_if = "Option::is_none")]
    pub max_auth_tries: Option<u32>,
    /// ## MaxSessions
    ///
    /// Specifies the maximum number of open sessions permitted per network connection. The default
    /// is 10.
    #[serde(rename = "MaxSessions", skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<u32>,
    /// ## MaxStartups
    ///
    /// Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.
    /// Additional connections will be dropped until authentication succeeds or the
    /// **LoginGraceTime** expires for a connection. The default is 10.
    ///
    /// Alternatively, random early drop can be enabled by specifying the three colon separated
    /// values `start:rate:full` (e.g. "10:30:60"). **sshd(8)** will refuse connection attempts
    /// with a probability of `rate/100` (30%) if there are currently `start` (10)
    /// unauthenticated connections. The probability increases linearly and all connection attempts
    /// are refused if the number of unauthenticated connections reaches `full` (60).
    #[serde(rename = "MaxStartups", skip_serializing_if = "Option::is_none")]
    pub max_startups: Option<String>,
    /// ## PasswordAuthentication
    ///
    /// Specifies whether password authentication is allowed. The default is `yes`.
    #[serde(
        rename = "PasswordAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_authentication: Option<YesNo>,
    /// ## PermitEmptyPasswords
    ///
    /// When password authentication is allowed, it specifies whether the server allows login to
    /// accounts with empty password strings. The default is `no`.
    #[serde(
        rename = "PermitEmptyPasswords",
        skip_serializing_if = "Option::is_none"
    )]
    pub permit_empty_passwords: Option<YesNo>,
    /// ## PermitOpen
    ///
    /// Specifies the destinations to which TCP port forwarding is permitted. The forwarding
    /// specification must be one of the following forms:
    ///
    /// ```
    /// PermitOpen host:port
    /// PermitOpen IPv4_addr:port
    /// PermitOpen [IPv6_addr]:port
    /// ```
    ///
    /// Multiple forwards may be specified by separating them with whitespace. An argument of `any`
    /// can be used to remove all restrictions and permit any forwarding requests. By default all
    /// port forwarding requests are permitted.
    #[serde(rename = "PermitOpen", skip_serializing_if = "Option::is_none")]
    pub permit_open: Option<String>,
    /// ## PermitRootLogin
    ///
    /// Specifies whether root can log in using **ssh(1)**. The argument must be `yes`,
    /// `without-password`, `forced-commands-only`, or `no`. The default is `yes`.
    ///
    /// If this option is set to `without-password`, password authentication is disabled for root.
    ///
    /// If this option is set to `forced-commands-only`, root login with public key authentication
    /// will be allowed, but only if the command option has been specified (which may be useful for
    /// taking remote backups even if root login is normally not allowed). All other authentication
    /// methods are disabled for root.
    ///
    /// If this option is set to `no`, root is not allowed to log in.
    #[serde(rename = "PermitRootLogin", skip_serializing_if = "Option::is_none")]
    pub permit_root_login: Option<RootLogin>,
    /// ## PermitTunnel
    ///
    /// Specifies whether **tun(4)** device forwarding is allowed. The argument must be `yes`,
    /// `point-to-point` (layer 3), `ethernet` (layer 2), or `no`. Specifying `yes` permits both
    /// `point-to-point` and `ethernet`. The default is `no`.
    #[serde(rename = "PermitTunnel", skip_serializing_if = "Option::is_none")]
    pub permit_tunnel: Option<TunnelOptions>,
    /// ## PermitUserEnvironment
    ///
    /// Specifies whether `~/.ssh/environment` and `environment=` options in
    /// `~/.ssh/authorized_keys` are processed by **sshd(8)**. The default is `no`. Enabling
    /// environment processing may enable users to bypass access restrictions in some
    /// configurations using mechanisms such as LD_PRELOAD.
    #[serde(
        rename = "PermitUserEnvironment",
        skip_serializing_if = "Option::is_none"
    )]
    pub permit_user_environment: Option<YesNo>,
    /// ## PidFile
    ///
    /// Specifies the file that contains the process ID of the SSH daemon. The default is
    /// `/var/run/sshd.pid`.
    #[serde(rename = "PidFile", skip_serializing_if = "Option::is_none")]
    pub pid_file: Option<String>,
    /// ## Port
    ///
    /// Specifies the port number that **sshd(8)** listens on. The default is 22. Multiple options
    /// of this type are permitted. See also **ListenAddress**.
    #[serde(rename = "Port", skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    /// ## PrintLastLog
    ///
    /// Specifies whether **sshd(8)** should print the date and time of the last user login when a
    /// user logs in interactively. The default is `yes`.
    #[serde(rename = "PrintLastLog", skip_serializing_if = "Option::is_none")]
    pub print_last_log: Option<YesNo>,
    /// ## PrintMotd
    ///
    /// Specifies whether **sshd(8)** should print `/etc/motd` when a user logs in interactively.
    /// (On some systems it is also printed by the shell, `/etc/profile`, or equivalent.) The
    /// default is `yes`.
    #[serde(rename = "PrintMotd", skip_serializing_if = "Option::is_none")]
    pub print_motd: Option<YesNo>,
    /// ## Protocol
    ///
    /// Specifies the protocol versions **sshd(8)** supports. The possible values are '1' and '2'.
    /// Multiple versions must be comma-separated. The default is `2,1`. Note that the order of the
    /// protocol list does not indicate preference, because the client selects among multiple
    /// protocol versions offered by the server. Specifying `2,1` is identical to `1,2`.
    #[serde(rename = "Protocol", skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// ## PubkeyAuthentication
    ///
    /// Specifies whether public key authentication is allowed. The default is `yes`. Note that
    /// this option applies to protocol version 2 only.
    #[serde(
        rename = "PubkeyAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub pubkey_authentication: Option<YesNo>,
    /// ## AuthorizedKeysCommand
    ///
    /// Specifies a program to be used for lookup of the user's public keys. The program will be
    /// invoked with its first argument the name of the user being authorized, and should produce
    /// on standard output **AuthorizedKeys** lines (see AUTHORIZED_KEYS in **sshd(8)**). By
    /// default (or when set to the empty string) there is no **AuthorizedKeysCommand** run. If
    /// the **AuthorizedKeysCommand** does not successfully authorize the user, authorization falls
    /// through to the **AuthorizedKeysFile**. Note that this option has an effect only with
    /// **PubkeyAuthentication** turned on.
    #[serde(
        rename = "AuthorizedKeysCommand",
        skip_serializing_if = "Option::is_none"
    )]
    pub authorized_keys_command: Option<String>,
    /// ## AuthorizedKeysCommandRunAs
    ///
    /// Specifies the user under whose account the **AuthorizedKeysCommand** is run. Empty string
    /// (the default value) means the user being authorized is used.
    #[serde(
        rename = "AuthorizedKeysCommandRunAs",
        skip_serializing_if = "Option::is_none"
    )]
    pub authorized_keys_command_run_as: Option<String>,
    /// ## RhostsRSAAuthentication
    /// Specifies required methods of authentications that has to succeed before authorizing the
    /// connection. (**RequiredAuthentication1* for Protocol version 1, and
    /// **RequiredAuthentication2** for v2)
    ///
    /// ```
    /// RequiredAuthentications1 method[,method...]
    /// RequiredAuthentications2 method[,method...]
    /// ```
    ///
    /// Example 1:
    ///
    /// ```
    /// RequiredAuthentications2 password,hostbased
    /// ```
    ///
    /// Example 2:
    ///
    /// ```
    /// RequiredAuthentications2 publickey,password
    /// ```
    ///
    /// Available methods:
    /// password, keyboard-interactive, publickey, hostbased, gssapi-keyex, gssapi-with-mic
    #[serde(
        rename = "RequiredAuthentications1",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_authentications1: Option<String>,
    #[serde(
        rename = "RequiredAuthentications2",
        skip_serializing_if = "Option::is_none"
    )]
    pub required_authentications2: Option<String>,
    /// ## RhostsRSAAuthentication
    ///
    /// Specifies whether rhosts or `/etc/hosts.equiv` authentication together with successful RSA
    /// host authentication is allowed. The default is `no`. This option applies to protocol
    /// version 1 only.
    #[serde(
        rename = "RhostsRSAAuthentication",
        skip_serializing_if = "Option::is_none"
    )]
    pub rhosts_rsa_authentication: Option<YesNo>,
    /// ## RSAAuthentication
    ///
    /// Specifies whether pure RSA authentication is allowed. The default is `yes`. This option
    /// applies to protocol version 1 only.
    #[serde(rename = "RSAAuthentication", skip_serializing_if = "Option::is_none")]
    pub rsa_authentication: Option<YesNo>,
    /// ## ServerKeyBits
    ///
    /// Defines the number of bits in the ephemeral protocol version 1 server key. The minimum
    /// value is 512, and the default is 1024.
    #[serde(rename = "ServerKeyBits", skip_serializing_if = "Option::is_none")]
    pub server_key_bits: Option<u32>,
    /// ## ShowPatchLevel
    ///
    /// Specifies whether sshd will display the patch level of the binary in the identification
    /// string. The patch level is set at compile-time. The default is `no`. This option applies
    /// to protocol version 1 only.
    #[serde(rename = "ShowPatchLevel", skip_serializing_if = "Option::is_none")]
    pub show_patch_level: Option<YesNo>,
    /// ## StrictModes
    ///
    /// Specifies whether **sshd(8)** should check file modes and ownership of the user's files
    /// and home directory before accepting login. This is normally desirable because novices
    /// sometimes accidentally leave their directory or files world-writable. The default is `yes`.
    #[serde(rename = "StrictModes", skip_serializing_if = "Option::is_none")]
    pub strict_modes: Option<YesNo>,
    /// ## Subsystem
    ///
    /// Configures an external subsystem (e.g. file transfer daemon). Arguments should be a
    /// subsystem name and a command (with optional arguments) to execute upon subsystem request.
    ///
    /// The command **sftp-server(8)** implements the `sftp` file transfer subsystem.
    ///
    /// Alternately the name `internal-sftp` implements an in-process `sftp` server. This may
    /// simplify configurations using **ChrootDirectory** to force a different filesystem root on
    /// clients.
    ///
    /// By default no subsystems are defined. Note that this option applies to protocol version 2
    /// only.
    #[serde(rename = "Subsystem", skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    /// ## SyslogFacility
    ///
    /// Gives the facility code that is used when logging messages from **sshd(8)**. The possible
    /// values are: DAEMON, USER, AUTH, AUTHPRIV, LOCAL0, LOCAL1, LOCAL2, LOCAL3, LOCAL4, LOCAL5,
    /// LOCAL6, LOCAL7. The default is AUTH.
    #[serde(rename = "SyslogFacility", skip_serializing_if = "Option::is_none")]
    pub syslog_facility: Option<String>,
    /// ## TCPKeepAlive
    ///
    /// Specifies whether the system should send TCP keepalive messages to the other side. If they
    /// are sent, death of the connection or crash of one of the machines will be properly noticed.
    /// However, this means that connections will die if the route is down temporarily, and some
    /// people find it annoying. On the other hand, if TCP keepalives are not sent, sessions may
    /// hang indefinitely on the server, leaving `ghost` users and consuming server resources.
    ///
    /// The default is `yes` (to send TCP keepalive messages), and the server will notice if the
    /// network goes down or the client host crashes. This avoids infinitely hanging sessions.
    ///
    /// To disable TCP keepalive messages, the value should be set to `no`.
    #[serde(rename = "TCPKeepAlive", skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive: Option<YesNo>,
    /// ## UseDNS
    ///
    /// Specifies whether **sshd(8)** should look up the remote host name and check that the
    /// resolved host name for the remote IP address maps back to the very same IP address. The
    /// default is `yes`.
    #[serde(rename = "UseDNS", skip_serializing_if = "Option::is_none")]
    pub use_dns: Option<YesNo>,
    /// ## UseLogin
    ///
    /// Specifies whether **login(1)** is used for interactive login sessions. The default is `no`.
    /// Note that **login(1)** is never used for remote command execution. Note also, that if this
    /// is enabled, **X11Forwarding** will be disabled because **login(1)** does not know how to
    /// handle **xauth(1)** cookies. If **UsePrivilegeSeparation** is specified, it will be
    /// disabled after authentication.
    #[serde(rename = "UseLogin", skip_serializing_if = "Option::is_none")]
    pub use_login: Option<YesNo>,
    /// ## UsePAM
    ///
    /// Enables the Pluggable Authentication Module interface. If set to `yes` this will enable
    /// PAM authentication using **ChallengeResponseAuthentication** and **PasswordAuthentication**
    /// in addition to PAM account and session module processing for all authentication types.
    ///
    /// Because PAM challenge-response authentication usually serves an equivalent role to password
    /// authentication, you should disable either **PasswordAuthentication** or
    /// **ChallengeResponseAuthentication**.
    ///
    /// If **UsePAM** is enabled, you will not be able to run **sshd(8)** as a non-root user. The
    /// default is `no`.
    #[serde(rename = "UsePAM", skip_serializing_if = "Option::is_none")]
    pub use_pam: Option<YesNo>,
    /// ## UsePrivilegeSeparation
    ///
    /// Specifies whether **sshd(8)** separates privileges by creating an unprivileged child
    /// process to deal with incoming network traffic. After successful authentication, another
    /// process will be created that has the privilege of the authenticated user. The goal of
    /// privilege separation is to prevent privilege escalation by containing any corruption within
    /// the unprivileged processes. The default is `yes`.
    #[serde(
        rename = "UsePrivilegeSeparation",
        skip_serializing_if = "Option::is_none"
    )]
    pub use_privilege_separation: Option<YesNo>,
    /// ## X11DisplayOffset
    ///
    /// Specifies the first display number available for **sshd(8)**'s X11 forwarding. This
    /// prevents sshd from interfering with real X11 servers. The default is 10.
    #[serde(rename = "X11DisplayOffset", skip_serializing_if = "Option::is_none")]
    pub x11_display_offset: Option<u32>,
    /// ## X11Forwarding
    ///
    /// Specifies whether X11 forwarding is permitted. The argument must be `yes` or `no`. The
    /// default is `no`.
    ///
    /// When X11 forwarding is enabled, there may be additional exposure to the server and to
    /// client displays if the **sshd(8)** proxy display is configured to listen on the wildcard
    /// address (see **X11UseLocalhost** below), though this is not the default. Additionally, the
    /// authentication spoofing and authentication data verification and substitution occur on the
    /// client side. The security risk of using X11 forwarding is that the client's X11 display
    /// server may be exposed to attack when the SSH client requests forwarding (see the warnings
    /// for **ForwardX11** in **ssh_config(5)**). A system administrator may have a stance in which
    /// they want to protect clients that may expose themselves to attack by unwittingly requesting
    /// X11 forwarding, which can warrant a `no` setting.
    ///
    /// Note that disabling X11 forwarding does not prevent users from forwarding X11 traffic, as
    /// users can always install their own forwarders. X11 forwarding is automatically disabled if
    /// **UseLogin** is enabled.
    #[serde(rename = "X11Forwarding", skip_serializing_if = "Option::is_none")]
    pub x11_forwarding: Option<YesNo>,
    /// ## X11UseLocalhost
    ///
    /// Specifies whether **sshd(8)** should bind the X11 forwarding server to the loopback address
    /// or to the wildcard address. By default, sshd binds the forwarding server to the loopback
    /// address and sets the hostname part of the DISPLAY environment variable to `localhost`. This
    /// prevents remote hosts from connecting to the proxy display. However, some older X11 clients
    /// may not function with this configuration. **X11UseLocalhost** may be set to `no` to specify
    /// that the forwarding server should be bound to the wildcard address. The argument must be
    /// `yes` or `no`. The default is `yes`.
    #[serde(rename = "X11UseLocalhost", skip_serializing_if = "Option::is_none")]
    pub x11_use_localhost: Option<YesNo>,
    /// ## XAuthLocation
    ///
    /// Specifies the full pathname of the **xauth(1)** program. The default is `/usr/bin/xauth`.
    #[serde(rename = "XAuthLocation", skip_serializing_if = "Option::is_none")]
    pub xauth_location: Option<String>,
}

impl ServerRecord {
    /// Create a new `ServerRecord` with default values.
    pub fn new() -> Self {
        Self {
            accept_env: None,
            address_family: None,
            allow_agent_forwarding: None,
            allow_groups: None,
            allow_tcp_forwarding: None,
            allow_users: None,
            authorized_keys_file: None,
            banner: None,
            challenge_response_authentication: None,
            chroot_directory: None,
            ciphers: None,
            client_alive_count_max: None,
            client_alive_interval: None,
            compression: None,
            deny_groups: None,
            deny_users: None,
            force_command: None,
            gateway_ports: None,
            gssapi_authentication: None,
            gssapi_key_exchange: None,
            gssapi_cleanup_credentials: None,
            gssapi_strict_acceptor_check: None,
            gssapi_store_credentials_on_rekey: None,
            hostbased_authentication: None,
            hostbased_uses_name_from_packet_only: None,
            host_key: None,
            ignore_rhosts: None,
            ignore_user_known_hosts: None,
            kerberos_authentication: None,
            kerberos_get_afs_token: None,
            kerberos_or_local_passwd: None,
            kerberos_ticket_cleanup: None,
            kerberos_use_kuserok: None,
            key_regeneration_interval: None,
            listen_address: None,
            login_grace_time: None,
            log_level: None,
            macs: None,
            match_: None,
            max_auth_tries: None,
            max_sessions: None,
            max_startups: None,
            password_authentication: None,
            permit_empty_passwords: None,
            permit_open: None,
            permit_root_login: None,
            permit_tunnel: None,
            permit_user_environment: None,
            pid_file: None,
            port: None,
            print_last_log: None,
            print_motd: None,
            protocol: None,
            pubkey_authentication: None,
            authorized_keys_command: None,
            authorized_keys_command_run_as: None,
            required_authentications1: None,
            required_authentications2: None,
            rhosts_rsa_authentication: None,
            rsa_authentication: None,
            server_key_bits: None,
            show_patch_level: None,
            strict_modes: None,
            subsystem: None,
            syslog_facility: None,
            tcp_keep_alive: None,
            use_dns: None,
            use_login: None,
            use_pam: None,
            use_privilege_separation: None,
            x11_display_offset: None,
            x11_forwarding: None,
            x11_use_localhost: None,
            xauth_location: None,
        }
    }

    pub fn set_property(&mut self, key: &str, value: String) {
        match key.to_lowercase().as_str() {
            "acceptenv" => self.accept_env = Some(value),
            "allowgroups" => self.allow_groups = Some(value),
            "allowusers" => self.allow_users = Some(value),
            "authorizedkeysfile" => self.authorized_keys_file = Some(value),
            "banner" => self.banner = Some(value),
            "chrootdirectory" => self.chroot_directory = Some(value),
            "ciphers" => self.ciphers = Some(value),
            "denygroups" => self.deny_groups = Some(value),
            "denyusers" => self.deny_users = Some(value),
            "forcecommand" => self.force_command = Some(value),
            "hostkey" => self.host_key = Some(value),
            "listenaddress" => self.listen_address = Some(value),
            "macs" => self.macs = Some(value),
            "match" => self.match_ = Some(value),
            "maxstartups" => self.max_startups = Some(value),
            "permitopen" => self.permit_open = Some(value),
            "pidfile" => self.pid_file = Some(value),
            "protocol" => self.protocol = Some(value),
            "authorizedkeyscommand" => self.authorized_keys_command = Some(value),
            "authorizedkeyscommandrunas" => self.authorized_keys_command_run_as = Some(value),
            "requiredauthentications1" => self.required_authentications1 = Some(value),
            "requiredauthentications2" => self.required_authentications2 = Some(value),
            "subsystem" => self.subsystem = Some(value),
            "syslogfacility" => self.syslog_facility = Some(value),
            "xauthlocation" => self.xauth_location = Some(value),
            // Handle numeric value conversions
            "clientalivecountmax" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.client_alive_count_max = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "clientaliveinterval" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.client_alive_interval = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "keyregenerationinterval" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.key_regeneration_interval = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "logingracetime" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.login_grace_time = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "maxauthtries" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.max_auth_tries = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "maxsessions" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.max_sessions = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "port" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.port = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "serverkeybits" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.server_key_bits = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            "x11displayoffset" => {
                if let Ok(parsed_value) = value.parse::<u32>() {
                    self.x11_display_offset = Some(parsed_value);
                } else {
                    eprintln!(
                        "Error: Could not parse {} as u32 for {}",
                        value,
                        key.to_string()
                    );
                }
            }
            // Handle enumerated values
            "addressfamily" => match value.to_lowercase().as_str() {
                "any" => self.address_family = Some(AddressFamily::Any),
                "inet" => self.address_family = Some(AddressFamily::Inet),
                "inet6" => self.address_family = Some(AddressFamily::Inet6),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "allowagentforwarding" => match value.to_lowercase().as_str() {
                "yes" => self.allow_agent_forwarding = Some(YesNo::Yes),
                "no" => self.allow_agent_forwarding = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "allowtcpforwarding" => match value.to_lowercase().as_str() {
                "yes" => self.allow_tcp_forwarding = Some(YesNo::Yes),
                "no" => self.allow_tcp_forwarding = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "challengeresponseauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.challenge_response_authentication = Some(YesNo::Yes),
                "no" => self.challenge_response_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "compression" => match value.to_lowercase().as_str() {
                "yes" => self.compression = Some(YesNoDelayed::Yes),
                "no" => self.compression = Some(YesNoDelayed::No),
                "delayed" => self.compression = Some(YesNoDelayed::Delayed),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "gatewayports" => match value.to_lowercase().as_str() {
                "yes" => self.gateway_ports = Some(YesNoClientspecified::Yes),
                "no" => self.gateway_ports = Some(YesNoClientspecified::No),
                "clientspecified" => {
                    self.gateway_ports = Some(YesNoClientspecified::Clientspecified)
                }
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "gssapiauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.gssapi_authentication = Some(YesNo::Yes),
                "no" => self.gssapi_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "gssapikeyexchange" => match value.to_lowercase().as_str() {
                "yes" => self.gssapi_key_exchange = Some(YesNo::Yes),
                "no" => self.gssapi_key_exchange = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "gssapicleanupcredentials" => match value.to_lowercase().as_str() {
                "yes" => self.gssapi_cleanup_credentials = Some(YesNo::Yes),
                "no" => self.gssapi_cleanup_credentials = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "gssapistrictacceptorcheck" => match value.to_lowercase().as_str() {
                "yes" => self.gssapi_strict_acceptor_check = Some(YesNo::Yes),
                "no" => self.gssapi_strict_acceptor_check = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "gssapistorecredentialsonrekey" => match value.to_lowercase().as_str() {
                "yes" => self.gssapi_store_credentials_on_rekey = Some(YesNo::Yes),
                "no" => self.gssapi_store_credentials_on_rekey = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "hostbasedauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.hostbased_authentication = Some(YesNo::Yes),
                "no" => self.hostbased_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "hostbasedusesnamefrompacketonly" => match value.to_lowercase().as_str() {
                "yes" => self.hostbased_uses_name_from_packet_only = Some(YesNo::Yes),
                "no" => self.hostbased_uses_name_from_packet_only = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "ignorerhosts" => match value.to_lowercase().as_str() {
                "yes" => self.ignore_rhosts = Some(YesNo::Yes),
                "no" => self.ignore_rhosts = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "ignoreuserknownhosts" => match value.to_lowercase().as_str() {
                "yes" => self.ignore_user_known_hosts = Some(YesNo::Yes),
                "no" => self.ignore_user_known_hosts = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "kerberosauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.kerberos_authentication = Some(YesNo::Yes),
                "no" => self.kerberos_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "kerberosgetafstoken" => match value.to_lowercase().as_str() {
                "yes" => self.kerberos_get_afs_token = Some(YesNo::Yes),
                "no" => self.kerberos_get_afs_token = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "kerberosorlocalpasswd" => match value.to_lowercase().as_str() {
                "yes" => self.kerberos_or_local_passwd = Some(YesNo::Yes),
                "no" => self.kerberos_or_local_passwd = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "kerberosticketcleanup" => match value.to_lowercase().as_str() {
                "yes" => self.kerberos_ticket_cleanup = Some(YesNo::Yes),
                "no" => self.kerberos_ticket_cleanup = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "kerberosusekuserok" => match value.to_lowercase().as_str() {
                "yes" => self.kerberos_use_kuserok = Some(YesNo::Yes),
                "no" => self.kerberos_use_kuserok = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "loglevel" => match value.to_lowercase().as_str() {
                "quiet" => self.log_level = Some(LogLevels::Quiet),
                "fatal" => self.log_level = Some(LogLevels::Fatal),
                "error" => self.log_level = Some(LogLevels::Error),
                "info" => self.log_level = Some(LogLevels::Info),
                "verbose" => self.log_level = Some(LogLevels::Verbose),
                "debug" => self.log_level = Some(LogLevels::Debug),
                "debug1" => self.log_level = Some(LogLevels::Debug1),
                "debug2" => self.log_level = Some(LogLevels::Debug2),
                "debug3" => self.log_level = Some(LogLevels::Debug3),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "passwordauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.password_authentication = Some(YesNo::Yes),
                "no" => self.password_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "permitemptypasswords" => match value.to_lowercase().as_str() {
                "yes" => self.permit_empty_passwords = Some(YesNo::Yes),
                "no" => self.permit_empty_passwords = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "permitrootlogin" => match value.to_lowercase().as_str() {
                "yes" => self.permit_root_login = Some(RootLogin::Yes),
                "without-password" => self.permit_root_login = Some(RootLogin::WithoutPassword),
                "forced-commands-only" => {
                    self.permit_root_login = Some(RootLogin::ForcedCommandsOnly)
                }
                "no" => self.permit_root_login = Some(RootLogin::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "permittunnel" => match value.to_lowercase().as_str() {
                "yes" => self.permit_tunnel = Some(TunnelOptions::Yes),
                "point-to-point" => self.permit_tunnel = Some(TunnelOptions::PointToPoint),
                "ethernet" => self.permit_tunnel = Some(TunnelOptions::Ethernet),
                "no" => self.permit_tunnel = Some(TunnelOptions::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "permituserenvironment" => match value.to_lowercase().as_str() {
                "yes" => self.permit_user_environment = Some(YesNo::Yes),
                "no" => self.permit_user_environment = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "printlastlog" => match value.to_lowercase().as_str() {
                "yes" => self.print_last_log = Some(YesNo::Yes),
                "no" => self.print_last_log = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "printmotd" => match value.to_lowercase().as_str() {
                "yes" => self.print_motd = Some(YesNo::Yes),
                "no" => self.print_motd = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "pubkeyauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.pubkey_authentication = Some(YesNo::Yes),
                "no" => self.pubkey_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "rhostsrsaauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.rhosts_rsa_authentication = Some(YesNo::Yes),
                "no" => self.rhosts_rsa_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "rsaauthentication" => match value.to_lowercase().as_str() {
                "yes" => self.rsa_authentication = Some(YesNo::Yes),
                "no" => self.rsa_authentication = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "showpatchlevel" => match value.to_lowercase().as_str() {
                "yes" => self.show_patch_level = Some(YesNo::Yes),
                "no" => self.show_patch_level = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "strictmodes" => match value.to_lowercase().as_str() {
                "yes" => self.strict_modes = Some(YesNo::Yes),
                "no" => self.strict_modes = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "tcpkeepalive" => match value.to_lowercase().as_str() {
                "yes" => self.tcp_keep_alive = Some(YesNo::Yes),
                "no" => self.tcp_keep_alive = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "usedns" => match value.to_lowercase().as_str() {
                "yes" => self.use_dns = Some(YesNo::Yes),
                "no" => self.use_dns = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "uselogin" => match value.to_lowercase().as_str() {
                "yes" => self.use_login = Some(YesNo::Yes),
                "no" => self.use_login = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "usepam" => match value.to_lowercase().as_str() {
                "yes" => self.use_pam = Some(YesNo::Yes),
                "no" => self.use_pam = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "useprivilegeseparation" => match value.to_lowercase().as_str() {
                "yes" => self.use_privilege_separation = Some(YesNo::Yes),
                "no" => self.use_privilege_separation = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "x11forwarding" => match value.to_lowercase().as_str() {
                "yes" => self.x11_forwarding = Some(YesNo::Yes),
                "no" => self.x11_forwarding = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            "x11uselocalhost" => match value.to_lowercase().as_str() {
                "yes" => self.x11_use_localhost = Some(YesNo::Yes),
                "no" => self.x11_use_localhost = Some(YesNo::No),
                _ => {
                    eprintln!("Invalid value for {}: {}", key.to_string(), value);
                }
            },
            _ => {}
        }
    }
}
