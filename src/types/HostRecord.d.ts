type ValidKexAlgorithnms = 'curve25519-sha256' |'curve25519-sha256@libssh.org' |'ecdh-sha2-nistp256' |'ecdh-sha2-nistp384' |'ecdh-sha2-nistp521' |
  'diffie-hellman-group-exchange-sha256' | 'diffie-hellman-group16-sha512' | 'diffie-hellman-group18-sha512' | 'diffie-hellman-group14-sha256';

type ValidMACs = 'hmac-md5' | 'hmac-sha1' | 'umac-64@openssh.com' | 'hmac-ripemd160' | 'hmac-sha1-96' | 'hmac-md5-96';

type ValidIPQoS = 'af11' | 'af12' | 'af13' | 'af21' | 'af22' | 'af23' | 'af31' | 'af32' | 'af33' | 'af41' | 'af42' |
  'af43' | 'cs0' | 'cs1' | 'cs2' | 'cs3' | 'cs4' | 'cs5' | 'cs6' | 'cs7' | 'ef' | 'le' | 'lowdelay' | 'throughput' |
  'reliability' | 'none' | number;

type ValidPubKeyAlgorithms = 'ssh-ed25519-cert-v01@openssh.com' | 'ecdsa-sha2-nistp256-cert-v01@openssh.com' | 'ecdsa-sha2-nistp384-cert-v01@openssh.com' | 
  'ecdsa-sha2-nistp521-cert-v01@openssh.com' | 'sk-ssh-ed25519-cert-v01@openssh.com' | 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com' | 
  'rsa-sha2-512-cert-v01@openssh.com' | 'rsa-sha2-256-cert-v01@openssh.com' | 'ssh-rsa-cert-v01@openssh.com' | 'ssh-ed25519' | 'ecdsa-sha2-nistp256' |
  'ecdsa-sha2-nistp384' | 'ecdsa-sha2-nistp521' | 'sk-ssh-ed25519@openssh.com' | 'sk-ecdsa-sha2-nistp256@openssh.com' | 'rsa-sha2-512' | 'rsa-sha2-256,ssh-rsa';

type ValidPubKeyTypes = 'ecdsa-sha2-nistp256-cert-v01@openssh.com' | 'ecdsa-sha2-nistp384-cert-v01@openssh.com' | 'ecdsa-sha2-nistp521-cert-v01@openssh.com' | 
  'ssh-ed25519-cert-v01@openssh.com' | 'rsa-sha2-512-cert-v01@openssh.com' | 'rsa-sha2-256-cert-v01@openssh.com' | 'ssh-rsa-cert-v01@openssh.com' | 
  'ecdsa-sha2-nistp256' | 'ecdsa-sha2-nistp384' | 'ecdsa-sha2-nistp521' | 'ssh-ed25519' | 'rsa-sha2-512' | 'rsa-sha2-256' | 'ssh-rsa';

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
  Host: string;
  AcceptEnv?: string;
  AddKeysToAgent?: 'yes' | 'no' | 'confirm' | 'ask' | string;
  AddressFamily?: 'any' | 'inet' | 'inet6';
  AllowAgentForwarding?: 'yes' | 'no';
  AllowGroups?: string;
  AllowStreamLocalForwarding?: 'yes' | 'all' | 'no' | 'local' | 'remote';
  AllowTcpForwarding?: 'yes' | 'all' | 'no' | 'local' | 'remote';
  AllowUsers?: string;
  AuthenticationMethods?: 'gssapi-with-mic' | 'hostbased' | 'keyboard-interactive' | 'none' | 'password' | 'publickey';
  AuthorizedKeysCommand?: string;
  AuthorizedKeysCommandUser?: string;
  AuthorizedKeysFile?: string;
  AuthorizedPrincipalsCommand?: string;
  AuthorizedPrincipalsCommandUser?: string;
  AuthorizedPrincipalsFile?: string;
  Banner?: string;
  BatchMode?: 'yes' | 'no';
  BindAddress?: string;
  BindInterface?: string;
  CanonicalDomains?: string;
  CanonicalizeFallbackLocal?: 'yes' | 'no';
  CanonicalizeHostname?: 'yes' | 'no';
  CanonicalizeMaxDots?: number;
  CanonicalizePermittedCNAMEs?: string;
  CASignatureAlgorithms?: string;
  CertificateFile?: string;
  ChallengeResponseAuthentication?: 'yes' | 'no';
  CheckHostIP?: 'yes' | 'no';
  ChrootDirectory?: string;
  Cipher?: '3des' | 'blowfish' | 'des';
  Ciphers?: string;
  ClearAllForwardings?: 'yes' | 'no';
  ClientAliveCountMax?: number;
  ClientAliveInterval?: number;
  Compression?: 'yes' | 'no';
  CompressionLevel?: number;
  ConnectionAttempts?: number;
  ConnectTimeout?: number;
  ControlMaster?: 'auto' | 'autoask' | 'yes' | 'no';
  ControlPath?: string;
  ControlPersist?: number | 'yes' | 'no';
  DenyGroups?: string;
  DenyUsers?: string;
  DisableForwarding?: 'yes' | 'no';
  DynamicForward?: string;
  EnableSSHKeysign?: 'yes' | 'no';
  EscapeChar?: string;
  ExitOnForwardFailure?: 'yes' | 'no';
  ExposeAuthInfo?: 'yes' | 'no';
  FingerprintHash?: 'md5' | 'sha256';
  ForceCommand?: string;
  ForkAfterAuthentication?: 'yes' | 'no';
  ForwardAgent?: 'yes' | 'no';
  ForwardX11?: 'yes' | 'no';
  ForwardX11Timeout?: number;
  ForwardX11Trusted?: 'yes' | 'no';
  GatewayPorts?: 'yes' | 'no';
  GlobalKnownHostsFile?: string;
  GSSAPIAuthentication?: 'yes' | 'no';
  GSSAPICleanupCredentials?: 'yes' | 'no';
  GSSAPIClientIdentity?: string;
  GSSAPIDelegateCredentials?: 'yes' | 'no';
  GSSAPIKeyExchange?: 'yes' | 'no';
  GSSAPIRenewalForcesRekey?: 'yes' | 'no';
  GSSAPIStrictAcceptorCheck?: 'yes' | 'no';
  GSSAPITrustDns?: 'yes' | 'no';
  HashKnownHosts?: 'yes' | 'no';
  HostbasedAcceptedAlgorithms?: string;
  HostbasedAcceptedKeyTypes?: string;
  HostbasedAuthentication?: 'yes' | 'no';
  HostbasedUsesNameFromPacketOnly?: 'yes' | 'no';
  HostCertificate?: string;
  HostKey?: string;
  HostKeyAgent?: string;
  HostKeyAlgorithms?: string;
  HostKeyAlias?: string;
  HostName?: string;
  IdentitiesOnly?: 'yes' | 'no';
  IdentityAgent?: string;
  IdentityFile?: string;
  IgnoreRhosts?: 'yes' | 'no';
  IgnoreUnknown?: string;
  IgnoreUserKnownHosts?: 'yes' | 'no';
  Include?: string;
  IPQoS?: ValidIPQoS[];
  KbdInteractiveAuthentication?: 'yes' | 'no';
  KbdInteractiveDevices?: string;
  KerberosAuthentication?: 'yes' | 'no';
  KerberosGetAFSToken?: 'yes' | 'no';
  KerberosOrLocalPasswd?: 'yes' | 'no';
  KerberosTicketCleanup?: 'yes' | 'no';
  KexAlgorithms?: ValidKexAlgorithnms[];
  KnownHostsCommand?: string;
  ListenAddress?: string;
  LocalCommand?: string;
  LocalForward?: string;
  LoginGraceTime?: number;
  LogLevel?: 'QUIET' | 'FATAL' | 'ERROR' | 'INFO' | 'VERBOSE' | 'DEBUG' | 'DEBUG1' | 'DEBUG2' | 'DEBUG3';
  LogVerbose?: 'yes' | 'no';
  MACs?: ValidMACs[];
  Match?: string;
  MaxAuthTries?: number;
  MaxSessions?: number;
  MaxStartups?: string;
  NoHostAuthenticationForLocalhost?: 'yes' | 'no';
  NumberOfPasswordPrompts?: number;
  PasswordAuthentication?: 'yes' | 'no';
  PermitEmptyPasswords?: 'yes' | 'no';
  PermitListen?: string;
  PermitLocalCommand?: 'yes' | 'no';
  PermitOpen?: string;
  PermitRemoteOpen?: string;
  PermitRootLogin?: 'yes' | 'prohibit-password' | 'forced-commands-only' | 'no';
  PermitTTY?: 'yes' | 'no';
  PermitTunnel?: 'yes' | 'point-to-point' | 'ethernet' | 'no';
  PermitUserEnvironment?: 'yes' | 'no' | string;
  PermitUserRC?: 'yes' | 'no';
  PidFile?: string;
  PKCS11Provider?: string;
  Port?: number;
  PreferredAuthentications?: string;
  PrintLastLog?: 'yes' | 'no';
  PrintMotd?: 'yes' | 'no';
  Protocol?: number;
  ProxyCommand?: string;
  ProxyJump?: string;
  ProxyUseFdpass?: 'yes' | 'no';
  PubkeyAcceptedAlgorithms?: ValidPubKeyAlgorithms[];
  PubkeyAcceptedKeyTypes?: ValidPubKeyTypes[];
  PubkeyAuthentication?: 'yes' | 'no';
  RDomain?: string;
  // The RekeyLimit argument is the number of bytes, with an optional suffix of ‘K’, ‘M’, or ‘G’ to indicate Kilobytes, Megabytes, or Gigabytes, respectively.
  // The default is between ‘1G’ and ‘4G’, depending on the cipher. This option applies to protocol version 2 only.
  RekeyLimit?: string;
  RemoteCommand?: string;
  RemoteForward?: string;
  RequestTTY?: 'no' | 'yes' | 'force' | 'auto';
  RevokedHostKeys?: string;
  RevokedKeys?: string;
  RhostsRSAAuthentication?: 'yes' | 'no';
  RSAAuthentication?: 'yes' | 'no';
  SecurityKeyProvider?: string;
  SendEnv?: string;
  ServerAliveCountMax?: number;
  ServerAliveInterval?: number;
  SessionType?: string;
  SetEnv?: string;
  SmartcardDevice?: string;
  StdinNull?: 'yes' | 'no';
  StreamLocalBindMask?: string;
  StreamLocalBindUnlink?: 'yes' | 'no';
  StrictHostKeyChecking?: 'yes' | 'no' | 'ask';
  StrictModes?: 'yes' | 'no';
  Subsystem?: string;
  SyslogFacility?: string;
  TCPKeepAlive?: 'yes' | 'no';
  TrustedUserCAKeys?: string;
  Tunnel?: 'yes' | 'no' | 'point-to-point' | 'ethernet';
  TunnelDevice?: string;
  UpdateHostKeys?: 'yes' | 'no' | 'ask';
  UseBlacklist?: 'yes' | 'no';
  UseDNS?: 'yes' | 'no';
  UsePAM?: 'yes' | 'no';
  UsePrivilegedPort?: 'yes' | 'no';
  User?: string;
  UserKnownHostsFile?: string;
  VerifyHostKeyDNS?: 'yes' | 'no' | 'ask';
  VersionAddendum?: string;
  VisualHostKey?: 'yes' | 'no';
  X11DisplayOffset?: number;
  X11Forwarding?: 'yes' | 'no';
  X11UseLocalhost?: 'yes' | 'no';
  XAuthLocation?: string;
};