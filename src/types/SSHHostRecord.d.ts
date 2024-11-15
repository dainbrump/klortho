export type ValidHostKeyAlgorithm =
  | 'ssh-ed25519-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp384-cert-v01@openssh.com'
  | 'ecdsa-sha2-nistp521-cert-v01@openssh.com'
  | 'sk-ssh-ed25519@openssh.com'
  | 'sk-ecdsa-sha2-nistp256@openssh.com'
  | 'ssh-ed25519'
  | 'ssh-rsa'
  | 'rsa-sha2-512'
  | 'rsa-sha2-256'
  | 'ecdsa-sha2-nistp256'
  | 'ecdsa-sha2-nistp384'
  | 'ecdsa-sha2-nistp521'
  | '+ssh-rsa'
  | '+ssh-dss';

export type ValidHostEntryMAC =
  | 'hmac-sha2-256-etm@openssh.com'
  | 'hmac-sha2-512-etm@openssh.com'
  | 'hmac-sha1-etm@openssh.com'
  | 'umac-64-etm@openssh.com'
  | 'umac-128-etm@openssh.com'
  | 'hmac-sha2-256'
  | 'hmac-sha2-512'
  | 'hmac-sha1'
  | 'umac-64@openssh.com'
  | 'umac-128@openssh.com'
  | 'hmac-ripemd160'
  | 'hmac-ripemd160@openssh.com'
  | 'hmac-sha1-96'
  | 'hmac-sha1-96-etm@openssh.com'
  | 'hmac-md5'
  | 'hmac-md5-96'
  | 'hmac-md5-etm@openssh.com'
  | 'hmac-md5-96-etm@openssh.com';

export type ValidHostEntryCiphers =
  | '3des-cbc'
  | 'aes128-cbc'
  | 'aes192-cbc'
  | 'aes256-cbc'
  | 'aes128-ctr'
  | 'aes192-ctr'
  | 'aes256-ctr'
  | 'aes128-gcm@openssh.com'
  | 'aes256-gcm@openssh.com'
  | 'chacha20-poly1305@openssh.com';

export type SSHHostRecord = {
  Host: string;
  Match?: string;
  AddressFamily?: 'any' | 'inet' | 'inet6';
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
  Ciphers?: ValidHostEntryCiphers[];
  ClearAllForwardings?: 'yes' | 'no';
  Compression?: 'yes' | 'no';
  CompressionLevel?: number;
  ConnectionAttempts?: number;
  ConnectTimeout?: number;
  ControlMaster?: 'auto' | 'autoask' | 'yes' | 'no';
  ControlPath?: string;
  ControlPersist?: number | 'yes' | 'no';
  DynamicForward?: string;
  EnableSSHKeysign?: 'yes' | 'no';
  EscapeChar?: string | number; // Allow both string and number
  ExitOnForwardFailure?: 'yes' | 'no';
  FingerprintHash?: 'md5' | 'sha256';
  ForwardAgent?: 'yes' | 'no';
  ForwardX11?: 'yes' | 'no';
  ForwardX11Timeout?: number;
  ForwardX11Trusted?: 'yes' | 'no';
  GatewayPorts?: 'yes' | 'no';
  GlobalKnownHostsFile?: string;
  GSSAPIAuthentication?: 'yes' | 'no';
  GSSAPIDelegateCredentials?: 'yes' | 'no';
  GSSAPIKeyExchange?: 'yes' | 'no';
  GSSAPIName?: string;
  GSSAPIServerIdentity?: string;
  GSSAPITrustDns?: 'yes' | 'no';
  HashKnownHosts?: 'yes' | 'no';
  HostbasedAuthentication?: 'yes' | 'no';
  HostbasedKeyTypes?: string;
  HostKeyAlgorithms?: ValidHostKeyAlgorithm[];
  HostKeyAlias?: string;
  HostName?: string;
  IdentitiesOnly?: 'yes' | 'no';
  IdentityAgent?: string;
  IdentityFile?: string;
  IgnoreUnknown?: string;
  Include?: string;
  IPQoS?: string;
  KbdInteractiveAuthentication?: 'yes' | 'no';
  KbdInteractiveDevices?: string;
  KexAlgorithms?: string;
  LocalCommand?: string;
  LocalForward?: string;
  LogLevel?: 'QUIET' | 'FATAL' | 'ERROR' | 'INFO' | 'VERBOSE' | 'DEBUG' | 'DEBUG1' | 'DEBUG2' | 'DEBUG3';
  MACs?: ValidHostEntryMAC[];
  NoHostAuthenticationForLocalhost?: 'yes' | 'no';
  NumberOfPasswordPrompts?: number;
  PasswordAuthentication?: 'yes' | 'no';
  PermitLocalCommand?: 'yes' | 'no';
  PermitRemoteOpen?: string;
  PKCS11Provider?: string;
  Port?: number;
  PreferredAuthentications?: string;
  ProxyCommand?: string;
  ProxyJump?: string;
  ProxyUseFdpass?: 'yes' | 'no';
  PubkeyAcceptedKeyTypes?: string;
  PubkeyAuthentication?: 'yes' | 'no';
  RekeyLimit?: string;
  RemoteCommand?: string;
  RemoteForward?: string;
  RequestTTY?: 'no' | 'yes' | 'force' | 'auto';
  RevokedHostKeys?: string;
  SendEnv?: string;
  ServerAliveCountMax?: number;
  ServerAliveInterval?: number;
  StreamLocalBindMask?: string;
  StreamLocalBindUnlink?: 'yes' | 'no';
  StrictHostKeyChecking?: 'yes' | 'no' | 'ask';
  SyslogFacility?: string;
  TCPKeepAlive?: 'yes' | 'no';
  Tunnel?: 'yes' | 'no' | 'point-to-point';
  TunnelDevice?: string;
  UpdateHostKeys?: 'yes' | 'no' | 'ask';
  UseKeychain?: 'yes' | 'no';
  User?: string;
  UserKnownHostsFile?: string;
  VerifyHostKeyDNS?: 'yes' | 'no' | 'ask';
  VisualHostKey?: 'yes' | 'no';
  XAuthLocation?: string;
};
