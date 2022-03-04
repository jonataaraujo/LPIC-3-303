# Overview
A certificação LPIC-3 Security é o culminar do programa de certificação profissional do Linux Professional Institute (LPI), é projetado para o nível empresarial Linux, LPIC-3 representa o mais alto nível de certificação.
Essa certificação abrange a administração de sistemas Linux em toda a empresa, com ênfase na segurança.


# Tópico 331 - Criptografia
## 331.1 - Certificados X.509 e infraestruturas de chave pública
Nesse tópico os candidatos devem compreender os certificados X.509 e infraestruturas de chave pública. Além disso, devem saber como configurar e usar o OpenSSL para implementar autoridades de certificação e emitir certificados SSL para vários fins.
> Peso 5

### Principais áreas de conhecimento:

- Entender os certificados X.509, ciclo de vida do certificado X.509, campos do certificado X.509 e extensões do certificado X.509v3
- Entender as cadeias de confiança e as infraestruturas de chave pública, incluindo a transparência dos certificados
- Gerar e gerenciar chaves públicas e privadas
- Criar, operar e proteger uma autoridade de certificação
- Solicitar, assinar e gerenciar certificados de servidor e cliente
- Revogar certificados e autoridades de certificação
- Conhecimento básico de recursos de Let's Encrypt, ACME e certbot
- Conhecimento básico de recursos do CFSSL

### Lista parcial dos arquivos, termos e utilitários usados:

- openssl (incluindo subcomandos relevantes)
- Configuração do OpenSSL
- PEM, DER, PKCS
- CSR
- CRL
- OCSPSP

## 331.2 Certificados X.509 para criptografia, assinatura e autenticação

Candidates should be able to use X.509 certificates for both server and client authentication. This includes implementing user and server authentication for Apache HTTPD. The version of Apache HTTPD covered is 2.4 or higher.
> Peso 4

### Principais áreas de conhecimento:

- Understand SSL, TLS, including protocol versions and ciphers
- Configure Apache HTTPD with mod_ssl to provide HTTPS service, including SNI and HSTS
- Configure Apache HTTPD with mod_ssl to serve certificate chains and adjust the cipher configuration (no cipher-specific knowledge)
- Configure Apache HTTPD with mod_ssl to authenticate users using certificates
- Configure Apache HTTPD with mod_ssl to provide OCSP stapling
- Use OpenSSL for SSL/TLS client and server tests

### Lista parcial dos arquivos, termos e utilitários usados:

- httpd.conf
- mod_ssl
- openssl (including relevant subcommands)
 
## 331.3 Encrypted File Systems - Peso 3

**Descrição:** Candidates should be able to set up and configure encrypted file systems.

### Principais áreas de conhecimento:
- Understand block device and file system encryption
- Use dm-crypt with LUKS1 to encrypt block devices
- Use eCryptfs to encrypt file systems, including home directories and PAM integration
- Awareness of plain dm-crypt
- Awareness of LUKS2 features
- Conceptual understanding of Clevis for LUKS devices and Clevis PINs for TMP2 and Network Bound Disk Encryption (NBDE)/Tang

### Lista parcial dos arquivos, termos e utilitários usados:

- cryptsetup (including relevant subcommands)
- cryptmount
- /etc/crypttab
- ecryptfsd
- ecryptfs-* commands
- mount.ecryptfs, umount.ecryptfs
- pam_ecryptfs
 
## 331.4 DNS and Cryptography - Peso 5

**Descrição:** Candidates should have experience and knowledge of cryptography in the context of DNS and its implementation using BIND. The version of BIND covered is 9.7 or higher.

### Principais áreas de conhecimento:

- Understand the concepts of DNS, zones and resource records
- Understand DNSSEC, including key signing keys, zone signing keys and relevant DNS records such as DS, DNSKEY, RRSIG, NSEC, NSEC3 and NSEC3PARAM
- Configure and troubleshoot BIND as an authoritative name server serving DNSSEC secured zones
- Manage DNSSEC signed zones, including key generation, key rollover and re-signing of zones
- Configure BIND as an recursive name server that performs DNSSEC validation on behalf of its clients
- Understand CAA and DANE, including relevant DNS records such as CAA and TLSA
- Use CAA and DANE to publish X.509 certificate and certificate authority information in DNS
- Use TSIG for secure communication with BIND
- Awareness of DNS over TLS and DNS over HTTPS
- Awareness of Multicast DNS

### Lista parcial dos arquivos, termos e utilitários usados:

- named.conf
- dnssec-keygen
- dnssec-signzone
- dnssec-settime
- dnssec-dsfromkey
- rndc (including relevant subcommands)
- dig
- delv
- openssl (including relevant subcommands)​

# Tópico 332: Host Security

## 332.1 Host Hardening - Peso 5

**Descrição:** Candidates should be able to secure computers running Linux against common threats.

### Principais áreas de conhecimento:

- Configure BIOS and boot loader (GRUB 2) security
- Disable unused software and services
- Understand and drop unnecessary capabilities for specific systemd units and the entire system
- Understand and configure Address Space Layout Randomization (ASLR), Data Execution Prevention (DEP) and Exec-Shield
- Black and white list USB devices attached to a computer using USBGuard
- Create an SSH CA, create SSH certificates for host and user keys using the CA and configure OpenSSH to use SSH certificates
- Work with chroot environments
- Use systemd units to limit the system calls and capabilities available to a process
- Use systemd units to start processes with limited or no access to specific files and devices
- Use systemd units to start processes with dedicated temporary and /dev directories and without network access
- Understand the implications of Linux Meltdown and Spectre mitigations and enable/disable the mitigations
- Awareness of polkit
- Awareness of the security advantages of virtualization and containerization

The following is a Lista parcial dos arquivos, termos e utilitários usados:

- grub.cfg
- systemctl
- getcap
- setcap
- capsh
- sysctl
- /etc/sysctl.conf
- /etc/usbguard/usbguard-daemon.conf
- /etc/usbguard/rules.conf
- usbguard
- ssh-keygen
- /etc/ssh/
- ~/.ssh/
- /etc/ssh/sshd_config
- chroot
 
## 332.2 Host Intrusion Detection - Peso 5

**Descrição:** Candidates should be familiar with the use and configuration of common host intrusion detection software. This includes managing the Linux Audit system and verifying a system's integrity.

Principais áreas de conhecimento:

- Use and configure the Linux Audit system
- Use chkrootkit
- Use and configure rkhunter, including updates
- Use Linux Malware Detect
- Automate host scans using cron
- Use RPM and DPKG package management tools to verify the integrity of installed files
- Configure and use AIDE, including rule management
- Awareness of OpenSCAP

Lista parcial dos arquivos, termos e utilitários usados:

- auditd
- auditctl
- ausearch, aureport
- auditd.conf
- audit.rules
- pam_tty_audit.so
- chkrootkit
- rkhunter
- /etc/rkhunter.conf
- maldet
- conf.maldet
- rpm
- dpkg
- aide
- /etc/aide/aide.conf
 
## 332.3 Resource Control - Peso 3

**Descrição:** Candidates should be able to restrict the resources services and programs can consume.

Principais áreas de conhecimento:

- Understand and configure ulimits
- Understand cgroups, including classes, limits and accounting
- Manage cgroups and process cgroup association
- Understand systemd slices, scopes and services
- Use systemd units to limit the system resources processes can consume
- Awareness of cgmanager and libcgroup utilities

Lista parcial dos arquivos, termos e utilitários usados:

- ulimit
- /etc/security/limits.conf
- pam_limits.so
- /sys/fs/group/
- /proc/cgroups
- systemd-cgls
- systemd-cgtop

# Tópico 333: Access Control

## 333.1 Discretionary Access Control - Peso 3

**Descrição:** Candidates should understand discretionary access control (DAC) and know how to implement it using access control lists (ACL). Additionally, candidates are required to understand and know how to use extended attributes.

Principais áreas de conhecimento:

- Understand and manage file ownership and permissions, including SetUID and SetGID bits
- Understand and manage access control lists
- Understand and manage extended attributes and attribute classes

Lista parcial dos arquivos, termos e utilitários usados:

- getfacl
- setfacl
- getfattr
- setfattr
 
## 333.2 Mandatory Access Control - Peso 5

**Descrição:** Candidates should be familiar with mandatory access control (MAC) systems for Linux. Specifically, candidates should have a thorough knowledge of SELinux. Also, candidates should be aware of other mandatory access control systems for Linux. This includes major features of these systems but not configuration and use.

Principais áreas de conhecimento:

- Understand the concepts of type enforcement, role based access control, mandatory access control and discretionary access control
- Configure, manage and use SELinux
- Awareness of AppArmor and Smack

Lista parcial dos arquivos, termos e utilitários usados:

- getenforce
- setenforce
- selinuxenabled
- getsebool
- setsebool
- togglesebool
- fixfiles
- restorecon
- setfiles
- newrole
- setcon
- runcon
- chcon
- semanage
- sestatus
- seinfo
- apol
- seaudit
- audit2why
- audit2allow
- /etc/selinux/*

# Tópico 334: Network Security

## 334.1 Network - Peso 4

**Descrição:** Candidates should be able to secure networks against common threats. This includes analyzing network traffic of specific nodes and protocols.

Principais áreas de conhecimento:

- Understand wireless networks security mechanisms
- Configure FreeRADIUS to authenticate network nodes
- Use Wireshark and tcpdump to analyze network traffic, including filters and statistics
- Use Kismet to analyze wireless networks and capture wireless network traffic
- Identify and deal with rogue router advertisements and DHCP messages
- Awareness of aircrack-ng and bettercap

Lista parcial dos arquivos, termos e utilitários usados:

- radiusd
- radmin
- radtest
- radclient
- radlast
- radwho
- radiusd.conf
- /etc/raddb/*
- wireshark
- tshark
- tcpdump
- kismet
- ndpmon
 
## 334.2 Network Intrusion Detection - Peso 4

**Descrição:** Candidates should be familiar with the use and configuration of network security scanning, network monitoring and network intrusion detection software. This includes updating and maintaining the security scanners.

Principais áreas de conhecimento:

- Implement bandwidth usage monitoring
- Configure and use Snort, including rule management
- Configure and use OpenVAS, including NASL

Lista parcial dos arquivos, termos e utilitários usados:

- ntop
- snort
- snort-stat
- pulledpork.pl
- /etc/snort/*
- openvas-adduser
- openvas-rmuser
- openvas-nvt-sync
- openvassd
- openvas-mkcert
- openvas-feed-update
- /etc/openvas/*
 

## 334.3 Packet Filtering - Peso: 5

**Descrição:** Candidates should be familiar with the use and configuration of the netfilter Linux packet filter.

Principais áreas de conhecimento:

- Understand common firewall architectures, including DMZ
- Understand and use iptables and ip6tables, including standard modules, tests and targets
- Implement packet filtering for IPv4 and IPv6
- Implement connection tracking and network address translation
- Manage IP sets and use them in netfilter rules
- Awareness of nftables and nft
- Awareness of ebtables
- Awareness of conntrackd

Lista parcial dos arquivos, termos e utilitários usados:

- iptables
- ip6tables
- iptables-save
- iptables-restore
- ip6tables-save
- ip6tables-restore
- ipset
 

## 334.4 Virtual Private Networks - Peso: 4

**Descrição:** Candidates should be familiar with the use of OpenVPN, IPsec and WireGuard to set up remote access and site to site VPNs.

Principais áreas de conhecimento:

- Understand the principles of bridged and routed VPNs
- Understand the principles and major differences of the OpenVPN, IPsec, IKEv2 and WireGuard protocols
- Configure and operate OpenVPN servers and clients
- Configure and operate IPsec servers and clients using strongSwan
- Configure and operate WireGuard servers and clients
- Awareness of L2TP

Lista parcial dos arquivos, termos e utilitários usados:

- /etc/openvpn/
- openvpn
- /etc/strongswan.conf
- /etc/strongswan.d/
- /etc/swanctl/swanctl.conf
- /etc/swanctl/
- swanctl
- /etc/wireguard/
- wg
- wg-quick
- ip

# Tópico 335: Threats and Vulnerability Assessment

## 335.1 Common Security Vulnerabilities and Threats - Peso: 2

**Descrição:** Candidates should understand the principle of major types of security vulnerabilities and threats.

Principais áreas de conhecimento:

- Conceptual understanding of threats against individual nodes
- Conceptual understanding of threats against networks
- Conceptual understanding of threats against application
- Conceptual understanding of threats against credentials and confidentiality
- Conceptual understanding of honeypots

Lista parcial dos arquivos, termos e utilitários usados:

- Trojans
- Viruses
- Rootkits
- Keylogger
- DoS and DDoS
- Man in the Middle
- ARP and NDP forgery
- Rogue Access Points, Routers and DHCP servers
- Link layer address and IP address spoofing
- Buffer Overflows
- SQL and Code Injections
- Cross Site Scripting
- Cross Site Request Forgery
- Privilege escalation
- Brute Force Attacks
- Rainbow tables
- Phishing
- Social Engineering
 

## 335.2 Penetration Testing - Peso: 3

**Descrição:** Candidates understand the concepts of penetration testing, including an understand of commonly used penetration testing tools. Furthermore, candidates should be able to use nmap to verify the effectiveness of network security measures.

Principais áreas de conhecimento:

- Understand the concepts of penetration testing and ethical hacking
- Understand legal implications of penetration testing
- Understand the phases of penetration tests, such as active and passive information gathering, enumeration, gaining access, privilege escalation, access maintenance, covering tracks
- Understand the architecture and components of Metasploit, including Metasploit module types and how Metasploit integrates various security tools
- Use nmap to scan networks and hosts, including different scan methods, version scans and operating system recognition
- Understand the concepts of Nmap Scripting Engine and execute existing scripts
- Awareness of Kali Linux, Armitage and the Social Engineer Toolkit (SET)

Lista parcial dos arquivos, termos e utilitários usados:

- nmap

## Links

- https://www.lpi.org/our-certifications/exam-303-objectives
