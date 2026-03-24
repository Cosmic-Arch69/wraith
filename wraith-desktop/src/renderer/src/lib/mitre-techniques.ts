// Official MITRE ATT&CK Enterprise technique names
// Source: https://attack.mitre.org/techniques/enterprise/
// Used to enrich heatmap cells with proper names when the API returns only IDs

export const TECHNIQUE_NAMES: Record<string, string> = {
  // Reconnaissance
  'T1595': 'Active Scanning',
  'T1595.001': 'Scanning IP Blocks',
  'T1595.002': 'Vulnerability Scanning',
  'T1595.003': 'Wordlist Scanning',
  'T1592': 'Gather Victim Host Information',
  'T1592.001': 'Hardware',
  'T1592.002': 'Software',
  'T1592.003': 'Firmware',
  'T1592.004': 'Client Configurations',
  'T1590': 'Gather Victim Network Information',
  'T1590.001': 'Domain Properties',
  'T1590.002': 'DNS',
  'T1590.004': 'Network Topology',
  'T1590.006': 'Network Security Appliances',
  'T1591': 'Gather Victim Org Information',
  'T1589': 'Gather Victim Identity Information',
  'T1046': 'Network Service Discovery',
  'T1018': 'Remote System Discovery',
  'T1016': 'System Network Configuration Discovery',

  // Initial Access
  'T1190': 'Exploit Public-Facing Application',
  'T1133': 'External Remote Services',
  'T1200': 'Hardware Additions',
  'T1078': 'Valid Accounts',
  'T1078.001': 'Default Accounts',
  'T1078.002': 'Domain Accounts',
  'T1078.003': 'Local Accounts',
  'T1078.004': 'Cloud Accounts',
  'T1189': 'Drive-by Compromise',
  'T1566': 'Phishing',

  // Execution
  'T1059': 'Command and Scripting Interpreter',
  'T1059.001': 'PowerShell',
  'T1059.003': 'Windows Command Shell',
  'T1059.004': 'Unix Shell',
  'T1059.005': 'Visual Basic',
  'T1059.006': 'Python',
  'T1047': 'Windows Management Instrumentation',
  'T1053': 'Scheduled Task/Job',
  'T1053.005': 'Scheduled Task',
  'T1569': 'System Services',

  // Persistence
  'T1098': 'Account Manipulation',
  'T1136': 'Create Account',
  'T1547': 'Boot or Logon Autostart Execution',
  'T1543': 'Create or Modify System Process',

  // Privilege Escalation
  'T1068': 'Exploitation for Privilege Escalation',
  'T1548': 'Abuse Elevation Control Mechanism',
  'T1134': 'Access Token Manipulation',
  'T1134.001': 'Token Impersonation/Theft',
  'T1134.002': 'Create Process with Token',

  // Defense Evasion
  'T1562': 'Impair Defenses',
  'T1562.001': 'Disable or Modify Tools',
  'T1562.002': 'Disable Windows Event Logging',
  'T1070': 'Indicator Removal',
  'T1036': 'Masquerading',
  'T1027': 'Obfuscated Files or Information',

  // Credential Access
  'T1110': 'Brute Force',
  'T1110.001': 'Password Guessing',
  'T1110.002': 'Password Cracking',
  'T1110.003': 'Password Spraying',
  'T1110.004': 'Credential Stuffing',
  'T1003': 'OS Credential Dumping',
  'T1003.001': 'LSASS Memory',
  'T1003.002': 'Security Account Manager',
  'T1003.003': 'NTDS',
  'T1003.004': 'LSA Secrets',
  'T1003.005': 'Cached Domain Credentials',
  'T1003.006': 'DCSync',
  'T1558': 'Steal or Forge Kerberos Tickets',
  'T1558.001': 'Golden Ticket',
  'T1558.003': 'Kerberoasting',
  'T1558.004': 'AS-REP Roasting',
  'T1187': 'Forced Authentication',
  'T1552': 'Unsecured Credentials',
  'T1552.001': 'Credentials In Files',
  'T1552.006': 'Group Policy Preferences',
  'T1555': 'Credentials from Password Stores',
  'T1555.001': 'Keychain',
  'T1555.003': 'Credentials from Web Browsers',
  'T1649': 'Steal or Forge Authentication Certificates',

  // Discovery
  'T1087': 'Account Discovery',
  'T1087.001': 'Local Account',
  'T1087.002': 'Domain Account',
  'T1069': 'Permission Groups Discovery',
  'T1135': 'Network Share Discovery',
  'T1201': 'Password Policy Discovery',
  'T1526': 'Cloud Service Discovery',
  'T1482': 'Domain Trust Discovery',
  'T1615': 'Group Policy Discovery',

  // Lateral Movement
  'T1021': 'Remote Services',
  'T1021.001': 'Remote Desktop Protocol',
  'T1021.002': 'SMB/Windows Admin Shares',
  'T1021.003': 'Distributed Component Object Model',
  'T1021.004': 'SSH',
  'T1021.006': 'Windows Remote Management',
  'T1550': 'Use Alternate Authentication Material',
  'T1550.002': 'Pass the Hash',
  'T1550.003': 'Pass the Ticket',
  'T1090': 'Proxy',
  'T1090.001': 'Internal Proxy',

  // Collection
  'T1005': 'Data from Local System',
  'T1560': 'Archive Collected Data',
  'T1114': 'Email Collection',
  'T1056': 'Input Capture',

  // Command and Control
  'T1071': 'Application Layer Protocol',
  'T1572': 'Protocol Tunneling',
  'T1105': 'Ingress Tool Transfer',
  'T1571': 'Non-Standard Port',

  // Exfiltration
  'T1041': 'Exfiltration Over C2 Channel',
  'T1048': 'Exfiltration Over Alternative Protocol',
  'T1567': 'Exfiltration Over Web Service',

  // Impact
  'T1486': 'Data Encrypted for Impact',
  'T1489': 'Service Stop',
  'T1529': 'System Shutdown/Reboot',
  'T1531': 'Account Access Removal',
  'T1485': 'Data Destruction',
}

// Get the official name for a technique ID, fallback to the ID itself
export function getTechniqueName(id: string): string {
  return TECHNIQUE_NAMES[id] || id
}

// Get a brief description for hover tooltips
export function getTechniqueDescription(id: string): string {
  const DESCRIPTIONS: Record<string, string> = {
    'T1003.006': 'Abuse domain controller replication to extract credential data (NTLM hashes, Kerberos keys) from Active Directory via the Directory Replication Service (DRS) protocol.',
    'T1558.001': 'Forge Kerberos ticket-granting tickets (TGTs) using the krbtgt account hash, enabling unrestricted access to any resource in the domain.',
    'T1558.003': 'Extract service account credentials by requesting Kerberos service tickets (TGS) for accounts with SPNs, then cracking them offline.',
    'T1558.004': 'Target accounts without Kerberos pre-authentication to request encrypted tickets that can be cracked offline.',
    'T1003.001': 'Dump credentials from the Local Security Authority Subsystem Service (LSASS) process memory.',
    'T1003.002': 'Extract credential material from the Security Account Manager (SAM) database.',
    'T1003.003': 'Extract credential material from the Active Directory NTDS.dit database file.',
    'T1110.003': 'Attempt a single password against many accounts simultaneously to avoid account lockouts.',
    'T1110.001': 'Systematically guess passwords for a single user account.',
    'T1190': 'Exploit vulnerabilities in internet-facing applications (web servers, APIs) to gain initial access.',
    'T1550.002': 'Authenticate to remote services using stolen NTLM password hashes without cracking them.',
    'T1021.002': 'Move laterally using SMB and Windows administrative shares (C$, ADMIN$, IPC$).',
    'T1021.006': 'Execute commands on remote systems via Windows Remote Management (WinRM).',
    'T1021.001': 'Connect to remote systems via Remote Desktop Protocol for interactive access.',
    'T1046': 'Scan network ports and services to identify targets, open ports, and running services.',
    'T1562.001': 'Disable or modify security tools and monitoring to avoid detection.',
    'T1187': 'Force NTLM authentication to capture credential hashes via protocols like SMB, WebDAV.',
    'T1087.002': 'Enumerate domain user accounts using LDAP queries, net commands, or PowerShell.',
  }
  return DESCRIPTIONS[id] || `MITRE ATT&CK Technique ${id}`
}
