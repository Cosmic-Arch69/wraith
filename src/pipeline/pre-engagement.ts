// v3.7.0: Pre-engagement validation checks
// Runs before the pipeline to catch common issues that cause run failures

import { execSync } from 'node:child_process';
import type { WraithV3Config } from '../types/index.js';

export interface PreEngagementCheck {
  name: string;
  status: 'pass' | 'warn' | 'fail';
  message: string;
}

export interface PreEngagementResult {
  passed: boolean;
  checks: PreEngagementCheck[];
}

export async function runPreEngagementChecks(config: WraithV3Config): Promise<PreEngagementResult> {
  const checks: PreEngagementCheck[] = [];

  // 1. NTP sync check (Kerberos needs <5min skew)
  checks.push(checkNtpSync(config));

  // 2. Connectivity to targets
  checks.push(...checkConnectivity(config));

  // 3. Tool availability
  checks.push(checkToolAvailability());

  // 4. Disk space
  checks.push(checkDiskSpace(config.output.log_dir));

  const hasFail = checks.some(c => c.status === 'fail');
  return { passed: !hasFail, checks };
}

function checkNtpSync(config: WraithV3Config): PreEngagementCheck {
  const dc = config.target.dc;
  if (!dc) return { name: 'NTP sync', status: 'warn', message: 'No DC configured -- skipping NTP check' };

  try {
    // Try ntpdate query (non-destructive)
    const output = execSync(`ntpdate -q ${dc} 2>&1 | tail -1`, { timeout: 10000, encoding: 'utf-8' });
    const offsetMatch = output.match(/offset\s+(-?[\d.]+)/);
    if (offsetMatch) {
      const offset = Math.abs(parseFloat(offsetMatch[1]));
      if (offset > 300) {
        return { name: 'NTP sync', status: 'warn', message: `Clock offset ${offset.toFixed(0)}s from DC -- Kerberos attacks may fail (max 300s)` };
      }
      return { name: 'NTP sync', status: 'pass', message: `Clock offset ${offset.toFixed(1)}s from DC -- OK` };
    }
    return { name: 'NTP sync', status: 'warn', message: 'Could not determine NTP offset' };
  } catch {
    // ntpdate not available -- try timedatectl
    try {
      const output = execSync('timedatectl show --property=NTPSynchronized --value 2>/dev/null', { timeout: 5000, encoding: 'utf-8' });
      if (output.trim() === 'yes') {
        return { name: 'NTP sync', status: 'pass', message: 'System NTP synchronized' };
      }
      return { name: 'NTP sync', status: 'warn', message: 'System NTP not synchronized -- Kerberos attacks may fail' };
    } catch {
      return { name: 'NTP sync', status: 'warn', message: 'Cannot check NTP sync (ntpdate/timedatectl unavailable)' };
    }
  }
}

function checkConnectivity(config: WraithV3Config): PreEngagementCheck[] {
  const results: PreEngagementCheck[] = [];
  const targets: string[] = [];

  if (config.engagement?.type === 'external') {
    if (config.engagement.wan_ip) targets.push(config.engagement.wan_ip);
  } else {
    if (config.target.dc) targets.push(config.target.dc);
    for (const h of config.target.hosts) targets.push(h.ip);
  }

  for (const ip of targets) {
    try {
      execSync(`ping -c 1 -W 3 ${ip} 2>/dev/null`, { timeout: 10000, encoding: 'utf-8' });
      results.push({ name: `Connectivity ${ip}`, status: 'pass', message: `${ip} reachable` });
    } catch {
      results.push({ name: `Connectivity ${ip}`, status: 'fail', message: `${ip} unreachable -- cannot attack` });
    }
  }

  if (targets.length === 0) {
    results.push({ name: 'Connectivity', status: 'warn', message: 'No targets to check' });
  }

  return results;
}

function checkToolAvailability(): PreEngagementCheck {
  const required = ['nmap', 'sqlmap', 'hydra', 'john', 'nuclei', 'nxc'];
  const optional = ['hashcat', 'kerbrute', 'bloodhound-python', 'smbclient', 'rpcclient', 'ldapsearch'];
  const missing: string[] = [];
  const missingOptional: string[] = [];

  const expandedEnv = { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` };

  for (const tool of required) {
    try {
      execSync(`which ${tool} 2>/dev/null`, { timeout: 5000, encoding: 'utf-8', env: expandedEnv });
    } catch {
      missing.push(tool);
    }
  }

  for (const tool of optional) {
    try {
      execSync(`which ${tool} 2>/dev/null`, { timeout: 5000, encoding: 'utf-8', env: expandedEnv });
    } catch {
      missingOptional.push(tool);
    }
  }

  if (missing.length > 0) {
    return { name: 'Tools', status: 'fail', message: `Missing required tools: ${missing.join(', ')}` };
  }
  if (missingOptional.length > 0) {
    return { name: 'Tools', status: 'warn', message: `Missing optional tools: ${missingOptional.join(', ')}. Some attacks may be limited.` };
  }
  return { name: 'Tools', status: 'pass', message: `All ${required.length + optional.length} tools available` };
}

function checkDiskSpace(logDir: string): PreEngagementCheck {
  try {
    const output = execSync(`df -BM "${logDir}" 2>/dev/null | tail -1`, { timeout: 5000, encoding: 'utf-8' });
    const parts = output.trim().split(/\s+/);
    const availMB = parseInt(parts[3]?.replace('M', '') ?? '0', 10);
    if (availMB < 1024) {
      return { name: 'Disk space', status: 'warn', message: `Only ${availMB}MB available in ${logDir} -- may run out during long runs` };
    }
    return { name: 'Disk space', status: 'pass', message: `${availMB}MB available` };
  } catch {
    return { name: 'Disk space', status: 'warn', message: 'Could not check disk space' };
  }
}

export function printPreEngagementResults(result: PreEngagementResult): void {
  console.log('\n  Pre-engagement checks:');
  for (const check of result.checks) {
    const icon = check.status === 'pass' ? 'OK' : check.status === 'warn' ? 'WARN' : 'FAIL';
    console.log(`    [${icon}] ${check.name}: ${check.message}`);
  }
  console.log('');
}
