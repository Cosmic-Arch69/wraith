// Automated nuclei CVE/misconfig scanning -- no LLM needed
// Runs between RECON and ONTOLOGY phases
// v3.1.0: Stream F -- fast, comprehensive vulnerability detection

import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { AttackGraphService } from '../services/attack-graph.js';

interface NucleiResult {
  'template-id': string;
  info: {
    name: string;
    severity: string;
    description?: string;
    reference?: string[];
    tags?: string[];
  };
  'matched-at'?: string;
  host?: string;
  type?: string;
}

export class NucleiScanner {
  async scan(
    targets: string[],
    logDir: string,
    graphService: AttackGraphService,
  ): Promise<number> {
    let totalFindings = 0;

    for (const target of targets) {
      console.log(`[nuclei] Scanning ${target}...`);
      const safeTarget = target.replace(/[^a-zA-Z0-9._:-]/g, '_');
      const outputPath = join(logDir, `nuclei-${safeTarget}.json`);

      try {
        execSync(
          `nuclei -u "${target}" -t cves/ -t default-logins/ -t misconfigurations/ -severity critical,high,medium -json -o "${outputPath}" 2>/dev/null`,
          { timeout: 120_000, encoding: 'utf-8' },
        );
      } catch {
        // nuclei returns non-zero when it finds vulnerabilities -- normal
      }

      const findings = this.parseResults(outputPath);
      totalFindings += findings.length;

      // Update graph with CVE vectors
      for (const finding of findings) {
        const ip = this.extractIP(finding.host ?? finding['matched-at'] ?? target);
        if (ip) {
          graphService.initNode(ip, ip);
          graphService.updateNode(ip, {
            vectors_open: [`cve-${finding['template-id']}`],
            notes: [`[nuclei] ${finding.info.severity}: ${finding.info.name}`],
          });
        }
      }

      if (findings.length > 0) {
        this.writeEvidence(findings, logDir, target);
      }

      console.log(`[nuclei] ${target}: ${findings.length} findings`);
    }

    return totalFindings;
  }

  private parseResults(outputPath: string): NucleiResult[] {
    if (!existsSync(outputPath)) return [];
    try {
      const content = readFileSync(outputPath, 'utf-8').trim();
      if (!content) return [];
      return content
        .split('\n')
        .filter(Boolean)
        .map(line => { try { return JSON.parse(line); } catch { return null; } })
        .filter((r): r is NucleiResult => r !== null);
    } catch {
      return [];
    }
  }

  private writeEvidence(findings: NucleiResult[], logDir: string, target: string): void {
    const critical = findings.filter(f => f.info.severity === 'critical');
    const high = findings.filter(f => f.info.severity === 'high');
    const medium = findings.filter(f => f.info.severity === 'medium');

    const lines = [
      `# Nuclei Scan Results -- ${target}`,
      ``,
      `Total: ${findings.length} findings (${critical.length} critical, ${high.length} high, ${medium.length} medium)`,
      ``,
    ];

    const format = (items: NucleiResult[], label: string) => {
      if (items.length === 0) return;
      lines.push(`## ${label}`);
      for (const f of items) {
        lines.push(`- **${f['template-id']}**: ${f.info.name}`);
        lines.push(`  URL: ${f['matched-at'] ?? f.host ?? 'unknown'}`);
        if (f.info.description) lines.push(`  Description: ${f.info.description.substring(0, 200)}`);
        lines.push('');
      }
    };

    format(critical, 'Critical');
    format(high, 'High');
    format(medium, 'Medium');

    const evidencePath = join(logDir, 'nuclei_evidence.md');
    const content = existsSync(evidencePath)
      ? readFileSync(evidencePath, 'utf-8') + '\n---\n\n' + lines.join('\n')
      : lines.join('\n');
    writeFileSync(evidencePath, content);
  }

  private extractIP(url: string): string | null {
    const match = url.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    return match?.[1] ?? null;
  }
}
