// Credential Store -- in-memory store with JSON file persistence
// Part of Wraith v2.1 Feature F2

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Credential, CredentialScope } from '../types/index.js';
import { eventBus } from '../api/event-emitter.js';

function makeId(username: string, password?: string, hash?: string): string {
  return Buffer.from(username + (password ?? hash ?? '')).toString('base64').slice(0, 16);
}

export class CredentialStore {
  private readonly filePath: string;
  private creds: Map<string, Credential> = new Map();

  constructor(logDir: string) {
    mkdirSync(logDir, { recursive: true });
    this.filePath = join(logDir, 'credentials.json');
    if (existsSync(this.filePath)) {
      try {
        const raw = readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw) as Credential[];
        for (const cred of parsed) {
          this.creds.set(cred.id, cred);
        }
      } catch {
        // Corrupted file -- start fresh
      }
    }
  }

  add(cred: Omit<Credential, 'id' | 'discovered_at'>): Credential {
    const id = makeId(cred.username, cred.password, cred.hash);

    // v3.7.0 BUG-20: Check for existing entry with same username (different password/hash variant)
    const existingByUsername = this.findByUsername(cred.username, cred.scope);
    const existing = this.creds.get(id) ?? existingByUsername;

    if (existing) {
      // Merge: combine password + hash + hosts + protocols into one entry
      const merged: Credential = {
        ...existing,
        password: existing.password ?? cred.password,
        hash: existing.hash ?? cred.hash,
        hosts_valid: Array.from(new Set([...existing.hosts_valid, ...cred.hosts_valid])),
        hosts_failed: Array.from(new Set([...existing.hosts_failed, ...cred.hosts_failed])),
        protocol_valid: Array.from(new Set([...existing.protocol_valid, ...cred.protocol_valid])),
        protocol_failed: Array.from(new Set([...existing.protocol_failed, ...cred.protocol_failed])),
      };
      // If merged into a username-matched entry (different id), remove old id entry
      if (existingByUsername && !this.creds.has(id)) {
        this.creds.delete(existingByUsername.id);
        merged.id = existingByUsername.id;
      }
      this.creds.set(merged.id, merged);
      this.persist();
      return merged;
    }

    const newCred: Credential = {
      ...cred,
      id,
      discovered_at: new Date().toISOString(),
    };
    this.creds.set(id, newCred);
    this.persist();
    eventBus.emit('credential:discovered', { username: newCred.username, scope: newCred.scope, source: newCred.source });
    return newCred;
  }

  // v3.7.0 BUG-20: Find existing credential by username + scope to merge variants
  private findByUsername(username: string, scope: CredentialScope): Credential | undefined {
    for (const cred of this.creds.values()) {
      if (cred.username === username && cred.scope === scope) return cred;
    }
    return undefined;
  }

  query(filters: {
    protocol?: string;
    host?: string;
    scope?: CredentialScope;
    untested_for_host?: string;
    untested_for_protocol?: string;
  }): Credential[] {
    let results = Array.from(this.creds.values());

    if (filters.scope !== undefined) {
      results = results.filter(c => c.scope === filters.scope);
    }

    if (filters.host !== undefined) {
      const h = filters.host;
      results = results.filter(
        c => c.hosts_valid.includes(h) || c.hosts_failed.includes(h),
      );
    }

    if (filters.protocol !== undefined) {
      const p = filters.protocol;
      results = results.filter(
        c => c.protocol_valid.includes(p) || c.protocol_failed.includes(p),
      );
    }

    if (filters.untested_for_host !== undefined) {
      const h = filters.untested_for_host;
      results = results.filter(
        c => !c.hosts_valid.includes(h) && !c.hosts_failed.includes(h),
      );
    }

    if (filters.untested_for_protocol !== undefined) {
      const p = filters.untested_for_protocol;
      results = results.filter(
        c => !c.protocol_valid.includes(p) && !c.protocol_failed.includes(p),
      );
    }

    return results;
  }

  markTested(id: string, host: string, protocol: string, success: boolean): void {
    const cred = this.creds.get(id);
    if (!cred) return;

    if (success) {
      if (!cred.hosts_valid.includes(host)) cred.hosts_valid.push(host);
      if (!cred.protocol_valid.includes(protocol)) cred.protocol_valid.push(protocol);
      // Remove from failed if previously recorded
      cred.hosts_failed = cred.hosts_failed.filter(h => h !== host);
      cred.protocol_failed = cred.protocol_failed.filter(p => p !== protocol);
    } else {
      if (!cred.hosts_failed.includes(host)) cred.hosts_failed.push(host);
      if (!cred.protocol_failed.includes(protocol)) cred.protocol_failed.push(protocol);
    }

    this.persist();
  }

  getAll(): Credential[] {
    return Array.from(this.creds.values());
  }

  toJSON(): string {
    return JSON.stringify(Array.from(this.creds.values()), null, 2);
  }

  getStats(): { total: number; by_scope: Record<string, number>; cracked: number } {
    const all = this.getAll();
    const by_scope: Record<string, number> = {};
    let cracked = 0;

    for (const cred of all) {
      by_scope[cred.scope] = (by_scope[cred.scope] ?? 0) + 1;
      if (cred.password !== undefined) cracked++;
    }

    return { total: all.length, by_scope, cracked };
  }

  private persist(): void {
    writeFileSync(this.filePath, this.toJSON(), 'utf-8');
  }
}
