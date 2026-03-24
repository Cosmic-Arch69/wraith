// v3.8.0: HTTP server for Wraith Console
// SSE endpoint streams events from the pipeline event bus
// REST endpoints serve run data from logDir files

import express from 'express';
import cors from 'cors';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { eventBus } from './event-emitter.js';
import type { SSEEvent } from './types.js';
import type http from 'node:http';

export interface PipelineState {
  version: string;
  phase: string;
  currentRound: number;
  maxRounds: number;
  agentsSpawned: number;
  maxAgents: number;
  startedAt: string;
  config: Record<string, unknown>;
}

export function startApiServer(
  logDir: string,
  port: number,
  state: PipelineState,
): http.Server {
  const app = express();
  app.use(cors());
  app.use(express.json());

  // Helper: read JSON file from logDir
  function readJsonFile(filename: string): unknown {
    const p = join(logDir, filename);
    if (!existsSync(p)) return null;
    try {
      return JSON.parse(readFileSync(p, 'utf-8'));
    } catch {
      return null;
    }
  }

  // Helper: read JSONL file as array
  function readJsonlFile(filename: string): unknown[] {
    const p = join(logDir, filename);
    if (!existsSync(p)) return [];
    try {
      return readFileSync(p, 'utf-8')
        .trim()
        .split('\n')
        .filter(Boolean)
        .map(line => JSON.parse(line));
    } catch {
      return [];
    }
  }

  // ---- SSE Endpoint ----
  app.get('/api/events', (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    });

    // Send initial connection event
    res.write(`data: ${JSON.stringify({ type: 'connected', timestamp: new Date().toISOString(), data: { phase: state.phase } })}\n\n`);

    const handler = (event: SSEEvent) => {
      try {
        res.write(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
      } catch {
        // Client disconnected
      }
    };

    eventBus.on('*', handler);

    req.on('close', () => {
      eventBus.off('*', handler);
    });
  });

  // ---- REST Endpoints ----

  // Pipeline status
  app.get('/api/engagement', (_req, res) => {
    res.json({
      version: state.version,
      state: state.phase,
      currentRound: state.currentRound,
      maxRounds: state.maxRounds,
      agentsSpawned: state.agentsSpawned,
      maxAgents: state.maxAgents,
      startedAt: state.startedAt,
      elapsedMs: Date.now() - new Date(state.startedAt).getTime(),
      config: state.config,
    });
  });

  // Attack graph
  app.get('/api/graph', (_req, res) => {
    const graph = readJsonFile('attack-graph.json');
    if (!graph) return res.status(404).json({ error: 'No graph data yet' });
    res.json(graph);
  });

  // Attack events
  app.get('/api/attacks', (_req, res) => {
    res.json(readJsonlFile('attacks.jsonl'));
  });

  // Attack stats (computed)
  app.get('/api/attacks/stats', (_req, res) => {
    const attacks = readJsonlFile('attacks.jsonl') as Array<{
      result: string;
      technique: string;
      phase: string;
    }>;

    const stats = {
      totalAttempted: 0,
      totalSucceeded: 0,
      totalFailed: 0,
      totalBlocked: 0,
      totalSkipped: 0,
      soarDetectionRate: 0,
      byTechnique: {} as Record<string, { attempts: number; successes: number; blocks: number }>,
      byPhase: {} as Record<string, { attempts: number; successes: number }>,
    };

    for (const a of attacks) {
      if (a.result === 'skipped' || a.result === 'pending') {
        stats.totalSkipped++;
        continue;
      }
      stats.totalAttempted++;
      if (a.result === 'success') stats.totalSucceeded++;
      else if (a.result === 'failed') stats.totalFailed++;
      else if (a.result === 'blocked') stats.totalBlocked++;

      // By technique
      if (!stats.byTechnique[a.technique]) {
        stats.byTechnique[a.technique] = { attempts: 0, successes: 0, blocks: 0 };
      }
      stats.byTechnique[a.technique].attempts++;
      if (a.result === 'success') stats.byTechnique[a.technique].successes++;
      if (a.result === 'blocked') stats.byTechnique[a.technique].blocks++;

      // By phase
      if (!stats.byPhase[a.phase]) {
        stats.byPhase[a.phase] = { attempts: 0, successes: 0 };
      }
      stats.byPhase[a.phase].attempts++;
      if (a.result === 'success') stats.byPhase[a.phase].successes++;
    }

    stats.soarDetectionRate = stats.totalAttempted > 0
      ? stats.totalBlocked / stats.totalAttempted
      : 0;

    res.json(stats);
  });

  // Round history
  app.get('/api/rounds', (_req, res) => {
    const rounds = readJsonFile('round_history.json');
    if (!rounds) return res.status(404).json({ error: 'No round data yet' });
    res.json(rounds);
  });

  // Credentials
  app.get('/api/credentials', (_req, res) => {
    const creds = readJsonFile('credentials.json');
    res.json(creds ?? []);
  });

  // Ontology
  app.get('/api/ontology', (_req, res) => {
    const ontology = readJsonFile('ontology.json');
    if (!ontology) return res.status(404).json({ error: 'No ontology data yet' });
    res.json(ontology);
  });

  // MITRE heatmap
  app.get('/api/mitre-heatmap', (_req, res) => {
    const heatmap = readJsonFile('mitre-heatmap.json');
    if (!heatmap) return res.status(404).json({ error: 'No heatmap data yet' });
    res.json(heatmap);
  });

  // Agent output
  app.get('/api/agents/:id/output', (req, res) => {
    const filename = `agent-${req.params.id}-output.md`;
    const p = join(logDir, filename);
    if (!existsSync(p)) return res.status(404).json({ error: 'Agent output not found' });
    res.type('text/markdown').send(readFileSync(p, 'utf-8'));
  });

  // List all agent outputs
  app.get('/api/agents', (_req, res) => {
    try {
      const files = readdirSync(logDir).filter(f => f.startsWith('agent-') && f.endsWith('-output.md'));
      const agents = files.map(f => {
        const id = f.replace('agent-', '').replace('-output.md', '');
        const content = readFileSync(join(logDir, f), 'utf-8');
        // Parse header fields
        const lines = content.split('\n');
        const template = lines.find(l => l.startsWith('Template:'))?.split(': ')[1] ?? '';
        const target = lines.find(l => l.startsWith('Target:'))?.split(': ')[1] ?? '';
        const turns = parseInt(lines.find(l => l.startsWith('Turns:'))?.split(': ')[1] ?? '0', 10);
        const success = lines.find(l => l.startsWith('Success:'))?.split(': ')[1] === 'true';
        const duration = lines.find(l => l.startsWith('Duration:'))?.split(': ')[1] ?? '0ms';
        return { id, template, target, turns, success, duration };
      });
      res.json(agents);
    } catch {
      res.json([]);
    }
  });

  // Pentest report
  app.get('/api/report', (_req, res) => {
    const p = join(logDir, 'pentest_report.md');
    if (!existsSync(p)) return res.status(404).json({ error: 'Report not generated yet' });
    res.type('text/markdown').send(readFileSync(p, 'utf-8'));
  });

  // Findings (parsed from mitre-heatmap + attacks)
  app.get('/api/findings', (_req, res) => {
    const heatmap = readJsonFile('mitre-heatmap.json') as {
      techniques?: Array<{
        id: string;
        name: string;
        attempts: number;
        successes: number;
        severity: string;
        remediation: string;
      }>;
    } | null;

    if (!heatmap?.techniques) return res.json([]);

    const findings = heatmap.techniques
      .filter(t => t.successes > 0)
      .map((t, i) => ({
        id: `F-${String(i + 1).padStart(3, '0')}`,
        title: `${t.name} (${t.id})`,
        severity: t.severity,
        technique: t.id,
        techniqueName: t.name,
        attempts: t.attempts,
        successes: t.successes,
        remediation: t.remediation,
      }))
      .sort((a, b) => {
        const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };
        return (order[a.severity as keyof typeof order] ?? 5) - (order[b.severity as keyof typeof order] ?? 5);
      });

    res.json(findings);
  });

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', logDir, uptime: process.uptime() });
  });

  const server = app.listen(port, '0.0.0.0', () => {
    console.log(`  [api] Console API server on http://0.0.0.0:${port}`);
  });

  // Update state from event bus
  eventBus.on('pipeline:phase', (event: SSEEvent) => {
    const data = event.data as { phase: string };
    state.phase = data.phase;
  });
  eventBus.on('round:start', (event: SSEEvent) => {
    const data = event.data as { round: number };
    state.currentRound = data.round;
  });
  eventBus.on('agent:spawn', () => {
    state.agentsSpawned++;
  });

  return server;
}
