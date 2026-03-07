# Wraith

**Autonomous AI penetration testing framework** -- Claude agents vs enterprise environments.

Wraith maps Cobalt Strike's architecture to Claude AI agents. Instead of a human operator, Claude agents autonomously perform reconnaissance, exploit web vulnerabilities, attack Active Directory, move laterally, escalate privileges, and generate a pentest report -- all while the SOAR pipeline detects and responds in real time.

> Part of the YASHnet homelab SOAR project. Attack happens. System detects. System responds. No human in the loop.

---

## Architecture

```
CS Concept          Wraith Equivalent
-----------         -----------------
Team Server      -> Temporal Server (durable workflows, crash recovery)
Beacon           -> MCP tools (execute_command, log_attack, check_connectivity)
Aggressor Script -> Claude agent prompts (natural language instructions)
Malleable C2     -> YAML attack profiles (configs/*.yaml)
Post-exploitation -> 9-agent DAG (kerberoast, lateral, privesc)
Reporting        -> Report agent (MITRE-mapped pentest report)
GUI              -> CLI + Temporal Web UI
```

### Agent DAG

```
Phase 1:  recon
           |
Phase 2+3: sqli  cmdi  auth-attack  kerberoast  bruteforce  (parallel)
                                    |
Phase 4:                          lateral
                                    |
Phase 5:                          privesc
                                    |
Phase 6:                          report
```

### Stack

- **Claude Agent SDK** -- subscription auth, zero per-run API cost
- **Temporal** -- workflow orchestration, retry policies, Web UI at :8233
- **MCP stdio server** -- tools exposed to every Claude agent instance
- **Docker + Kali ARM64** -- attack tooling (Impacket, CrackMapExec, nmap, Hydra, Evil-WinRM)
- **TypeScript** throughout

---

## Target Environment

Built against a Proxmox homelab running YASHnet.local:

| Target | IP | Services |
|--------|----|---------|
| Win10 | 172.16.20.103 | DVWA (port 80), Juice Shop (port 3000) |
| Win11 | 172.16.20.104 | DVWA (port 80), Juice Shop (port 3000) |
| DC1 | 172.16.20.5 | YASHnet.local AD (BadBlood: 2501 users, 50 Kerberoastable SPNs) |
| Wazuh | 172.16.30.10 | SIEM -- 21 custom MITRE-mapped detection rules |

SOAR pipeline: `Wazuh -> n8n -> SOAR Response Server -> pfSense block + AD disable + TheHive + Discord`

---

## Wazuh Detection Coverage

| Phase | MITRE Technique | Expected Rules |
|-------|-----------------|---------------|
| Recon | T1046 Network Scan | 100190 |
| CmdI | T1059.003 Windows Cmd | 100170, 100171, 100210 |
| SQLi | T1190 Exploit Public App | 100221 |
| Kerberoast | T1558.003 | 100111 |
| AS-REP Roast | T1558.004 | 100110 |
| Pass-the-Hash | T1550.002 | 100120, 100121 |
| DCSync | T1003.006 | 100140 |
| Golden Ticket | T1558.001 | 100150 |

Level 12+ detections trigger SOAR: attacker IP blocked on pfSense, targeted AD account disabled, TheHive case created, Discord alert with case URL.

---

## Quick Start

```bash
# Prerequisites: Docker, Node.js 20+, Temporal dev server
git clone https://github.com/Cosmic-Arch69/wraith
cd wraith
cp .env.example .env  # add CLAUDE_CODE_OAUTH_TOKEN

npm install
npm run build

# Start Temporal + worker
docker compose up -d temporal
npm run worker

# Run a pentest
node dist/index.js run --config configs/yashnet-lab.yaml

# Monitor
node dist/index.js status --workflow-id <id>
node dist/index.js logs --follow
```

Temporal UI: `http://localhost:8233`

---

## Project Status

> **In active development.** Spring break 2026 (Mar 14-21) = main build window.

- [x] Phase 1: Foundation -- compiles, MCP wired, CLI, GitHub (Mar 7)
- [x] Phase 2: Complete all 9 agent prompts
- [ ] Phase 3: Docker boot + Temporal worker test
- [ ] Phase 4: Recon agent vs live lab
- [ ] Phase 5: Full kill chain end-to-end
- [ ] Phase 6: SOAR integration + detection coverage measurement
- [ ] Phase 7: Real-time attack dashboard (stretch)
- [ ] Phase 8: Full README + demo recording + LinkedIn

---

*Built by Yash (Jaswanth Reddy Gorantla) -- cybersecurity grad student, May 2026.*
