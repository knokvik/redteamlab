# DevRedTeam Lab v2

DevRedTeam is a Docker-first, AI-augmented red-team simulation lab that executes a full kill-chain assessment against any GitHub repository.

## What's New in v2

- **Multi-phase kill chain**: Recon → Enumeration → Vuln Scan → Exploitation → Post-Exploitation → Stress Test
- **20+ attack tools**: nmap, gobuster, ffuf, nikto, nuclei, sqlmap, hydra, metasploit, wfuzz, siege, hping3, sslscan, whatweb, wafw00f, dirb, testssl, and more
- **SecLists integration**: Industry-standard wordlists baked into the attacker container
- **LLM chain-of-thought**: Multi-turn conversation with behavioral feedback loop from observability
- **Full database probing**: PostgreSQL, MySQL, MongoDB, and Redis latency probes
- **30+ technology fingerprints**: Django, Flask, Spring Boot, Rails, Go, Laravel, Angular, Vue, Svelte, Nuxt, and more
- **CVSS v3.1 vectors**: Per-finding CWE classification with proper CVSS vector strings
- **Stress testing**: siege, Apache Bench, hping3 SYN flood, connection exhaustion
- **Dark-mode HTML reports**: Professional report with phase badges, attack surface intelligence, and structured findings

## Quick Start

```bash
cd /Users/nirajrajendranaphade/Programming/redteamlab/devredteam
pip install -r requirements.txt
python cli.py run https://github.com/knokvik/portfolio --aggressive
```

## Run Modes

```bash
# Safe mode (default) — skips stress test and post-exploitation
python cli.py run <repo-url> --safe

# Aggressive mode — full kill chain with stress testing
python cli.py run <repo-url> --aggressive

# Skip rebuild
python cli.py run <repo-url> --no-build
```

## Kill Chain Phases

| Phase | Tools | Description |
|-------|-------|-------------|
| Recon | nmap, whatweb, wafw00f, gobuster | Port scans, fingerprinting, WAF detection |
| Enumeration | ffuf, gobuster, dirb, curl | Endpoint fuzzing, API mapping |
| Vuln Scan | nuclei, nikto, sslscan | CVE checks, misconfigurations |
| Exploit | sqlmap, curl, nuclei, metasploit | SQLi, XSS, SSTI, RCE, LFI |
| Post-Exploit | curl, sqlmap, metasploit | Data exfil, priv esc, lateral movement |
| Stress Test | siege, ab, hping3 | Load testing, connection exhaustion |

## Report Output

Each run produces: `reports/<YYYYMMDD-HHMMSS>-<repo>/index.html`

Report includes:
- Hybrid CVSS score (base × 0.6 + behavior × 0.4)
- Structured findings with CWE IDs and CVSS v3.1 vectors
- Phase-by-phase attack timeline with per-attempt impact correlation
- Attack surface intelligence (discovered paths, ports, WAF, technologies)
- Live metrics charts (CPU, memory, DB latency, disk I/O)
- Before/after attack network graphs
- Prioritized remediation guidance

## Remote Ollama Setup

```bash
export OLLAMA_HOST=http://100.100.100.10:11434
export OLLAMA_MODEL=llama3.1:8b
```

Falls back to deterministic phase-specific payloads if LLM is unavailable.

## Monitoring URLs

- Target app: `http://localhost:5173` (or detected port)
- Grafana: `http://localhost:8000`
- Prometheus: `http://localhost:9090`
- cAdvisor: `http://localhost:8080`
- Loki API: `http://localhost:3100`
