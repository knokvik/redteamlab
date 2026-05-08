# DevRedTeam Lab

DevRedTeam is a Docker-first red-team simulation lab.

It keeps the original hardened foundation intact:
- private Docker network with static IPs
- isolated Kali attacker container
- Grafana + Loki + Prometheus + cAdvisor observability stack
- generated target services for cloned repos

## Quick Start

```bash
cd /Users/nirajrajendranaphade/Programming/redteamlab/devredteam
pip install -r requirements.txt
python cli.py run https://github.com/knokvik/portfolio
# or:
./run.sh https://github.com/knokvik/portfolio
```

## Run Modes

`safe` is default:

```bash
python cli.py run https://github.com/knokvik/portfolio --safe
```

Aggressive mode:

```bash
python cli.py run https://github.com/knokvik/portfolio --aggressive
```

Skip image rebuild when images already exist:

```bash
python cli.py run https://github.com/knokvik/portfolio --no-build
```

Both modes run the full flow:
1. clone repo
2. detect stack
3. generate merged compose
4. start attacker + target + monitoring
5. seed dummy DB data (if detected)
6. crawl target with Playwright
7. run attack loop with remote LLM suggestions (or deterministic fallback)
8. collect observability samples
9. generate HTML report and auto-open it

## Report Output

Each run writes a timestamped folder:

`reports/<YYYYMMDD-HHMMSS>-<repo-name>/index.html`

The report includes:
- run metadata
- attack timeline with `X-RedTeam-ID`
- observed impact (CPU/memory/log correlation)
- before/after attack graph
- hybrid CVSS score
- prioritized fix guidance

## Remote Ollama Setup

Set remote Ollama host (friend machine or Tailscale IP):

```bash
export OLLAMA_HOST=http://100.100.100.10:11434
export OLLAMA_MODEL=llama3.1:8b
```

If Ollama is unavailable or returns invalid JSON, DevRedTeam automatically falls back to deterministic localhost-safe attack suggestions so runs do not fail.

## Docker Buildx Permission Issue (Optional Local Repair)

If Docker fails with `buildx` + `operation not permitted`, run:

```bash
docker builder prune -af
rm -rf ~/.docker/buildx
python3 cli.py run https://github.com/knokvik/portfolio
```

If images were already built previously, you can bypass rebuild:

```bash
python3 cli.py run https://github.com/knokvik/portfolio --no-build
```

## Monitoring URLs

- Target app: `http://localhost:9700` (or generated app port such as `5173`)
- Grafana: `http://localhost:8000`
- Prometheus: `http://localhost:9090`
- cAdvisor: `http://localhost:8080`
- Loki API: `http://localhost:3100`

## Report Screenshot (Placeholder)

Add a screenshot here after a sample run:

`docs/report-screenshot.png`
