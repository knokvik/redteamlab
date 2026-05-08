# DevRedTeam Docker Foundation

This step builds only the Docker foundation by cleanly recreating Docker patterns from:

- `oliverwiegers/pentest_lab`
- `dinosn/pack2theroot-lab`
- `anpa1200/AuditAI`

## Included patterns

- Private Docker bridge network with static IPs for attacker, target, and monitoring stack
- Merged single `docker-compose.yml` with attacker + target + Grafana/Loki/Prometheus/cAdvisor
- Kali-based isolated attacker container
- Hardened attacker runtime (`read_only`, `cap_drop`, minimal `cap_add`, `no-new-privileges`, non-root user)
- Loki Docker logging driver usage for centralized logs
- Persistent volumes and host port mappings where needed
- One-command startup script
- Python orchestrator using Docker SDK to start/verify attacker and test target reachability

## Folder structure

```text
devredteam/
├── docker/
│   ├── docker-compose.yml
│   ├── attacker/
│   │   └── Dockerfile
│   ├── monitoring/
│   │   ├── loki/
│   │   ├── prometheus/
│   │   └── grafana/
│   └── services/
├── core/
│   └── orchestrator.py
├── scripts/
│   └── start_lab.sh
├── requirements.txt
└── README.md
```

## Run

```bash
./scripts/start_lab.sh
```

## Access

- Target app: `http://localhost:9700`
- Grafana: `http://localhost:8000`
- Prometheus: `http://localhost:9090`
- cAdvisor: `http://localhost:8080`
- Loki API: `http://localhost:3100`

## Notes

- This is intentionally limited to Docker foundation only.
- No cloning/orchestration of arbitrary GitHub apps, no LLM attack logic, and no reporting pipeline are added in this step.
