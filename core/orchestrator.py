"""Start Docker compose stacks and verify attacker connectivity to victim services."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

import docker
import yaml
from rich.console import Console
from rich.table import Table

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start lab services and verify attacker connectivity.")
    parser.add_argument(
        "--compose-files",
        nargs="+",
        default=[str(Path(__file__).resolve().parents[1] / "docker" / "docker-compose.yml")],
        help="One or more compose files (later files override earlier files).",
    )
    parser.add_argument("--project-name", default="devredteam", help="Docker Compose project name")
    parser.add_argument(
        "--skip-compose-up",
        action="store_true",
        help="Skip docker compose up and only run Docker SDK checks/start on existing containers.",
    )
    return parser.parse_args()


def load_compose(compose_file: Path) -> Dict:
    with compose_file.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def merge_service_views(compose_files: List[Path]) -> Dict:
    merged: Dict = {"services": {}}
    for compose_file in compose_files:
        doc = load_compose(compose_file)
        merged["services"].update(doc.get("services", {}))
    return merged


def resolve_container_name(project: str, service_name: str, service_cfg: Dict) -> str:
    explicit = service_cfg.get("container_name")
    if explicit:
        return explicit
    return f"{project}-{service_name}-1"


def compose_up(compose_files: List[Path], project_name: str) -> None:
    console.print("[bold cyan]Bringing up lab stack with docker compose...[/bold cyan]")

    cmd = ["docker", "compose", "-p", project_name]
    for compose_file in compose_files:
        cmd.extend(["-f", str(compose_file)])
    cmd.extend(["up", "-d", "--build", "--remove-orphans"])

    subprocess.run(cmd, check=True)


def ensure_running(client: docker.DockerClient, container_name: str) -> docker.models.containers.Container:
    container = client.containers.get(container_name)
    if container.status != "running":
        console.print(f"[yellow]Starting stopped container:[/yellow] {container_name}")
        container.start()
    container.reload()
    return container


def discover_targets(services: Dict) -> List[str]:
    targets: List[str] = []
    for service_name, service_cfg in services.items():
        if service_name == "attacker":
            continue
        labels = service_cfg.get("labels", {})
        if isinstance(labels, dict) and labels.get("class") == "victim":
            targets.append(service_name)
    if not targets and "target-web" in services:
        targets.append("target-web")
    return targets


def run_connectivity_checks(
    client: docker.DockerClient,
    attacker_container_name: str,
    target_names: List[str],
    services: Dict,
    project_name: str,
) -> int:
    attacker_cfg = services["attacker"]
    attacker_name = resolve_container_name(project_name, "attacker", attacker_cfg)
    if attacker_container_name != attacker_name:
        attacker_name = attacker_container_name

    attacker = ensure_running(client, attacker_name)

    table = Table(title="Attacker Connectivity")
    table.add_column("Target Service")
    table.add_column("Container")
    table.add_column("Check")

    failures = 0

    for target_service in target_names:
        target_cfg = services[target_service]
        target_container_name = resolve_container_name(project_name, target_service, target_cfg)
        ensure_running(client, target_container_name)

        exit_code, output = attacker.exec_run(f"ping -c 1 -W 2 {target_service}")
        status = "OK" if exit_code == 0 else "FAILED"
        if exit_code != 0:
            failures += 1

        table.add_row(target_service, target_container_name, status)

        if exit_code != 0:
            console.print(output.decode("utf-8", errors="ignore"))

    console.print(table)
    return failures


def run_lab(compose_files: List[Path | str], project_name: str = "devredteam", skip_compose_up: bool = False) -> int:
    resolved_compose_files = [Path(path).resolve() for path in compose_files]

    for compose_file in resolved_compose_files:
        if not compose_file.exists():
            console.print(f"[red]Compose file not found:[/red] {compose_file}")
            return 1

    merged_compose = merge_service_views(resolved_compose_files)
    services = merged_compose.get("services", {})
    if "attacker" not in services:
        console.print("[red]Compose file must define an 'attacker' service.[/red]")
        return 1

    if not skip_compose_up:
        compose_up(resolved_compose_files, project_name)

    client = docker.from_env()
    attacker_container_name = resolve_container_name(project_name, "attacker", services["attacker"])

    targets = discover_targets(services)
    if not targets:
        console.print("[yellow]No victim target services discovered in compose file.[/yellow]")
        return 0

    failures = run_connectivity_checks(
        client=client,
        attacker_container_name=attacker_container_name,
        target_names=targets,
        services=services,
        project_name=project_name,
    )

    if failures:
        console.print(f"[red]Connectivity checks failed for {failures} target(s).[/red]")
        return 1

    console.print("[bold green]Lab is up. Attacker can reach target services.[/bold green]")
    return 0


def main() -> int:
    args = parse_args()
    return run_lab(
        compose_files=args.compose_files,
        project_name=args.project_name,
        skip_compose_up=args.skip_compose_up,
    )


if __name__ == "__main__":
    sys.exit(main())
