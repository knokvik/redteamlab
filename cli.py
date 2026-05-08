"""DevRedTeam command-line entrypoint."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from core import orchestrator
from docker_generator import generate_compose_for_repo
from dummy_data_seeder import seed_dummy_data
from github_cloner import clone_repo
from stack_detector import detect_stack


console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent
BASE_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.yml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevRedTeam Lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="Clone a target repository and launch the lab")
    run_cmd.add_argument("github_url", help="GitHub repository URL")
    run_cmd.add_argument("--project-name", default="devredteam", help="Docker Compose project name")

    return parser.parse_args()


def run_pipeline(github_url: str, project_name: str) -> int:
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        console.print("[red]Docker daemon is not running or not reachable.[/red]")
        return 1

    plugin_list = subprocess.run(
        ["docker", "plugin", "ls", "--format", "{{.Name}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    if not any(line.startswith("loki") for line in plugin_list.stdout.splitlines()):
        console.print("[bold cyan]Installing Loki Docker logging plugin...[/bold cyan]")
        subprocess.run(
            [
                "docker",
                "plugin",
                "install",
                "grafana/loki-docker-driver:latest",
                "--alias",
                "loki",
                "--grant-all-permissions",
            ],
            check=True,
        )

    console.print(f"[bold cyan]Cloning target repository:[/bold cyan] {github_url}")
    repo_path = clone_repo(github_url)

    console.print("[bold cyan]Detecting stack...[/bold cyan]")
    detection = detect_stack(repo_path)
    console.print(f"Detected technologies: {', '.join(detection['technologies']) or 'none'}")

    console.print("[bold cyan]Generating merged compose file...[/bold cyan]")
    generated = generate_compose_for_repo(
        repo_path=repo_path,
        detection=detection,
        base_compose_path=BASE_COMPOSE,
    )

    compose_file = Path(generated["compose_file"])
    console.print(f"Compose ready: {compose_file}")

    status = orchestrator.run_lab(
        compose_files=[compose_file],
        project_name=project_name,
        skip_compose_up=False,
    )
    if status != 0:
        return status

    console.print("[bold cyan]Seeding dummy data (if DB detected)...[/bold cyan]")
    seed_result = seed_dummy_data(compose_file=compose_file, project_name=project_name)
    if seed_result.get("seeded"):
        console.print(f"[green]Seeded {seed_result.get('db_type')} in {seed_result.get('service')}[/green]")
    else:
        console.print(f"[yellow]Seeder skipped:[/yellow] {seed_result.get('reason', 'unknown')}" )

    console.print("[bold cyan]Running crawler, attack loop, observability, and report generation...[/bold cyan]")
    pipeline = orchestrator.run_attack_intelligence_pipeline(
        compose_file=compose_file,
        project_name=project_name,
        reports_dir=PROJECT_ROOT / "reports",
        attempts=4,
    )
    report_path = pipeline.get("report", {}).get("report_path")
    if report_path:
        console.print(f"[bold green]Report generated:[/bold green] {report_path}")

    console.print("[bold green]Pipeline complete.[/bold green]")
    return 0


def main() -> int:
    args = parse_args()

    if args.command == "run":
        return run_pipeline(args.github_url, args.project_name)

    return 1


if __name__ == "__main__":
    sys.exit(main())
