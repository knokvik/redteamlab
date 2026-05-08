"""DevRedTeam command-line entrypoint."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import webbrowser
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent
BASE_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.yml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevRedTeam Lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="Clone a target repository and launch the lab")
    run_cmd.add_argument("github_url", help="GitHub repository URL")
    run_cmd.add_argument("--project-name", default="devredteam", help="Docker Compose project name")
    mode_group = run_cmd.add_mutually_exclusive_group()
    mode_group.add_argument("--safe", action="store_true", help="Run in safe mode (default)")
    mode_group.add_argument("--aggressive", action="store_true", help="Run in aggressive mode")

    return parser.parse_args()


def _open_report(report_path: Path) -> None:
    try:
        webbrowser.open(report_path.resolve().as_uri())
        console.print(f"[green]Opened report in browser:[/green] {report_path}")
    except Exception as exc:
        console.print(f"[yellow]Could not auto-open browser:[/yellow] {exc}")
        console.print(f"[yellow]Report location:[/yellow] {report_path}")


def run_pipeline(github_url: str, project_name: str, mode: str) -> int:
    from core import orchestrator
    from docker_generator import generate_compose_for_repo
    from dummy_data_seeder import seed_dummy_data
    from github_cloner import clone_repo
    from stack_detector import detect_stack

    step_total = 9
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

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running DevRedTeam pipeline", total=step_total)

        progress.update(task, description="[cyan]1/9 Cloning repository[/cyan]")
        repo_path = clone_repo(github_url)
        progress.advance(task)

        progress.update(task, description="[cyan]2/9 Detecting stack[/cyan]")
        detection = detect_stack(repo_path)
        progress.advance(task)

        progress.update(task, description="[cyan]3/9 Generating compose[/cyan]")
        generated = generate_compose_for_repo(
            repo_path=repo_path,
            detection=detection,
            base_compose_path=BASE_COMPOSE,
        )
        compose_file = Path(generated["compose_file"])
        progress.advance(task)

        progress.update(task, description="[cyan]4/9 Starting containers[/cyan]")
        status = orchestrator.run_lab(
            compose_files=[compose_file],
            project_name=project_name,
            skip_compose_up=False,
        )
        if status != 0:
            return status
        progress.advance(task)

        progress.update(task, description="[cyan]5/9 Seeding dummy data[/cyan]")
        seed_result = seed_dummy_data(compose_file=compose_file, project_name=project_name)
        progress.advance(task)

        progress.update(task, description="[cyan]6-9 Crawling, attacks, observability, report[/cyan]")
        pipeline = orchestrator.run_attack_intelligence_pipeline(
            compose_file=compose_file,
            project_name=project_name,
            reports_dir=PROJECT_ROOT / "reports",
            attempts=4,
            mode=mode,
            repo_url=github_url,
            repo_name=re.sub(r"\\.git$", "", github_url.rstrip("/").split("/")[-1]) or Path(repo_path).name,
        )
        progress.advance(task, 4)

    report_path = pipeline.get("report", {}).get("report_path")
    fallback_used = bool(pipeline.get("attacks", {}).get("fallback_used", False))
    seed_note = (
        f"Seeded {seed_result.get('db_type')} in {seed_result.get('service')}"
        if seed_result.get("seeded")
        else f"Seeder skipped: {seed_result.get('reason', 'unknown')}"
    )
    console.print(f"Detected technologies: {', '.join(detection['technologies']) or 'none'}")
    console.print(seed_note)
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Mode: [bold]{mode}[/bold]",
                    f"Target URL: [bold]{pipeline.get('target_url', 'n/a')}[/bold]",
                    f"Fallback used: [bold]{fallback_used}[/bold]",
                    f"Report: [bold]{report_path or 'not generated'}[/bold]",
                ]
            ),
            title="Run Summary",
            border_style="green",
        )
    )
    if report_path:
        _open_report(Path(report_path))
    console.print("[bold green]Pipeline complete.[/bold green]")
    return 0


def main() -> int:
    args = parse_args()

    if args.command == "run":
        mode = "aggressive" if args.aggressive else "safe"
        return run_pipeline(args.github_url, args.project_name, mode)

    return 1


if __name__ == "__main__":
    sys.exit(main())
