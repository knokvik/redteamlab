"""DevRedTeam command-line entrypoint."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import webbrowser
import warnings
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

console = Console()
PROJECT_ROOT = Path(__file__).resolve().parent
BASE_COMPOSE = PROJECT_ROOT / "docker" / "docker-compose.yml"
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevRedTeam Lab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_cmd = sub.add_parser("run", help="Clone a target repository and launch the lab")
    run_cmd.add_argument("github_url", help="GitHub repository URL")
    run_cmd.add_argument("--project-name", default="devredteam", help="Docker Compose project name")
    run_cmd.add_argument(
        "--no-build",
        action="store_true",
        help="Skip Docker image build and start existing images only",
    )
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


def run_pipeline(github_url: str, project_name: str, mode: str, no_build: bool = False) -> int:
    from core import orchestrator
    from core.setup_orchestrator import finalize_smart_setup, prepare_smart_setup
    from docker_generator import generate_compose_for_repo
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
        setup_prepared = prepare_smart_setup(
            repo_path=repo_path,
            compose_file=compose_file,
            detection=detection,
        )
        progress.advance(task)

        progress.update(task, description="[cyan]4/9 Starting containers[/cyan]")
        if no_build:
            console.print("[bold yellow]Skipping image build (--no-build). Using existing images.[/bold yellow]")
        else:
            console.print("[bold cyan]Building attacker image (first run may take 30-90s)...[/bold cyan]")
        try:
            status = orchestrator.run_lab(
                compose_files=[compose_file],
                project_name=project_name,
                skip_compose_up=False,
                build_images=not no_build,
            )
        except Exception as exc:
            console.print(f"[red]Failed to start lab stack:[/red] {exc}")
            return 1
        if status != 0:
            return status
        progress.advance(task)

        progress.update(task, description="[cyan]5/9 Smart setup (migrate + seed + health checks)[/cyan]")
        setup_result = finalize_smart_setup(
            repo_path=repo_path,
            compose_file=compose_file,
            project_name=project_name,
            prepared=setup_prepared,
        )
        if setup_result.get("smart_db_mode") and not setup_result.get("ready"):
            console.print("[red]Smart DB Setup Mode did not reach healthy state. Aborting attack phase.[/red]")
            health = setup_result.get("health", {})
            for check in health.get("checks", []):
                console.print(
                    f"  - {check.get('check')}: {'OK' if check.get('ok') else 'FAILED'} | {check.get('value', '')}"
                )
            return 1
        progress.advance(task)

        progress.update(task, description="[cyan]6-9 Crawling, attacks, observability, report[/cyan]")
        try:
            pipeline = orchestrator.run_attack_intelligence_pipeline(
                compose_file=compose_file,
                project_name=project_name,
                reports_dir=PROJECT_ROOT / "reports",
                attempts=4,
                mode=mode,
                repo_url=github_url,
                repo_name=re.sub(r"\\.git$", "", github_url.rstrip("/").split("/")[-1]) or Path(repo_path).name,
                stack_snapshot=detection,
            )
        except Exception as exc:
            console.print(f"[red]Attack intelligence pipeline failed:[/red] {exc}")
            return 1
        progress.advance(task, 4)

    report_path = pipeline.get("report", {}).get("report_path")
    attacks = pipeline.get("attacks", {}).get("attempts", [])
    fallback_used = bool(pipeline.get("attacks", {}).get("fallback_used", False))
    attack_context = pipeline.get("attacks", {}).get("attack_context", {})
    phases_executed = pipeline.get("attacks", {}).get("phases_executed", [])
    findings_count = pipeline.get("report", {}).get("findings_count", 0)
    hybrid_cvss = pipeline.get("report", {}).get("hybrid_cvss", 0.0)
    llm_used = sum(1 for a in attacks if a.get("source") == "remote-ollama")
    fallback_count = sum(1 for a in attacks if str(a.get("source", "")).startswith("fallback:"))
    top_cpu = pipeline.get("observability", {}).get("summary", {}).get("max_cpu_percent", 0.0)
    vuln_count = len(attack_context.get("vulnerabilities", []))
    paths_found = len(attack_context.get("discovered_paths", []))
    ports_found = len(attack_context.get("open_ports", []))
    seed_result = setup_result.get("seed", {})
    setup_mode = bool(setup_result.get("smart_db_mode"))
    seed_note = (
        f"Seeded {seed_result.get('db_type')} in {seed_result.get('service')}"
        if seed_result.get("seeded")
        else f"Seeder skipped: {seed_result.get('reason', 'unknown')}"
    )
    setup_ready = bool(setup_result.get("ready"))
    runtime = setup_result.get("runtime", {})
    expected_db_port = runtime.get("expected_db_host_port")
    console.print(f"Detected technologies: {', '.join(detection['technologies']) or 'none'}")
    console.print(seed_note)
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"Mode: [bold]{mode}[/bold]",
                    f"Target URL: [bold]{pipeline.get('target_url', 'n/a')}[/bold]",
                    f"Smart DB Setup Mode: [bold]{setup_mode}[/bold] | Ready: [bold]{setup_ready}[/bold]",
                    f"Expected DB host port: [bold]{expected_db_port if expected_db_port else 'default'}[/bold]",
                    f"Phases: [bold]{' → '.join(phases_executed) or 'none'}[/bold]",
                    f"Total attempts: [bold]{len(attacks)}[/bold]",
                    f"Hybrid CVSS: [bold]{hybrid_cvss}[/bold]",
                    f"Findings: [bold]{findings_count}[/bold] | Vulnerabilities: [bold]{vuln_count}[/bold]",
                    f"Paths discovered: [bold]{paths_found}[/bold] | Ports found: [bold]{ports_found}[/bold]",
                    f"LLM suggestions: [bold]{llm_used}[/bold] | fallback: [bold]{fallback_count}[/bold]",
                    f"Peak CPU: [bold]{round(float(top_cpu), 2)}%[/bold]",
                    f"Report: [bold]{report_path or 'not generated'}[/bold]",
                ]
            ),
            title="DevRedTeam Run Summary",
            border_style="green",
        )
    )
    if report_path:
        _open_report(Path(report_path))
        console.print(f"[bold green]Report generated at:[/bold green] {report_path}")
    else:
        console.print("[yellow]No report was generated.[/yellow]")
    console.print("[bold green]Pipeline complete.[/bold green]")
    return 0


def main() -> int:
    args = parse_args()

    if args.command == "run":
        mode = "aggressive" if args.aggressive else "safe"
        return run_pipeline(args.github_url, args.project_name, mode, no_build=args.no_build)

    return 1


if __name__ == "__main__":
    sys.exit(main())
