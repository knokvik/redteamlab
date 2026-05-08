"""Start Docker compose stacks and verify attacker connectivity to victim services."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import docker
import yaml
from rich.console import Console
from rich.table import Table

from core.attack_orchestrator import run_attack_loop
from core.observability import ObservabilityCollector
from core.playwright_crawler import crawl_and_build_graph, discover_target_urls, select_primary_target_url
from core.report_generator import generate_report

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


def _print_build_failure_help(project_name: str, build_images: bool) -> None:
    if build_images:
        console.print(
            "[yellow]Docker image build failed. If you see Buildx permission issues, try:[/yellow]\n"
            "  [cyan]docker builder prune -af[/cyan]\n"
            "  [cyan]rm -rf ~/.docker/buildx[/cyan]\n"
            f"  [cyan]python3 cli.py run <repo-url> --project-name {project_name}[/cyan]\n"
            "Or skip image rebuild if images already exist:\n"
            f"  [cyan]python3 cli.py run <repo-url> --project-name {project_name} --no-build[/cyan]"
        )
    else:
        console.print(
            "[yellow]Compose startup failed in --no-build mode. If images are missing, rerun without --no-build.[/yellow]"
        )


def compose_up(compose_files: List[Path], project_name: str, build_images: bool = True) -> bool:
    console.print("[bold cyan]Bringing up lab stack with docker compose...[/bold cyan]")

    cmd = ["docker", "compose", "-p", project_name]
    for compose_file in compose_files:
        cmd.extend(["-f", str(compose_file)])
    cmd.extend(["up", "-d", "--remove-orphans"])
    if build_images:
        cmd.append("--build")

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as exc:
        output = f"{exc.stdout or ''}\n{exc.stderr or ''}"
        lowered = output.lower()
        if "buildx" in lowered or "operation not permitted" in lowered:
            console.print("[red]Docker Buildx permission issue detected during compose startup.[/red]")
        else:
            console.print("[red]docker compose up failed.[/red]")
        _print_build_failure_help(project_name=project_name, build_images=build_images)
        return False


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


def run_lab(
    compose_files: List[Path | str],
    project_name: str = "devredteam",
    skip_compose_up: bool = False,
    build_images: bool = True,
) -> int:
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
        started = compose_up(resolved_compose_files, project_name, build_images=build_images)
        if not started:
            return 1

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


def run_attack_intelligence_pipeline(
    compose_file: Path | str,
    project_name: str = "devredteam",
    reports_dir: Path | str | None = None,
    attempts: int = 4,
    mode: str = "safe",
    repo_url: str = "",
    repo_name: str = "",
    stack_snapshot: Dict | None = None,
) -> Dict:
    compose_path = Path(compose_file).resolve()
    report_dir = Path(reports_dir) if reports_dir else Path(__file__).resolve().parents[1] / "reports"
    repo_slug = repo_name or re.sub(r"\.git$", "", repo_url.rstrip("/").split("/")[-1]) or "repo"

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    stack_snapshot = stack_snapshot or {}
    discovered_targets = discover_target_urls(compose_path)
    target_urls = [item.url for item in discovered_targets]
    if not target_urls:
        target_urls = ["http://localhost:9700"]
    base_url = select_primary_target_url(compose_path)
    console.print(f"[bold cyan]Playwright target URL:[/bold cyan] {base_url}")

    try:
        crawl_result = crawl_and_build_graph(base_url=base_url, run_id=run_id)
    except Exception as exc:
        crawl_result = {
            "run_id": run_id,
            "base_url": base_url,
            "error": f"crawler failure: {exc}",
            "flows": [],
            "endpoints": [],
            "graph": {"nodes": [], "edges": []},
        }

    db_info = stack_snapshot.get("database", {}) if isinstance(stack_snapshot, dict) else {}
    db_type = db_info.get("type") if isinstance(db_info, dict) else None
    collector = ObservabilityCollector(
        project_name=project_name,
        sample_interval_s=2,
        db_type=db_type,
        db_service_name="target-db",
    )
    collector.start()
    try:
        try:
            attack_result = run_attack_loop(
                base_url=base_url,
                graph_snapshot=crawl_result.get("graph", {}),
                observability_collector=collector,
                project_name=project_name,
                attempts=attempts,
                mode=mode,
                stack_snapshot=stack_snapshot,
                target_urls=target_urls,
            )
        except Exception as exc:
            attack_result = {
                "attempts": [],
                "fallback_used": True,
                "error": f"attack loop failure: {exc}",
            }
    finally:
        try:
            observability_result = collector.stop()
        except Exception as exc:
            observability_result = {"samples": [], "summary": {}, "error": str(exc)}

    try:
        report_result = generate_report(
            output_root=report_dir,
            repo_name=repo_slug,
            repo_url=repo_url or "n/a",
            mode=mode,
            run_id=run_id,
            target_url=base_url,
            target_urls=target_urls,
            stack_snapshot=stack_snapshot,
            crawl_result=crawl_result,
            attack_result=attack_result,
            observability_result=observability_result,
            compose_file=str(compose_path),
        )
    except Exception as exc:
        fallback_dir = report_dir / f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{repo_slug}"
        fallback_dir.mkdir(parents=True, exist_ok=True)
        fallback_file = fallback_dir / "index.html"
        fallback_file.write_text(
            (
                "<html><body><h1>DevRedTeam Report (Fallback)</h1>"
                f"<p>Run ID: {run_id}</p>"
                f"<p>Target: {base_url}</p>"
                f"<p>Mode: {mode}</p>"
                f"<p>Report generation error: {exc}</p>"
                "</body></html>"
            ),
            encoding="utf-8",
        )
        report_result = {
            "report_path": str(fallback_file),
            "report_dir": str(fallback_dir),
            "base_cvss": 0.0,
            "behavior_impact": 0.0,
            "hybrid_cvss": 0.0,
            "error": str(exc),
        }

    return {
        "run_id": run_id,
        "target_url": base_url,
        "target_urls": target_urls,
        "stack": stack_snapshot,
        "crawl": crawl_result,
        "attacks": attack_result,
        "observability": observability_result,
        "report": report_result,
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    args = parse_args()
    return run_lab(
        compose_files=args.compose_files,
        project_name=args.project_name,
        skip_compose_up=args.skip_compose_up,
    )


if __name__ == "__main__":
    sys.exit(main())
