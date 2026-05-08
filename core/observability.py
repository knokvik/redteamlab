"""Collect correlated container stats/logs and optional DB latency during attacks."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import docker


class ObservabilityCollector:
    def __init__(
        self,
        project_name: str,
        sample_interval_s: int = 2,
        db_type: str | None = None,
        db_service_name: str | None = None,
    ):
        self.project_name = project_name
        self.sample_interval_s = sample_interval_s
        self.db_type = (db_type or "").lower() or None
        self.db_service_name = db_service_name
        self.client = docker.from_env()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: List[Dict] = []
        self._attempts: Dict[str, Dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_ts(value: str | None) -> datetime:
        if not value:
            return datetime.fromtimestamp(0, tz=timezone.utc)
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    def _project_containers(self):
        containers = self.client.containers.list(all=True)
        scoped = []
        for container in containers:
            labels = container.labels or {}
            if labels.get("com.docker.compose.project") == self.project_name:
                scoped.append(container)
        return scoped

    def _resolve_db_container(self):
        if self.db_type != "postgres":
            return None
        for container in self._project_containers():
            labels = container.labels or {}
            service = labels.get("com.docker.compose.service", "")
            if self.db_service_name and service == self.db_service_name:
                return container
            if service == "target-db":
                return container
        return None

    @staticmethod
    def _cpu_percent(stats: Dict) -> float:
        cpu_stats = stats.get("cpu_stats", {})
        precpu = stats.get("precpu_stats", {})

        cpu_delta = float(cpu_stats.get("cpu_usage", {}).get("total_usage", 0)) - float(
            precpu.get("cpu_usage", {}).get("total_usage", 0)
        )
        system_delta = float(cpu_stats.get("system_cpu_usage", 0)) - float(precpu.get("system_cpu_usage", 0))
        online_cpus = float(cpu_stats.get("online_cpus", 0) or 0)
        if online_cpus == 0:
            online_cpus = float(len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", []) or [1]))

        if cpu_delta > 0 and system_delta > 0:
            return (cpu_delta / system_delta) * online_cpus * 100.0
        return 0.0

    def _postgres_latency_probe(self, db_container) -> Dict:
        started = time.perf_counter()
        code, output = db_container.exec_run(
            "sh -lc \"PGPASSWORD=app psql -U app -d appdb -tAc 'SELECT 1'\""
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        result = {
            "db_query_latency_ms": elapsed_ms,
            "db_probe_success": code == 0,
            "db_probe_output": output.decode("utf-8", errors="ignore").strip()[:400],
        }
        if code != 0:
            result["db_probe_error"] = "probe-nonzero-exit"
        return result

    def _collect_once(self) -> None:
        now = self._utc_now_iso()
        container_samples = []

        db_probe: Dict = {
            "db_query_latency_ms": None,
            "db_probe_success": False,
            "db_probe_output": "db-not-configured",
        }
        if self.db_type == "postgres":
            db_container = self._resolve_db_container()
            if db_container is not None:
                try:
                    db_probe = self._postgres_latency_probe(db_container)
                except Exception as exc:  # pragma: no cover - defensive
                    db_probe = {
                        "db_query_latency_ms": None,
                        "db_probe_success": False,
                        "db_probe_output": "",
                        "db_probe_error": str(exc),
                    }
            else:
                db_probe = {
                    "db_query_latency_ms": None,
                    "db_probe_success": False,
                    "db_probe_output": "db-container-not-found",
                }

        for container in self._project_containers():
            try:
                stats = container.stats(stream=False)
                logs = container.logs(tail=30).decode("utf-8", errors="ignore")
                mem_usage = float(stats.get("memory_stats", {}).get("usage", 0))
                net = stats.get("networks", {})
                net_rx = 0.0
                net_tx = 0.0
                for iface in net.values():
                    net_rx += float(iface.get("rx_bytes", 0))
                    net_tx += float(iface.get("tx_bytes", 0))

                container_samples.append(
                    {
                        "container": container.name,
                        "timestamp": now,
                        "cpu_percent": round(self._cpu_percent(stats), 3),
                        "memory_bytes": mem_usage,
                        "net_rx_bytes": net_rx,
                        "net_tx_bytes": net_tx,
                        "log_excerpt": logs,
                    }
                )
            except Exception as exc:
                container_samples.append(
                    {
                        "container": container.name,
                        "timestamp": now,
                        "error": str(exc),
                    }
                )

        sample = {"timestamp": now, "containers": container_samples, "db": db_probe}
        with self._lock:
            self._samples.append(sample)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._collect_once()
            self._stop_event.wait(self.sample_interval_s)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def begin_attempt(self, attempt_id: str, metadata: Dict | None = None) -> None:
        with self._lock:
            self._attempts[attempt_id] = {
                "attempt_id": attempt_id,
                "started_at": self._utc_now_iso(),
                "ended_at": None,
                "metadata": metadata or {},
            }

    def end_attempt(self, attempt_id: str, metadata: Dict | None = None) -> None:
        with self._lock:
            entry = self._attempts.setdefault(
                attempt_id,
                {"attempt_id": attempt_id, "started_at": self._utc_now_iso(), "metadata": {}},
            )
            entry["ended_at"] = self._utc_now_iso()
            if metadata:
                entry.setdefault("metadata", {}).update(metadata)

    def snapshot_window(self, start_ts: str | None, end_ts: str | None) -> List[Dict]:
        if not start_ts:
            return []
        start = self._parse_ts(start_ts)
        end = self._parse_ts(end_ts) if end_ts else datetime.now(timezone.utc)

        with self._lock:
            samples = list(self._samples)

        scoped = []
        for sample in samples:
            ts = self._parse_ts(sample.get("timestamp"))
            if start <= ts <= end:
                scoped.append(sample)
        return scoped

    @staticmethod
    def _summarize_window(samples: List[Dict]) -> Dict:
        cpu_values: List[float] = []
        mem_values: List[float] = []
        rx_values: List[float] = []
        tx_values: List[float] = []
        db_latencies: List[float] = []
        log_lines: List[str] = []
        sensitive_hits = 0
        error_hits = 0
        leak_tokens = ("password", "secret", "token", "apikey", "authorization", "set-cookie")
        error_tokens = ("error", "exception", "failed", "traceback", "denied")

        for sample in samples:
            db = sample.get("db", {})
            latency = db.get("db_query_latency_ms")
            if isinstance(latency, (float, int)):
                db_latencies.append(float(latency))

            for container in sample.get("containers", []):
                if "cpu_percent" in container:
                    cpu_values.append(float(container["cpu_percent"]))
                if "memory_bytes" in container:
                    mem_values.append(float(container["memory_bytes"]))
                rx_values.append(float(container.get("net_rx_bytes", 0.0) or 0.0))
                tx_values.append(float(container.get("net_tx_bytes", 0.0) or 0.0))

                logs = str(container.get("log_excerpt", ""))
                for line in logs.splitlines()[-10:]:
                    line_lower = line.lower()
                    if any(tok in line_lower for tok in error_tokens):
                        error_hits += 1
                        if len(log_lines) < 30:
                            log_lines.append(f"[{container.get('container', 'unknown')}] {line}")
                    if any(tok in line_lower for tok in leak_tokens):
                        sensitive_hits += 1
                        if len(log_lines) < 30:
                            log_lines.append(f"[{container.get('container', 'unknown')}] {line}")

        return {
            "sample_count": len(samples),
            "max_cpu_percent": max(cpu_values) if cpu_values else 0.0,
            "avg_cpu_percent": (sum(cpu_values) / len(cpu_values)) if cpu_values else 0.0,
            "max_memory_bytes": max(mem_values) if mem_values else 0.0,
            "net_rx_delta_bytes": (max(rx_values) - min(rx_values)) if len(rx_values) >= 2 else 0.0,
            "net_tx_delta_bytes": (max(tx_values) - min(tx_values)) if len(tx_values) >= 2 else 0.0,
            "db_latency_max_ms": max(db_latencies) if db_latencies else None,
            "db_latency_avg_ms": (sum(db_latencies) / len(db_latencies)) if db_latencies else None,
            "error_log_hits": error_hits,
            "sensitive_log_hits": sensitive_hits,
            "log_excerpt": "\n".join(log_lines) if log_lines else "No correlated error/leak lines found.",
        }

    def _attempt_correlations(self) -> Dict[str, Dict]:
        correlations: Dict[str, Dict] = {}
        with self._lock:
            attempts = dict(self._attempts)

        for attempt_id, attempt_info in attempts.items():
            scoped_samples = self.snapshot_window(attempt_info.get("started_at"), attempt_info.get("ended_at"))
            correlations[attempt_id] = {
                "attempt_id": attempt_id,
                "started_at": attempt_info.get("started_at"),
                "ended_at": attempt_info.get("ended_at"),
                "metadata": attempt_info.get("metadata", {}),
                "window_summary": self._summarize_window(scoped_samples),
            }
        return correlations

    def stop(self) -> Dict:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.sample_interval_s * 2)
        return self.snapshot()

    def snapshot(self) -> Dict:
        with self._lock:
            samples = list(self._samples)

        summary = self._summarize_window(samples)
        summary.update(
            {
                "db_probe_enabled": self.db_type == "postgres",
                "db_type": self.db_type,
                "db_service_name": self.db_service_name,
            }
        )

        return {
            "samples": samples,
            "summary": summary,
            "attempt_correlations": self._attempt_correlations(),
        }
