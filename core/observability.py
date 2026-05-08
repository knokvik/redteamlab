"""Collect correlated container stats/logs, database latency probes, and disk I/O during attacks."""

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
        self._baseline: Dict = {}

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

    @staticmethod
    def _io_stats(stats: Dict) -> Dict:
        """Extract block I/O statistics from container stats."""
        blkio = stats.get("blkio_stats", {})
        io_service_bytes = blkio.get("io_service_bytes_recursive", []) or []
        read_bytes = 0.0
        write_bytes = 0.0
        for entry in io_service_bytes:
            op = entry.get("op", "").lower()
            value = float(entry.get("value", 0))
            if op == "read":
                read_bytes += value
            elif op == "write":
                write_bytes += value
        return {"disk_read_bytes": read_bytes, "disk_write_bytes": write_bytes}

    @staticmethod
    def _pids_count(stats: Dict) -> int:
        """Extract process/thread count from container stats."""
        return int(stats.get("pids_stats", {}).get("current", 0) or 0)

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
            "db_type": "postgres",
        }
        if code != 0:
            result["db_probe_error"] = "probe-nonzero-exit"

        # Additional probe: check active connections count
        code2, output2 = db_container.exec_run(
            "sh -lc \"PGPASSWORD=app psql -U app -d appdb -tAc "
            "'SELECT count(*) FROM pg_stat_activity'\""
        )
        if code2 == 0:
            try:
                result["db_active_connections"] = int(output2.decode().strip())
            except ValueError:
                pass

        return result

    def _mysql_latency_probe(self, db_container) -> Dict:
        """MySQL/MariaDB latency probe — fixes the missing MySQL probe limitation."""
        started = time.perf_counter()
        code, output = db_container.exec_run(
            "sh -lc 'mysql -u\"${MYSQL_USER:-root}\" "
            "-p\"${MYSQL_PASSWORD:-${MYSQL_ROOT_PASSWORD:-root}}\" "
            "\"${MYSQL_DATABASE:-appdb}\" -e \"SELECT 1\" 2>/dev/null'"
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        result = {
            "db_query_latency_ms": elapsed_ms,
            "db_probe_success": code == 0,
            "db_probe_output": output.decode("utf-8", errors="ignore").strip()[:400],
            "db_type": "mysql",
        }
        if code != 0:
            result["db_probe_error"] = "probe-nonzero-exit"

        # Additional probe: check process list for active queries
        code2, output2 = db_container.exec_run(
            "sh -lc 'mysql -u\"${MYSQL_USER:-root}\" "
            "-p\"${MYSQL_PASSWORD:-${MYSQL_ROOT_PASSWORD:-root}}\" "
            "-e \"SHOW PROCESSLIST\" 2>/dev/null'"
        )
        if code2 == 0:
            try:
                lines = output2.decode().strip().splitlines()
                result["db_active_connections"] = max(0, len(lines) - 1)
            except Exception:
                pass

        return result

    def _mongodb_latency_probe(self, db_container) -> Dict:
        """MongoDB latency probe via mongosh/mongo shell."""
        started = time.perf_counter()
        code, output = db_container.exec_run(
            "sh -lc 'mongosh --eval \"db.runCommand({ping: 1})\" --quiet 2>/dev/null || "
            "mongo --eval \"db.runCommand({ping: 1})\" --quiet 2>/dev/null'"
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        result = {
            "db_query_latency_ms": elapsed_ms,
            "db_probe_success": code == 0,
            "db_probe_output": output.decode("utf-8", errors="ignore").strip()[:400],
            "db_type": "mongodb",
        }
        if code != 0:
            result["db_probe_error"] = "probe-nonzero-exit"
        return result

    def _redis_latency_probe(self, db_container) -> Dict:
        """Redis latency probe."""
        started = time.perf_counter()
        code, output = db_container.exec_run(
            "sh -lc 'redis-cli ping 2>/dev/null'"
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
        result = {
            "db_query_latency_ms": elapsed_ms,
            "db_probe_success": code == 0 and "PONG" in output.decode("utf-8", errors="ignore"),
            "db_probe_output": output.decode("utf-8", errors="ignore").strip()[:400],
            "db_type": "redis",
        }
        if code != 0:
            result["db_probe_error"] = "probe-nonzero-exit"

        # Get memory usage and connected clients
        code2, output2 = db_container.exec_run(
            "sh -lc 'redis-cli info memory 2>/dev/null | head -5'"
        )
        if code2 == 0:
            result["redis_info"] = output2.decode("utf-8", errors="ignore").strip()[:200]

        return result

    def _run_db_probe(self) -> Dict:
        """Dispatch database probe based on detected type."""
        default_probe = {
            "db_query_latency_ms": None,
            "db_probe_success": False,
            "db_probe_output": "db-not-configured",
        }

        if not self.db_type:
            return default_probe

        db_container = self._resolve_db_container()
        if db_container is None:
            return {
                "db_query_latency_ms": None,
                "db_probe_success": False,
                "db_probe_output": "db-container-not-found",
            }

        try:
            if self.db_type == "postgres":
                return self._postgres_latency_probe(db_container)
            elif self.db_type in ("mysql", "mariadb"):
                return self._mysql_latency_probe(db_container)
            elif self.db_type in ("mongodb", "mongo"):
                return self._mongodb_latency_probe(db_container)
            elif self.db_type == "redis":
                return self._redis_latency_probe(db_container)
            else:
                return {
                    "db_query_latency_ms": None,
                    "db_probe_success": False,
                    "db_probe_output": f"unsupported-db-type:{self.db_type}",
                }
        except Exception as exc:
            return {
                "db_query_latency_ms": None,
                "db_probe_success": False,
                "db_probe_output": "",
                "db_probe_error": str(exc),
            }

    def _collect_once(self) -> None:
        now = self._utc_now_iso()
        container_samples = []

        db_probe = self._run_db_probe()

        for container in self._project_containers():
            try:
                stats = container.stats(stream=False)
                logs = container.logs(tail=30).decode("utf-8", errors="ignore")
                mem_usage = float(stats.get("memory_stats", {}).get("usage", 0))
                mem_limit = float(stats.get("memory_stats", {}).get("limit", 0))
                net = stats.get("networks", {})
                net_rx = 0.0
                net_tx = 0.0
                for iface in net.values():
                    net_rx += float(iface.get("rx_bytes", 0))
                    net_tx += float(iface.get("tx_bytes", 0))

                io = self._io_stats(stats)
                pids = self._pids_count(stats)

                container_samples.append(
                    {
                        "container": container.name,
                        "timestamp": now,
                        "cpu_percent": round(self._cpu_percent(stats), 3),
                        "memory_bytes": mem_usage,
                        "memory_limit_bytes": mem_limit,
                        "memory_percent": round((mem_usage / mem_limit * 100) if mem_limit > 0 else 0, 3),
                        "net_rx_bytes": net_rx,
                        "net_tx_bytes": net_tx,
                        "disk_read_bytes": io["disk_read_bytes"],
                        "disk_write_bytes": io["disk_write_bytes"],
                        "pids": pids,
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
        # Capture baseline before attacks begin
        self._collect_once()
        with self._lock:
            if self._samples:
                self._baseline = self._samples[-1].copy()

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
        mem_percent_values: List[float] = []
        rx_values: List[float] = []
        tx_values: List[float] = []
        disk_read_values: List[float] = []
        disk_write_values: List[float] = []
        db_latencies: List[float] = []
        pids_values: List[int] = []
        log_lines: List[str] = []
        sensitive_hits = 0
        error_hits = 0
        leak_tokens = ("password", "secret", "token", "apikey", "authorization", "set-cookie",
                       "private_key", "aws_secret", "database_url", "connection_string")
        error_tokens = ("error", "exception", "failed", "traceback", "denied", "fatal",
                        "segfault", "panic", "oom", "killed", "timeout", "refused")

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
                if "memory_percent" in container:
                    mem_percent_values.append(float(container["memory_percent"]))
                rx_values.append(float(container.get("net_rx_bytes", 0.0) or 0.0))
                tx_values.append(float(container.get("net_tx_bytes", 0.0) or 0.0))
                disk_read_values.append(float(container.get("disk_read_bytes", 0.0) or 0.0))
                disk_write_values.append(float(container.get("disk_write_bytes", 0.0) or 0.0))
                pids_values.append(int(container.get("pids", 0) or 0))

                logs = str(container.get("log_excerpt", ""))
                for line in logs.splitlines()[-10:]:
                    line_lower = line.lower()
                    if any(tok in line_lower for tok in error_tokens):
                        error_hits += 1
                        if len(log_lines) < 50:
                            log_lines.append(f"[{container.get('container', 'unknown')}] {line}")
                    if any(tok in line_lower for tok in leak_tokens):
                        sensitive_hits += 1
                        if len(log_lines) < 50:
                            log_lines.append(f"[{container.get('container', 'unknown')}] {line}")

        return {
            "sample_count": len(samples),
            "max_cpu_percent": max(cpu_values) if cpu_values else 0.0,
            "avg_cpu_percent": (sum(cpu_values) / len(cpu_values)) if cpu_values else 0.0,
            "max_memory_bytes": max(mem_values) if mem_values else 0.0,
            "max_memory_percent": max(mem_percent_values) if mem_percent_values else 0.0,
            "net_rx_delta_bytes": (max(rx_values) - min(rx_values)) if len(rx_values) >= 2 else 0.0,
            "net_tx_delta_bytes": (max(tx_values) - min(tx_values)) if len(tx_values) >= 2 else 0.0,
            "disk_read_total_bytes": sum(disk_read_values),
            "disk_write_total_bytes": sum(disk_write_values),
            "max_pids": max(pids_values) if pids_values else 0,
            "db_latency_max_ms": max(db_latencies) if db_latencies else None,
            "db_latency_avg_ms": (sum(db_latencies) / len(db_latencies)) if db_latencies else None,
            "db_latency_p95_ms": sorted(db_latencies)[int(len(db_latencies) * 0.95)] if len(db_latencies) > 1 else None,
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
                "db_probe_enabled": self.db_type is not None,
                "db_type": self.db_type,
                "db_service_name": self.db_service_name,
            }
        )

        return {
            "samples": samples,
            "summary": summary,
            "attempt_correlations": self._attempt_correlations(),
            "baseline": self._baseline,
        }
