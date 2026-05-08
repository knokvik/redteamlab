"""Collect lightweight container logs and resource stats during attacks."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Dict, List

import docker


class ObservabilityCollector:
    def __init__(self, project_name: str, sample_interval_s: int = 2):
        self.project_name = project_name
        self.sample_interval_s = sample_interval_s
        self.client = docker.from_env()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._samples: List[Dict] = []

    def _project_containers(self):
        containers = self.client.containers.list(all=True)
        scoped = []
        for container in containers:
            labels = container.labels or {}
            if labels.get("com.docker.compose.project") == self.project_name:
                scoped.append(container)
        return scoped

    @staticmethod
    def _cpu_percent(stats: Dict) -> float:
        cpu_stats = stats.get("cpu_stats", {})
        precpu = stats.get("precpu_stats", {})

        cpu_delta = float(cpu_stats.get("cpu_usage", {}).get("total_usage", 0)) - float(
            precpu.get("cpu_usage", {}).get("total_usage", 0)
        )
        system_delta = float(cpu_stats.get("system_cpu_usage", 0)) - float(
            precpu.get("system_cpu_usage", 0)
        )
        online_cpus = float(cpu_stats.get("online_cpus", 0) or 0)
        if online_cpus == 0:
            online_cpus = float(len(cpu_stats.get("cpu_usage", {}).get("percpu_usage", []) or [1]))

        if cpu_delta > 0 and system_delta > 0:
            return (cpu_delta / system_delta) * online_cpus * 100.0
        return 0.0

    def _collect_once(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        container_samples = []

        for container in self._project_containers():
            try:
                stats = container.stats(stream=False)
                logs = container.logs(tail=20).decode("utf-8", errors="ignore")
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

        self._samples.append({"timestamp": now, "containers": container_samples})

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._collect_once()
            self._stop_event.wait(self.sample_interval_s)

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> Dict:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.sample_interval_s * 2)
        return self.snapshot()

    def snapshot(self) -> Dict:
        if not self._samples:
            return {"samples": [], "summary": {}}

        cpu_values = []
        mem_values = []
        for sample in self._samples:
            for c in sample.get("containers", []):
                if "cpu_percent" in c:
                    cpu_values.append(c["cpu_percent"])
                if "memory_bytes" in c:
                    mem_values.append(c["memory_bytes"])

        summary = {
            "max_cpu_percent": max(cpu_values) if cpu_values else 0.0,
            "avg_cpu_percent": (sum(cpu_values) / len(cpu_values)) if cpu_values else 0.0,
            "max_memory_bytes": max(mem_values) if mem_values else 0.0,
            "sample_count": len(self._samples),
        }

        return {"samples": self._samples, "summary": summary}
