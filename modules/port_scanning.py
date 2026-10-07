"""
SyncHunt - Port Scanning
Wraps naabu / nmap / masscan, parses their structured output and flags
exposed high-risk services.

masscan needs raw sockets (root): it is skipped unless `port_scanning.masscan.allow_root`
is explicitly enabled, and SyncHunt never invokes sudo on its own.
"""

from __future__ import annotations

import os
import time
from typing import Dict, List

from core.models import Asset, Finding
from core.utils import (
    host_from_url,
    read_file_lines,
    read_json_lines,
    save_json,
    write_file_lines,
)

# port -> (service hint, severity when exposed)
RISKY_SERVICES = {
    "21": ("FTP", "medium"),
    "23": ("Telnet", "high"),
    "111": ("rpcbind", "low"),
    "135": ("MSRPC", "low"),
    "139": ("NetBIOS", "low"),
    "445": ("SMB", "medium"),
    "1433": ("MSSQL", "medium"),
    "1521": ("Oracle DB", "medium"),
    "2049": ("NFS", "medium"),
    "2375": ("Docker API (plaintext)", "critical"),
    "2379": ("etcd", "high"),
    "3306": ("MySQL", "medium"),
    "3389": ("RDP", "medium"),
    "5432": ("PostgreSQL", "medium"),
    "5601": ("Kibana", "medium"),
    "5900": ("VNC", "high"),
    "6379": ("Redis", "high"),
    "9200": ("Elasticsearch", "high"),
    "9300": ("Elasticsearch transport", "medium"),
    "11211": ("Memcached", "high"),
    "27017": ("MongoDB", "high"),
    "27018": ("MongoDB", "medium"),
}


class PortScanner:
    """Orchestrates port scanning tools and records what they find."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.config = ctx.config
        self.runner = ctx.runner
        self.logger = ctx.logger
        self.output_dir = ctx.path("ports")
        self.targets_file = ctx.resolve_file("live_hosts", "dns", "live_hosts.txt")
        os.makedirs(self.output_dir, exist_ok=True)
        self.open_ports: Dict[str, List[str]] = {}
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    def get_output_file(self) -> str:
        return os.path.join(self.output_dir, "all_ports.txt")

    def _clean_targets(self) -> str:
        clean_file = os.path.join(self.output_dir, "scan_targets.txt")
        hosts = []
        for entry in read_file_lines(self.targets_file):
            host = host_from_url(entry)
            if host:
                hosts.append(host)
        hosts = sorted(set(hosts))
        write_file_lines(clean_file, hosts)
        return clean_file

    # ------------------------------------------------------------------
    def run_all(self) -> str:
        self.logger.phase_banner("PORT SCANNING", 4)
        started = time.time()

        if not read_file_lines(self.targets_file):
            self.logger.warning("No live hosts to scan")
            write_file_lines(self.get_output_file(), [])
            return self.get_output_file()

        clean_file = self._clean_targets()
        self.logger.info(f"Scanning ports on {len(read_file_lines(clean_file))} host(s)...")

        if self.config.is_tool_enabled("port_scanning", "naabu"):
            self.run_naabu(clean_file)
        if self.config.is_tool_enabled("port_scanning", "nmap"):
            self.run_nmap(clean_file)
        if self.config.is_tool_enabled("port_scanning", "masscan"):
            self.run_masscan(clean_file)

        self._merge_outputs()
        self._service_findings()
        self._write_outputs()

        self.logger.result(
            f"Port Scanning Complete: {len(read_file_lines(self.get_output_file()))} "
            f"open port(s) in {time.time() - started:.1f}s"
        )
        return self.get_output_file()

    # ------------------------------------------------------------------
    def run_naabu(self, targets_file: str) -> List[str]:
        """naabu with JSON output parsed into host -> ports."""
        output_file = os.path.join(self.output_dir, "naabu.jsonl")
        if self.runner.require("naabu", output_file):
            return []

        cfg = self.config.get_tool_config("port_scanning", "naabu")
        self.logger.info("Running naabu...")
        cmd = [
            "naabu", "-list", targets_file, "-silent", "-json", "-o", output_file,
            "-top-ports", str(cfg.get("top_ports", 1000)),
            "-rate", str(cfg.get("rate", 5000)),
            "-c", str(cfg.get("threads", 25)),
        ]
        scan_type = str(cfg.get("scan_type", "s") or "").strip()
        if scan_type:
            cmd += ["-scan-type", scan_type]

        result = self.runner.run(cmd, tool_name="naabu", timeout=2400)
        if not result.get("success") and "root" in (result.get("stderr") or "").lower():
            self.logger.warning(
                "naabu SYN scan needs root - retrying with a TCP connect scan"
            )
            cmd = [part for part in cmd if part != scan_type]
            cmd += ["-scan-type", "c"]
            self.runner.run(cmd, tool_name="naabu-connect", timeout=2400)

        ports: List[str] = []
        for record in read_json_lines(output_file):
            host = record.get("host") or record.get("ip") or ""
            port = str(record.get("port", ""))
            if not host or not port:
                continue
            self.open_ports.setdefault(host, [])
            if port not in self.open_ports[host]:
                self.open_ports[host].append(port)
            ports.append(f"{host}:{port}")

        if not ports:
            # Older naabu builds may ignore -json; parse the text output instead.
            text_file = os.path.join(self.output_dir, "naabu.txt")
            fallback = [
                "naabu", "-list", targets_file, "-silent",
                "-top-ports", str(cfg.get("top_ports", 1000)),
                "-rate", str(cfg.get("rate", 5000)),
                "-o", text_file,
            ]
            self.runner.run(fallback, tool_name="naabu-text", timeout=2400)
            for line in read_file_lines(text_file):
                if ":" in line:
                    host, _, port = line.rpartition(":")
                    self.open_ports.setdefault(host, []).append(port)
                    ports.append(line)

        self.logger.found(f"naabu: {len(ports)} open port(s)")
        return ports

    def run_nmap(self, targets_file: str) -> None:
        """Service/version detection with nmap (per host, only open ports)."""
        output_dir = os.path.join(self.output_dir, "nmap")
        os.makedirs(output_dir, exist_ok=True)
        if self.runner.require("nmap"):
            return

        cfg = self.config.get_tool_config("port_scanning", "nmap")
        scan_type = str(cfg.get("scan_type", "-sV -sC")).split()
        timing = str(cfg.get("timing", "T4")).lstrip("-")

        if self.open_ports:
            self.logger.info("Running nmap service detection on discovered ports...")
            for host, ports in list(self.open_ports.items())[:50]:
                if not ports:
                    continue
                output_file = os.path.join(
                    output_dir, f"nmap_{host.replace('.', '_').replace(':', '_')}"
                )
                cmd = ["nmap", *scan_type, f"-{timing}", "-p", ",".join(ports),
                       "-oA", output_file, host]
                self.runner.run(cmd, tool_name=f"nmap-{host[:40]}", timeout=900)
        else:
            self.logger.info("Running nmap top-ports scan (no naabu results)...")
            output_file = os.path.join(output_dir, "nmap_scan")
            cmd = ["nmap", *scan_type, f"-{timing}",
                   "--top-ports", str(cfg.get("top_ports", 100)),
                   "-iL", targets_file, "-oA", output_file]
            self.runner.run(cmd, tool_name="nmap", timeout=1800)

        self._collect_nmap_results(output_dir)
        self.logger.found("nmap: service detection complete")

    def _collect_nmap_results(self, output_dir: str) -> None:
        """Parse nmap XML-ish output for open ports (gnmap is simplest)."""
        for name in os.listdir(output_dir):
            if not name.endswith(".gnmap"):
                continue
            with open(os.path.join(output_dir, name), "r", errors="ignore") as fh:
                for line in fh:
                    if "Ports:" not in line:
                        continue
                    host = line.split("Host:", 1)[-1].strip().split(" ", 1)[0]
                    for chunk in line.split("Ports:", 1)[1].split(","):
                        parts = chunk.strip().split("/")
                        if len(parts) >= 2 and parts[1] == "open":
                            port = parts[0]
                            self.open_ports.setdefault(host, [])
                            if port not in self.open_ports[host]:
                                self.open_ports[host].append(port)

    def run_masscan(self, targets_file: str) -> None:
        cfg = self.config.get_tool_config("port_scanning", "masscan")
        if not cfg.get("allow_root", False):
            self.logger.skip(
                "masscan requires raw sockets/root - set "
                "port_scanning.masscan.allow_root: true to run it (SyncHunt never "
                "calls sudo itself)"
            )
            return
        if self.runner.require("masscan"):
            return

        json_file = os.path.join(self.output_dir, "masscan.json")
        self.logger.info("Running masscan...")
        cmd = [
            "masscan", "-iL", targets_file,
            "-p", str(cfg.get("ports", "1-65535")),
            "--rate", str(cfg.get("rate", 10000)),
            "-oJ", json_file, "--open-only",
        ]
        self.runner.run(cmd, tool_name="masscan", timeout=3600)

        data = read_json_lines(json_file) or []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            for record in entry.get("ports", []) or []:
                if record.get("status") != "open":
                    continue
                host = str(record.get("ip", ""))
                port = str(record.get("port", ""))
                if host and port:
                    self.open_ports.setdefault(host, [])
                    if port not in self.open_ports[host]:
                        self.open_ports[host].append(port)

    # ------------------------------------------------------------------
    def _merge_outputs(self) -> None:
        lines = [
            f"{host}:{port}"
            for host, ports in sorted(self.open_ports.items())
            for port in sorted(set(ports), key=lambda p: int(p) if p.isdigit() else 0)
        ]
        write_file_lines(self.get_output_file(), lines)

    def _service_findings(self) -> None:
        for host, ports in self.open_ports.items():
            for port in ports:
                service, severity = RISKY_SERVICES.get(str(port), (None, None))
                if not service:
                    continue
                if severity in ("critical", "high"):
                    self.logger.vuln(f"{host}:{port} exposes {service}")
                self.findings.append(
                    Finding(
                        category="exposure",
                        title=f"Exposed {service} service on port {port}",
                        severity=severity,
                        target=self.ctx.target,
                        url=f"{host}:{port}",
                        evidence=f"Port {port} open ({service})",
                        source="port_scanning",
                        confidence="medium",
                        tags=["network", "exposure"],
                        extra={"host": host, "port": port, "service": service},
                    )
                )

    def _write_outputs(self) -> None:
        save_json(self.open_ports, os.path.join(self.output_dir, "open_ports.json"))
        self.ctx.set_file("ports", self.get_output_file())
        self.ctx.record_assets(
            [
                Asset(
                    kind="port",
                    value=line,
                    host=line.rsplit(":", 1)[0],
                    port=int(line.rsplit(":", 1)[1]) if line.rsplit(":", 1)[1].isdigit() else None,
                    source="port_scanning",
                )
                for line in read_file_lines(self.get_output_file())
            ]
        )
        self.ctx.record_findings(self.findings)
