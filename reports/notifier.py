"""
SyncHunt - Notification System
Send scan summaries and critical findings to Slack, Discord or Telegram.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import requests

from core.utils import truncate

MAX_MESSAGE = 3500


class Notifier:
    """Send notifications about scan results."""

    def __init__(self, config, logger=None):
        self.config = config
        self.logger = logger

    # ------------------------------------------------------------------
    def _log(self, level: str, message: str) -> None:
        if self.logger is None:
            return
        handler = getattr(self.logger, level, None)
        if callable(handler):
            handler(message)

    @property
    def enabled(self) -> bool:
        return self.config.get_bool("notifications.enabled", False)

    def notify_all(self, message: str, critical: bool = False) -> Dict[str, bool]:
        """Send a notification to every enabled channel."""
        results: Dict[str, bool] = {}
        if not self.enabled:
            self._log("debug", "notifications disabled - skipping")
            return results

        message = truncate(message, MAX_MESSAGE)

        if self.config.get_bool("notifications.slack.enabled", False):
            results["slack"] = self.send_slack(message)
        if self.config.get_bool("notifications.discord.enabled", False):
            results["discord"] = self.send_discord(message)
        if self.config.get_bool("notifications.telegram.enabled", False):
            results["telegram"] = self.send_telegram(message)
        return results

    # ------------------------------------------------------------------
    def _post(self, url: str, payload: dict, ok_statuses=(200, 204)) -> bool:
        try:
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code in ok_statuses:
                return True
            self._log("warning", f"notification failed: HTTP {response.status_code}")
        except requests.RequestException as exc:
            self._log("warning", f"notification error: {exc}")
        return False

    def send_slack(self, message: str) -> bool:
        webhook_url = self.config.get("notifications.slack.webhook_url", "")
        if not webhook_url:
            return False
        payload = {
            "text": message,
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🔎 SyncHunt*\n{message}"},
                }
            ],
        }
        sent = self._post(webhook_url, payload)
        if sent:
            self._log("debug", "Slack notification sent")
        return sent

    def send_discord(self, message: str) -> bool:
        webhook_url = self.config.get("notifications.discord.webhook_url", "")
        if not webhook_url:
            return False
        payload = {"content": f"**🔎 SyncHunt**\n{message}", "username": "SyncHunt"}
        sent = self._post(webhook_url, payload)
        if sent:
            self._log("debug", "Discord notification sent")
        return sent

    def send_telegram(self, message: str) -> bool:
        bot_token = self.config.get("notifications.telegram.bot_token", "")
        chat_id = self.config.get("notifications.telegram.chat_id", "")
        if not bot_token or not chat_id:
            return False
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": f"🔎 SyncHunt\n\n{message}"}
        sent = self._post(url, payload)
        if sent:
            self._log("debug", "Telegram notification sent")
        return sent

    # ------------------------------------------------------------------
    def send_scan_summary(self, target: str, stats: Dict, extra: Optional[Dict] = None) -> None:
        lines: List[str] = [f"*Target:* {target}", "*Results:*"]
        for key in ("subdomains", "live_hosts", "open_ports", "urls", "vulnerabilities", "secrets"):
            if key in stats:
                label = key.replace("_", " ").title()
                lines.append(f"  • {label}: {stats[key]}")
        severity = (extra or {}).get("severity") or {}
        if severity:
            lines.append(
                "  • Severity: "
                + ", ".join(f"{k}={v}" for k, v in severity.items() if v)
            )
        self.notify_all("\n".join(lines))

    def send_critical_finding(self, finding: str) -> None:
        """Push a critical finding to every enabled channel."""
        if not self.enabled:
            return
        self.notify_all(f"🚨 CRITICAL FINDING\n\n{truncate(finding, 1500)}", critical=True)

    def send_critical_findings(self, findings) -> int:
        """Notify about up to 10 critical/high findings; returns count sent."""
        sent = 0
        for finding in findings or []:
            severity = (finding.severity or "").lower()
            if severity in ("critical", "high"):
                self.send_critical_finding(
                    f"[{finding.severity.upper()}] {finding.title}\n{finding.url}\n{finding.evidence[:300]}"
                )
                sent += 1
                if sent >= 10:
                    break
        return sent
