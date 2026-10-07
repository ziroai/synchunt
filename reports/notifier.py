"""
BugHuntRecon - Notification System
Send alerts via Slack, Discord, or Telegram.
"""

import json
import requests


class Notifier:
    """Send notifications about scan results."""

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def notify_all(self, message, critical=False):
        """Send notification to all configured channels."""
        if not self.config.get('notifications.enabled', False):
            return

        if self.config.get('notifications.slack.enabled', False):
            self.send_slack(message)

        if self.config.get('notifications.discord.enabled', False):
            self.send_discord(message)

        if self.config.get('notifications.telegram.enabled', False):
            self.send_telegram(message)

    def send_slack(self, message):
        """Send notification to Slack."""
        webhook_url = self.config.get('notifications.slack.webhook_url', '')
        if not webhook_url:
            return

        try:
            payload = {
                "text": message,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"🔥 *BugHuntRecon Alert*\n{message}"
                        }
                    }
                ]
            }

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                self.logger.debug("Slack notification sent")
            else:
                self.logger.warning(f"Slack notification failed: {response.status_code}")

        except Exception as e:
            self.logger.warning(f"Slack notification error: {e}")

    def send_discord(self, message):
        """Send notification to Discord."""
        webhook_url = self.config.get('notifications.discord.webhook_url', '')
        if not webhook_url:
            return

        try:
            payload = {
                "content": f"🔥 **BugHuntRecon Alert**\n{message}",
                "username": "BugHuntRecon"
            }

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code in [200, 204]:
                self.logger.debug("Discord notification sent")
            else:
                self.logger.warning(f"Discord notification failed: {response.status_code}")

        except Exception as e:
            self.logger.warning(f"Discord notification error: {e}")

    def send_telegram(self, message):
        """Send notification to Telegram."""
        bot_token = self.config.get('notifications.telegram.bot_token', '')
        chat_id = self.config.get('notifications.telegram.chat_id', '')

        if not bot_token or not chat_id:
            return

        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": f"🔥 BugHuntRecon Alert\n\n{message}",
                "parse_mode": "HTML"
            }

            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                self.logger.debug("Telegram notification sent")
            else:
                self.logger.warning(f"Telegram notification failed: {response.status_code}")

        except Exception as e:
            self.logger.warning(f"Telegram notification error: {e}")

    def send_scan_summary(self, target, stats):
        """Send a scan summary notification."""
        message = (
            f"🎯 Target: {target}\n"
            f"📊 Results:\n"
            f"  • Subdomains: {stats.get('subdomains', 0)}\n"
            f"  • Live Hosts: {stats.get('live_hosts', 0)}\n"
            f"  • Open Ports: {stats.get('open_ports', 0)}\n"
            f"  • URLs: {stats.get('urls', 0)}\n"
            f"  • Vulnerabilities: {stats.get('vulns', 0)}\n"
            f"  • Secrets: {stats.get('secrets', 0)}\n"
        )

        self.notify_all(message)

    def send_critical_finding(self, finding):
        """Send notification for critical findings."""
        message = f"🚨 CRITICAL FINDING\n\n{finding}"
        self.notify_all(message, critical=True)