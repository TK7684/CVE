import requests
from config.settings import settings
from core.logger import log

class Notifier:
    def __init__(self):
        self.webhook_url = settings.DISCORD_WEBHOOK_URL

    def send_alert(self, title, description, severity="MEDIUM", color=None):
        """
        Sends an alert to the configured Discord Webhook.
        """
        if not self.webhook_url:
            log.warning("No Discord Webhook configured. Skipping alert.")
            return

        # Determine color code based on severity if not provided
        if not color:
            if severity == "CRITICAL":
                color = 15158332 # Red
            elif severity == "HIGH":
                color = 15105570 # Orange
            elif severity == "MEDIUM":
                color = 3447003  # Blue
            else:
                color = 3066993  # Green

        payload = {
            "username": "Hunter Bot",
            "embeds": [
                {
                    "title": f"[{severity}] {title}",
                    "description": description,
                    "color": color,
                    "footer": {
                        "text": "The Hunter's Loop Pipeline"
                    }
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            if response.status_code == 204:
                # log.info("[Notifier] Alert Sent Successfully")
                pass
            else:
                log.error(f"[Notifier] Failed to send alert: {response.status_code} - {response.text}")
        except Exception as e:
            log.error(f"[Notifier] Connection Error: {e}")

notifier = Notifier()
