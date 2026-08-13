"""
CyberSentinel WAF - Notification Dispatcher & Channel Handlers
"""
import logging
import smtplib
import json
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Tuple, Optional
from abc import ABC, abstractmethod
import datetime as dt_module

logger = logging.getLogger(__name__)


def _validate_outbound_url(url: str) -> Optional[str]:
    """
    Blocks SSRF via admin-configured Slack/generic-webhook URLs: an admin
    session (or a compromised one) could otherwise point an alert channel at
    an internal service or the cloud metadata endpoint
    (169.254.169.254) and have the backend fetch it on every alert. Returns
    an error string if the URL should be rejected, or None if it's fine to
    dispatch to.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "Invalid URL."

    if parsed.scheme not in ("http", "https"):
        return "Webhook URL must use http or https."
    if not parsed.hostname:
        return "Webhook URL is missing a host."

    try:
        addrs = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as e:
        return f"Could not resolve webhook host: {e}"

    for family, _, _, _, sockaddr in addrs:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        ):
            return f"Webhook host resolves to a non-public address ({ip_str}) — not allowed."

    return None


class BaseNotificationChannel(ABC):
    """Abstract base class for all alert channels"""

    @abstractmethod
    def send(self, config: Dict[str, Any], severity: str, event_type: str, message: str, event_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Send notification.
        Returns (success: bool, error_message: Optional[str])
        """
        pass


class EmailNotificationChannel(BaseNotificationChannel):
    """Sends alerts via SMTP Email"""

    def send(self, config: Dict[str, Any], severity: str, event_type: str, message: str, event_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        try:
            smtp_host = config.get("smtp_host")
            smtp_port = config.get("smtp_port", 587)
            username = config.get("username")
            password = config.get("password")  # Note: Should ideally be decrypted if stored encrypted
            from_addr = config.get("from_addr")
            to_addrs = config.get("to_addrs", [])
            use_tls = config.get("use_tls", True)
            use_ssl = config.get("use_ssl", False)

            if not smtp_host or not from_addr or not to_addrs:
                return False, "Missing SMTP host, from address, or recipient addresses."

            # Construct email message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"WAF Alert: [{severity.upper()}] {event_type}"
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addrs)

            html_body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; color: #333; }}
                    .container {{ padding: 20px; border-radius: 6px; border: 1px solid #e5e7eb; max-width: 600px; }}
                    .header {{ padding: 12px 20px; border-radius: 4px 4px 0 0; color: #fff; font-weight: bold; }}
                    .critical {{ background-color: #dc2626; }}
                    .high {{ background-color: #ea580c; }}
                    .medium {{ background-color: #eab308; }}
                    .low {{ background-color: #3b82f6; }}
                    .info {{ background-color: #6b7280; }}
                    .content {{ padding: 20px 0; }}
                    .details {{ background-color: #f3f4f6; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 13px; white-space: pre-wrap; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header {severity.lower()}">
                        🚨 CyberSentinel WAF - {severity.upper()} Alert
                    </div>
                    <div class="content">
                        <p><strong>Event:</strong> {event_type}</p>
                        <p><strong>Time:</strong> {dt_module.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                        <p><strong>Message:</strong> {message}</p>
                        <h3>Event Details:</h3>
                        <div class="details">{json.dumps(event_data, indent=2)}</div>
                    </div>
                </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(message, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # Connect and send
            if use_ssl:
                server = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10)
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)

            if use_tls and not use_ssl:
                server.starttls()

            if username and password:
                server.login(username, password)

            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
            return True, None
        except Exception as e:
            logger.error(f"Email notification dispatch failed: {e}")
            return False, str(e)


class SlackNotificationChannel(BaseNotificationChannel):
    """Sends alerts via Slack Webhooks"""

    def send(self, config: Dict[str, Any], severity: str, event_type: str, message: str, event_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        try:
            webhook_url = config.get("webhook_url")
            channel = config.get("channel")
            username = config.get("username", "WAF Alert Bot")
            icon_emoji = config.get("icon_emoji", ":shield:")

            if not webhook_url:
                return False, "Missing Slack Webhook URL."

            ssrf_error = _validate_outbound_url(webhook_url)
            if ssrf_error:
                return False, ssrf_error

            # Determine severity color
            color = "#6b7280"  # info
            if severity.lower() == "critical":
                color = "#dc2626"
            elif severity.lower() == "high":
                color = "#ea580c"
            elif severity.lower() == "medium":
                color = "#eab308"
            elif severity.lower() == "low":
                color = "#3b82f6"

            payload = {
                "username": username,
                "icon_emoji": icon_emoji,
                "attachments": [
                    {
                        "fallback": f"WAF Alert: {message}",
                        "color": color,
                        "title": f"🚨 CyberSentinel WAF Alert - {severity.upper()}",
                        "text": message,
                        "fields": [
                            {"title": "Event Type", "value": event_type, "short": True},
                            {"title": "Severity", "value": severity.upper(), "short": True},
                            {
                                "title": "Details",
                                "value": f"```\n{json.dumps(event_data, indent=2)[:1000]}\n```",
                                "short": False,
                            },
                        ]
                    }
                ],
            }
            if channel:
                payload["channel"] = channel

            res = requests.post(webhook_url, json=payload, timeout=10)
            if res.status_code == 200:
                return True, None
            else:
                return False, f"Slack webhook returned status code {res.status_code}: {res.text}"
        except Exception as e:
            logger.error(f"Slack notification dispatch failed: {e}")
            return False, str(e)


class WebhookNotificationChannel(BaseNotificationChannel):
    """Sends alerts via Generic HTTP Webhooks"""

    def send(self, config: Dict[str, Any], severity: str, event_type: str, message: str, event_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        try:
            url = config.get("url")
            method = config.get("method", "POST").upper()
            headers = config.get("headers", {})
            timeout = config.get("timeout", 10)
            # verify_ssl is intentionally NOT read from admin config anymore —
            # letting the UI disable TLS verification on an outbound webhook
            # is a pointless downgrade knob with no legitimate use case here
            # and a real MITM/credential-exposure risk if ever flipped.
            verify_ssl = True

            if not url:
                return False, "Missing Webhook URL."

            ssrf_error = _validate_outbound_url(url)
            if ssrf_error:
                return False, ssrf_error

            payload = {
                "event_type": event_type,
                "severity": severity,
                "message": message,
                "event_data": event_data,
                "timestamp": dt_module.datetime.utcnow().isoformat() + "Z"
            }

            headers.setdefault("Content-Type", "application/json")

            if method == "PUT":
                res = requests.put(url, json=payload, headers=headers, timeout=timeout, verify=verify_ssl)
            else:
                res = requests.post(url, json=payload, headers=headers, timeout=timeout, verify=verify_ssl)

            if 200 <= res.status_code < 300:
                return True, None
            else:
                return False, f"Webhook returned status code {res.status_code}: {res.text}"
        except Exception as e:
            logger.error(f"Webhook notification dispatch failed: {e}")
            return False, str(e)


class PagerDutyNotificationChannel(BaseNotificationChannel):
    """Sends alerts via PagerDuty Events API v2"""

    def send(self, config: Dict[str, Any], severity: str, event_type: str, message: str, event_data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        try:
            integration_key = config.get("integration_key")
            severity_mapping = config.get("severity_mapping", {
                "critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"
            })

            if not integration_key:
                return False, "Missing PagerDuty Integration Key."

            pd_severity = severity_mapping.get(severity.lower(), "error")

            payload = {
                "routing_key": integration_key,
                "event_action": "trigger",
                "payload": {
                    "summary": message,
                    "source": "CyberSentinel WAF",
                    "severity": pd_severity,
                    "component": "WAF Engine",
                    "group": event_type,
                    "custom_details": event_data
                }
            }

            url = "https://events.pagerduty.com/v2/enqueue"
            res = requests.post(url, json=payload, timeout=10)
            if res.status_code in (200, 202):
                return True, None
            else:
                return False, f"PagerDuty API returned status code {res.status_code}: {res.text}"
        except Exception as e:
            logger.error(f"PagerDuty notification dispatch failed: {e}")
            return False, str(e)


class NotificationDispatcher:
    """Manages routing of alert notifications to specific channels"""

    def __init__(self):
        self.channels = {
            "email": EmailNotificationChannel(),
            "slack": SlackNotificationChannel(),
            "webhook": WebhookNotificationChannel(),
            "pagerduty": PagerDutyNotificationChannel(),
        }
        self.executor = ThreadPoolExecutor(max_workers=5)

    def dispatch(self, channels_list: List[Dict[str, Any]], severity: str, event_type: str, message: str, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Dispatches alerts to multiple channels in parallel.
        Returns a list of logs containing status and errors.
        """
        futures = []
        for channel in channels_list:
            c_type = channel.get("channel_type")
            c_name = channel.get("name")
            c_config = channel.get("config")
            
            # Safely parse config if it's stored as a string
            if isinstance(c_config, str):
                try:
                    c_config = json.loads(c_config)
                except Exception:
                    pass

            handler = self.channels.get(c_type)
            if not handler:
                logger.warning(f"No handler registered for channel type: {c_type}")
                futures.append((c_name, False, f"Unsupported channel type: {c_type}"))
                continue

            if not channel.get("enabled", True):
                continue

            # Submit dispatch task
            def task(h=handler, cfg=c_config, name=c_name):
                success, err = h.send(cfg, severity, event_type, message, event_data)
                return name, success, err

            futures.append(self.executor.submit(task))

        results = []
        for f in futures:
            if isinstance(f, tuple):
                # Handle early failures (e.g. Unsupported channel type)
                results.append({
                    "channel_name": f[0],
                    "success": f[1],
                    "error": f[2]
                })
                continue
            try:
                name, success, err = f.result(timeout=15)
                results.append({
                    "channel_name": name,
                    "success": success,
                    "error": err
                })
            except Exception as e:
                logger.error(f"Failed to retrieve dispatch result: {e}")
                results.append({
                    "channel_name": "unknown",
                    "success": False,
                    "error": str(e)
                })

        return results


# Global notification dispatcher instance
notification_dispatcher = NotificationDispatcher()
