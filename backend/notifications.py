"""Phone & External Alert Notifications for OmniGuard SOC.

Supports instant push notifications to an analyst's phone without requiring a
custom native mobile app:
  1. ntfy       (NTFY_TOPIC, optional NTFY_SERVER default https://ntfy.sh)
  2. Telegram   (TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)
  3. Webhook    (ALERT_WEBHOOK_URL — Discord / Slack / generic JSON)

All dispatches are non-blocking / fail-safe so a flaky network during a closed
LAN demo can never slow down or break alert ingestion.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import httpx

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_config: dict[str, Any] = {
    "enabled": os.getenv("NOTIFICATIONS_ENABLED", "1").strip().lower() not in ("0", "false", "no", "off", ""),
    "min_severity": os.getenv("NOTIFY_MIN_SEVERITY", "high").strip().lower(),
    "ntfy_server": os.getenv("NTFY_SERVER", "https://ntfy.sh").strip().rstrip("/"),
    "ntfy_topic": os.getenv("NTFY_TOPIC", "").strip(),
    "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
    "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", "").strip(),
    "webhook_url": os.getenv("ALERT_WEBHOOK_URL", "").strip(),
    "dashboard_url": os.getenv("DASHBOARD_PUBLIC_URL", "http://localhost:5173").strip().rstrip("/"),
}

_recent_deliveries: list[dict[str, Any]] = []
_MAX_HISTORY = 30


def get_notification_status() -> dict[str, Any]:
    """Return current notification configuration (with secrets redacted) and recent deliveries."""
    channels = {
        "ntfy": bool(_config["ntfy_topic"]),
        "telegram": bool(_config["telegram_bot_token"] and _config["telegram_chat_id"]),
        "webhook": bool(_config["webhook_url"]),
    }
    return {
        "enabled": _config["enabled"],
        "min_severity": _config["min_severity"],
        "dashboard_url": _config["dashboard_url"],
        "ntfy_server": _config["ntfy_server"],
        "ntfy_topic": _config["ntfy_topic"],
        "telegram_configured": channels["telegram"],
        "webhook_configured": channels["webhook"],
        "active_channels": [k for k, v in channels.items() if v],
        "recent_deliveries": _recent_deliveries[:10],
    }


def configure_notifications(
    *,
    enabled: bool | None = None,
    min_severity: str | None = None,
    ntfy_server: str | None = None,
    ntfy_topic: str | None = None,
    telegram_bot_token: str | None = None,
    telegram_chat_id: str | None = None,
    webhook_url: str | None = None,
    dashboard_url: str | None = None,
) -> dict[str, Any]:
    """Update notification settings at runtime (useful during live demo setup)."""
    if enabled is not None:
        _config["enabled"] = bool(enabled)
    if min_severity is not None and min_severity.lower() in SEVERITY_RANK:
        _config["min_severity"] = min_severity.lower()
    if ntfy_server is not None:
        _config["ntfy_server"] = ntfy_server.strip().rstrip("/") or "https://ntfy.sh"
    if ntfy_topic is not None:
        _config["ntfy_topic"] = ntfy_topic.strip()
    if telegram_bot_token is not None:
        _config["telegram_bot_token"] = telegram_bot_token.strip()
    if telegram_chat_id is not None:
        _config["telegram_chat_id"] = telegram_chat_id.strip()
    if webhook_url is not None:
        _config["webhook_url"] = webhook_url.strip()
    if dashboard_url is not None:
        _config["dashboard_url"] = dashboard_url.strip().rstrip("/")
    return get_notification_status()


def _record_delivery(channel: str, ok: bool, title: str, detail: str = "") -> dict[str, Any]:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "ok": ok,
        "title": title,
        "detail": detail,
    }
    _recent_deliveries.insert(0, entry)
    if len(_recent_deliveries) > _MAX_HISTORY:
        del _recent_deliveries[_MAX_HISTORY:]
    return entry


def _should_notify(alert: dict[str, Any], force: bool = False) -> bool:
    if not _config["enabled"]:
        return False
    if force:
        return True
    sev = str(alert.get("severity", "low")).lower()
    min_sev = _config.get("min_severity", "high")
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(min_sev, 3)


def _format_alert_message(alert: dict[str, Any], proposal: dict[str, Any] | None = None) -> tuple[str, str, str]:
    sev = str((proposal or {}).get("severity") or alert.get("severity") or "high").upper()
    host = alert.get("host") or "unknown-host"
    event = alert.get("event_type") or "Security Alert"
    source = alert.get("source") or "omniguard"
    alert_id = alert.get("alert_id") or ""
    title = f"[{sev}] OmniGuard: {event} on {host}"

    lines = [
        f"Host: {host}",
        f"Source: {source} | Severity: {sev}",
    ]
    if alert.get("domain"):
        lines.append(f"Domain: {alert['domain']}")
    if alert.get("dst_ip"):
        lines.append(f"Dest IP: {alert['dst_ip']}")
    if proposal:
        verdict = str(proposal.get("verdict", "")).replace("_", " ").title()
        actions = ", ".join(proposal.get("actions") or [])
        lines.append(f"Live AI Verdict: {verdict}" + (f" (Suggests: {actions})" if actions else ""))
        if proposal.get("summary"):
            lines.append(f"AI Summary: {proposal['summary']}")
    elif alert.get("description"):
        lines.append(str(alert["description"])[:220])

    link = f"{_config['dashboard_url']}/?alert={alert_id}" if alert_id else _config["dashboard_url"]
    lines.append(f"Open SOC: {link}")
    return title, "\n".join(lines), link


def _send_ntfy(title: str, body: str, link: str, severity: str = "high") -> dict[str, Any]:
    topic = _config["ntfy_topic"]
    url = f"{_config['ntfy_server']}/{topic}"
    priority = "urgent" if severity == "critical" else "high" if severity == "high" else "default"
    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": "rotating_light,shield" if severity in ("critical", "high") else "shield",
        "Click": link,
    }
    try:
        resp = httpx.post(url, content=body.encode("utf-8"), headers=headers, timeout=5.0)
        resp.raise_for_status()
        return _record_delivery("ntfy", True, title, f"HTTP {resp.status_code}")
    except Exception as e:
        return _record_delivery("ntfy", False, title, str(e))


def _send_telegram(title: str, body: str) -> dict[str, Any]:
    token = _config["telegram_bot_token"]
    chat_id = _config["telegram_chat_id"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    text = f"🚨 {title}\n\n{body}"
    try:
        resp = httpx.post(url, json={"chat_id": chat_id, "text": text}, timeout=5.0)
        resp.raise_for_status()
        return _record_delivery("telegram", True, title, f"HTTP {resp.status_code}")
    except Exception as e:
        return _record_delivery("telegram", False, title, str(e))


def _send_webhook(title: str, body: str, link: str, alert: dict[str, Any]) -> dict[str, Any]:
    url = _config["webhook_url"]
    payload = {
        "title": title,
        "content": f"**{title}**\n{body}",
        "text": f"*{title}*\n{body}",
        "link": link,
        "alert_id": alert.get("alert_id"),
        "host": alert.get("host"),
        "severity": alert.get("severity"),
    }
    try:
        resp = httpx.post(url, json=payload, timeout=5.0)
        resp.raise_for_status()
        return _record_delivery("webhook", True, title, f"HTTP {resp.status_code}")
    except Exception as e:
        return _record_delivery("webhook", False, title, str(e))


def dispatch_alert_notification(
    alert: dict[str, Any],
    proposal: dict[str, Any] | None = None,
    force: bool = False,
) -> list[dict[str, Any]]:
    """Synchronously dispatch push notifications across all configured channels."""
    if not _should_notify(alert, force=force):
        return []

    title, body, link = _format_alert_message(alert, proposal=proposal)
    sev = str((proposal or {}).get("severity") or alert.get("severity") or "high").lower()
    results: list[dict[str, Any]] = []

    if _config["ntfy_topic"]:
        results.append(_send_ntfy(title, body, link, severity=sev))
    if _config["telegram_bot_token"] and _config["telegram_chat_id"]:
        results.append(_send_telegram(title, body))
    if _config["webhook_url"]:
        results.append(_send_webhook(title, body, link, alert))
    return results


def send_test_notification(note: str = "Test alert from OmniGuard SOC") -> dict[str, Any]:
    """Send a manual test notification to verify phone delivery before a demo."""
    sample = {
        "alert_id": "test-notification",
        "host": "DEMO-WORKSTATION",
        "event_type": "Test Phone Notification",
        "severity": "critical",
        "source": "omniguard",
        "description": note,
    }
    results = dispatch_alert_notification(sample, force=True)
    return {
        "sent": len(results),
        "results": results,
        "active_channels": get_notification_status()["active_channels"],
    }
