"""HITL notifier (PRD §9.10.4) - alert reviewers via Slack and PagerDuty.

Posts a structured card to a configured Slack webhook (per-tenant or global) when a flag is routed
for review. PagerDuty is a thin stub for critical-only; no-op unless configured. Both classes
return ``False`` cleanly when their respective webhooks are not configured so callers can branch
without catching exceptions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from auditor.logging import get_logger

if TYPE_CHECKING:
    from auditor.verdicts.aggregator import Flag

log = get_logger("auditor.hitl.notifier")


class SlackNotifier:
    """Post a flag-card to a Slack incoming-webhook URL.

    Parameters
    ----------
    webhook_url:
        The Slack webhook URL. If ``None`` or empty the notifier is a no-op.
    """

    def __init__(self, webhook_url: str | None = None) -> None:
        if webhook_url is None:
            # Fall back to settings if nothing was injected.
            try:
                from auditor.config import get_settings

                settings = get_settings()
                # Settings doesn't have a slack field yet; tolerate AttributeError.
                webhook_url = getattr(settings, "slack_webhook_url", None)
            except Exception:  # noqa: BLE001
                webhook_url = None
        self._webhook_url: str | None = webhook_url or None

    @property
    def configured(self) -> bool:
        return bool(self._webhook_url)

    async def notify(self, flag: Flag, *, ui_url: str | None = None) -> bool:
        """Post a Slack card for *flag*.  Returns ``False`` when unconfigured."""
        if not self.configured:
            log.debug("hitl.notifier.slack.unconfigured", flag_id=str(flag.flag_id))
            return False

        card = _build_slack_card(flag, ui_url=ui_url)

        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._webhook_url, json=card)  # type: ignore[arg-type]
                resp.raise_for_status()
            log.info(
                "hitl.notifier.slack.sent",
                flag_id=str(flag.flag_id),
                severity=flag.severity,
            )
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "hitl.notifier.slack.failed",
                flag_id=str(flag.flag_id),
                error=str(exc),
            )
            return False


def _build_slack_card(flag: Flag, *, ui_url: str | None) -> dict:
    """Construct a Slack Block Kit payload for *flag*."""
    categories_str = ", ".join(flag.asi_categories) if flag.asi_categories else "-"
    link_text = f"\n<{ui_url}|View flag>  " if ui_url else ""
    text = (
        f"*[{flag.severity.upper()}] HITL Flag Raised*\n"
        f"• `flag_id`: `{flag.flag_id}`\n"
        f"• `run_id`: `{flag.run_id}`\n"
        f"• `tenant_id`: `{flag.tenant_id}`\n"
        f"• Categories: `{categories_str}`\n"
        f"• Confidence: `{flag.confidence}`\n"
        f"{link_text}"
    )
    return {
        "text": f"[{flag.severity.upper()}] HITL flag {flag.flag_id} for run {flag.run_id}",
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
        ],
    }


class PagerDutyNotifier:
    """Thin stub for PagerDuty critical-only notifications.

    Currently a no-op unless ``pagerduty_routing_key`` is set in settings or injected.
    Designed so that replacing the body with a real ``pdpyras`` or ``httpx`` call
    requires no interface changes.
    """

    def __init__(self, routing_key: str | None = None) -> None:
        if routing_key is None:
            try:
                from auditor.config import get_settings

                settings = get_settings()
                routing_key = getattr(settings, "pagerduty_routing_key", None)
            except Exception:  # noqa: BLE001
                routing_key = None
        self._routing_key: str | None = routing_key or None

    @property
    def configured(self) -> bool:
        return bool(self._routing_key)

    async def notify(self, flag: Flag, *, ui_url: str | None = None) -> bool:
        """Trigger a PagerDuty alert for critical flags.  Returns ``False`` when unconfigured."""
        if not self.configured:
            log.debug("hitl.notifier.pagerduty.unconfigured", flag_id=str(flag.flag_id))
            return False

        # Stub body - replace with real PD Events v2 POST when routing key is available.
        log.warning(
            "hitl.notifier.pagerduty.stub",
            flag_id=str(flag.flag_id),
            message="PagerDuty notifier is a stub; configure pdpyras to enable real alerts.",
        )
        return False


__all__ = ["SlackNotifier", "PagerDutyNotifier"]
