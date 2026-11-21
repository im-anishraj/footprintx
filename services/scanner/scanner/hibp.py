"""HIBP (Have I Been Pwned) integration."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from .models import BreachInfo


# HIBP rate limit: respect Retry-After
_HIBP_BASE = "https://haveibeenpwned.com/api/v3"


async def check_breaches(email: str, api_key: str) -> list[BreachInfo]:
    """
    Check HIBP for breaches associated with an email.
    Returns list of BreachInfo objects.
    Honours rate limits and Retry-After headers.
    """
    breaches: list[BreachInfo] = []

    async with httpx.AsyncClient(timeout=15) as client:
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "FootprintX-Scanner",
        }

        for attempt in range(3):
            resp = await client.get(
                f"{_HIBP_BASE}/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
            )

            if resp.status_code == 200:
                data = resp.json()
                for breach_data in data:
                    data_classes = breach_data.get("DataClasses", [])
                    actions = _breach_actions(breach_data.get("Name", ""), data_classes)
                    breaches.append(BreachInfo(
                        name=breach_data.get("Name", "Unknown"),
                        date=breach_data.get("BreachDate", "Unknown"),
                        data_classes=data_classes,
                        description=breach_data.get("Description", ""),
                        actions=actions,
                    ))
                break

            elif resp.status_code == 404:
                # No breaches found
                break

            elif resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "2"))
                await asyncio.sleep(retry_after)
                continue

            else:
                break

    return breaches


def _breach_actions(breach_name: str, data_classes: list[str]) -> list[dict[str, Any]]:
    """Generate recommended actions based on exposed data classes."""
    actions: list[dict[str, Any]] = []

    if "Passwords" in data_classes:
        actions.append({
            "action": f"Change your password (exposed in {breach_name})",
            "priority": "today",
            "guide_id": "password-manager",
        })
        actions.append({
            "action": f"Enable 2FA (password exposed in {breach_name})",
            "priority": "today",
            "guide_id": "enable-2fa",
        })

    if "Phone numbers" in data_classes:
        actions.append({
            "action": "Review and update phone number privacy settings",
            "priority": "this_week",
        })

    if "Physical addresses" in data_classes:
        actions.append({
            "action": "Consider requesting data broker removal",
            "priority": "this_week",
            "guide_id": "data-broker-removal",
        })

    if "IP addresses" in data_classes:
        actions.append({
            "action": "Consider using a VPN for sensitive activities",
            "priority": "this_month",
        })

    if not actions:
        actions.append({
            "action": f"Review your account security after {breach_name} breach",
            "priority": "this_week",
        })

    return actions
