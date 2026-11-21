"""Recommendation mapper — builds prioritised action plans from findings and breaches."""
from __future__ import annotations

from typing import Any

from .models import BreachInfo, ScanFinding


def build_action_plan(
    findings: list[ScanFinding],
    breaches: list[BreachInfo],
) -> dict[str, list[dict[str, Any]]]:
    """
    Build a prioritised action plan.
    Priority order:
    1. Breach with passwords → Today
    2. 2FA gaps → Today
    3. Old account cleanup → This Week
    4. General hygiene → This Month
    """
    today: list[dict[str, Any]] = []
    this_week: list[dict[str, Any]] = []
    this_month: list[dict[str, Any]] = []

    seen_actions: set[str] = set()

    def add_unique(lst: list, item: dict):
        key = item.get("action", "")
        if key not in seen_actions:
            seen_actions.add(key)
            lst.append(item)

    # 1. Breach-related actions (highest priority)
    for breach in breaches:
        has_passwords = any(
            dc.lower() in ("passwords", "password")
            for dc in breach.data_classes
        )
        if has_passwords:
            add_unique(today, {
                "action": f"Change passwords exposed in the {breach.name} breach",
                "guide_id": "password-manager",
                "guide_title": "Start Using a Password Manager",
                "priority": "today",
                "source": f"breach:{breach.name}",
            })
            add_unique(today, {
                "action": f"Enable 2FA on accounts affected by {breach.name}",
                "guide_id": "enable-2fa",
                "guide_title": "Enable Two-Factor Authentication (2FA)",
                "priority": "today",
                "source": f"breach:{breach.name}",
            })

        if any(dc.lower() in ("phone numbers", "phone") for dc in breach.data_classes):
            add_unique(this_week, {
                "action": f"Review phone number privacy after {breach.name}",
                "guide_id": None,
                "guide_title": None,
                "priority": "this_week",
                "source": f"breach:{breach.name}",
            })

        if any(dc.lower() in ("physical addresses", "addresses") for dc in breach.data_classes):
            add_unique(this_week, {
                "action": "Consider requesting data broker removal",
                "guide_id": "data-broker-removal",
                "guide_title": "Request Removal from Data Brokers",
                "priority": "this_week",
                "source": f"breach:{breach.name}",
            })

    # 2. Account-found actions
    found_accounts = [f for f in findings if f.status in ("indicator_found", "likely")]
    for finding in found_accounts:
        add_unique(this_week, {
            "action": f"Review and secure your {finding.service_name} account",
            "guide_id": finding.guide_id or finding.service_id,
            "guide_title": finding.guide_title or f"Delete or Secure Your {finding.service_name} Account",
            "priority": "this_week",
            "source": f"finding:{finding.service_id}",
        })

    # 3. General monthly hygiene
    add_unique(this_month, {
        "action": "Set up email aliases for better privacy",
        "guide_id": "email-aliases",
        "guide_title": "Set Up Email Aliases for Better Privacy",
        "priority": "this_month",
        "source": "general",
    })
    add_unique(this_month, {
        "action": "Review third-party app access on your accounts",
        "guide_id": "google-third-party-apps",
        "guide_title": "Review Third-Party App Access on Your Google Account",
        "priority": "this_month",
        "source": "general",
    })
    add_unique(this_month, {
        "action": "Remove EXIF metadata from photos before sharing",
        "guide_id": "remove-exif-metadata",
        "guide_title": "Remove EXIF Metadata from Photos",
        "priority": "this_month",
        "source": "general",
    })

    return {
        "today": today,
        "this_week": this_week,
        "this_month": this_month,
    }
