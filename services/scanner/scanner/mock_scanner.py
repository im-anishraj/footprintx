"""Mock scanner for development and testing."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from .models import BreachInfo, ScanFinding, ScanResultPayload


class MockScanner:
    """
    Deterministic mock scanner that returns plausible fixture data.
    Results are based on a hash of the email, so the same email always
    produces the same results. All data is clearly synthetic.
    """

    def __init__(self, allowed_modules: dict[str, dict[str, Any]]):
        self.allowed_modules = allowed_modules

    def _email_hash_int(self, email: str) -> int:
        """Deterministic hash of email for consistent mock results."""
        return int(hashlib.sha256(email.encode()).hexdigest(), 16)

    async def scan(self, email: str) -> ScanResultPayload:
        """Generate deterministic mock results."""
        h = self._email_hash_int(email)
        now = datetime.now(timezone.utc).isoformat()

        # Mask email
        if "@" in email:
            local, domain = email.rsplit("@", 1)
            masked = (local[:2] + "***") if len(local) > 2 else (local[0] + "***")
            masked_email = f"{masked}@{domain}"
        else:
            masked_email = "***@***.***"

        findings: list[ScanFinding] = []
        total = len(self.allowed_modules)
        done = 0
        failed = 0

        for i, (module_name, module_info) in enumerate(self.allowed_modules.items()):
            # Deterministically decide status based on hash + index
            bucket = (h + i * 7) % 10
            if bucket < 3:
                status = "indicator_found"
                confidence = "medium"
            elif bucket < 4:
                status = "likely"
                confidence = "low"
            elif bucket < 8:
                status = "not_detected"
                confidence = "medium"
            elif bucket == 8:
                status = "unknown"
                confidence = "low"
            else:
                status = "rate_limited"
                confidence = "low"

            explanation = {
                "indicator_found": f"An account may be associated with this email on {module_info['name']}.",
                "likely": f"An account is likely associated with this email on {module_info['name']}.",
                "not_detected": f"No account indicator was detected on {module_info['name']}.",
                "unknown": f"The check for {module_info['name']} returned an inconclusive result.",
                "rate_limited": f"The check for {module_info['name']} was rate-limited.",
            }

            findings.append(ScanFinding(
                service_id=module_info["id"],
                service_name=module_info["name"],
                category=module_info.get("category", "other"),
                sensitivity=module_info.get("sensitivity", "low"),
                status=status,
                status_label=status.replace("_", " ").title(),
                confidence=confidence,
                evidence_type="mock_check",
                engine={"name": "mock", "version": "1.0", "module_health": "healthy"},
                checked_at=now,
                explanation=explanation.get(status, ""),
                actions=[],
                guide_id=module_info["id"],
                guide_title=f"Delete or Secure Your {module_info['name']} Account",
            ))
            done += 1

        # Mock breaches (deterministic based on hash)
        breaches: list[BreachInfo] = []
        if h % 3 == 0:
            breaches.append(BreachInfo(
                name="ExampleBreachCo [SAMPLE DATA]",
                date="2023-06-15",
                data_classes=["Email addresses", "Passwords", "Usernames"],
                description="This is sample breach data for demonstration purposes.",
                actions=[
                    {"action": "Change your password on ExampleBreachCo", "priority": "today"},
                    {"action": "Enable 2FA on ExampleBreachCo", "priority": "today"},
                ],
            ))
        if h % 5 == 0:
            breaches.append(BreachInfo(
                name="SampleDataLeak [SAMPLE DATA]",
                date="2022-01-20",
                data_classes=["Email addresses", "IP addresses", "Phone numbers"],
                description="This is sample breach data for demonstration purposes.",
                actions=[
                    {"action": "Review your phone number privacy settings", "priority": "this_week"},
                ],
            ))

        # Build action plan
        actions = self._build_action_plan(findings, breaches)

        return ScanResultPayload(
            findings=findings,
            breaches=breaches,
            modules_total=total,
            modules_done=done,
            modules_failed=failed,
            coverage={"total": total, "done": done, "failed": failed},
            actions=actions,
            masked_email=masked_email,
            hibp_available=True,
            empty_state_text="No accounts detected by these checks. That isn't a guarantee.",
        )

    def _build_action_plan(
        self,
        findings: list[ScanFinding],
        breaches: list[BreachInfo],
    ) -> dict[str, list[dict[str, Any]]]:
        """Build a prioritised action plan."""
        today: list[dict[str, Any]] = []
        this_week: list[dict[str, Any]] = []
        this_month: list[dict[str, Any]] = []

        # Breach actions first (highest priority)
        for breach in breaches:
            has_passwords = "Passwords" in breach.data_classes
            if has_passwords:
                today.append({
                    "action": f"Change passwords exposed in {breach.name}",
                    "guide_id": "password-manager",
                    "guide_title": "Start Using a Password Manager",
                    "priority": "today",
                })
                today.append({
                    "action": f"Enable 2FA on accounts affected by {breach.name}",
                    "guide_id": "enable-2fa",
                    "guide_title": "Enable Two-Factor Authentication (2FA)",
                    "priority": "today",
                })

            if "Phone numbers" in breach.data_classes:
                this_week.append({
                    "action": f"Review phone number privacy after {breach.name}",
                    "guide_id": None,
                    "guide_title": None,
                    "priority": "this_week",
                })

        # Account cleanup
        found_accounts = [f for f in findings if f.status in ("indicator_found", "likely")]
        for finding in found_accounts[:5]:
            this_week.append({
                "action": f"Review and secure your {finding.service_name} account",
                "guide_id": finding.guide_id,
                "guide_title": finding.guide_title,
                "priority": "this_week",
            })

        # General recommendations
        this_month.append({
            "action": "Set up email aliases for better privacy",
            "guide_id": "email-aliases",
            "guide_title": "Set Up Email Aliases for Better Privacy",
            "priority": "this_month",
        })
        this_month.append({
            "action": "Review third-party app access on your Google account",
            "guide_id": "google-third-party-apps",
            "guide_title": "Review Third-Party App Access on Your Google Account",
            "priority": "this_month",
        })

        return {
            "today": today,
            "this_week": this_week,
            "this_month": this_month,
        }
