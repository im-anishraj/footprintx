"""FootprintX Scanner Service — Holehe adapter with allow-list."""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional

from .mock_scanner import MockScanner
from .models import ScanFinding, ScanResultPayload


class HoleheAdapter:
    """
    Adapter for Holehe email-account checking.
    
    Security invariants:
    - Only allow-listed modules run
    - emailrecovery, phoneNumber, others fields are ALWAYS stripped
    - Bounded concurrency and timeouts
    """

    # Fields that must NEVER be passed through
    FORBIDDEN_FIELDS = {"emailrecovery", "phoneNumber", "others", "password", "recovery"}

    def __init__(
        self,
        allowed_modules: list[dict[str, Any]],
        concurrency: int = 8,
        module_timeout: float = 10.0,
        global_timeout: float = 60.0,
        scanner_mode: str = "mock",
    ):
        self.allowed_modules = {m["module"]: m for m in allowed_modules}
        self.concurrency = concurrency
        self.module_timeout = module_timeout
        self.global_timeout = global_timeout
        self.scanner_mode = scanner_mode

    def _strip_sensitive_fields(self, result: dict[str, Any]) -> dict[str, Any]:
        """Remove ALL sensitive fields from a Holehe result."""
        for field in self.FORBIDDEN_FIELDS:
            result.pop(field, None)
        return result

    def _map_status(self, holehe_result: dict[str, Any]) -> str:
        """Map Holehe result to our status enum."""
        if holehe_result.get("rateLimit", False):
            return "rate_limited"
        exists = holehe_result.get("exists", None)
        if exists is True:
            return "indicator_found"
        elif exists is False:
            return "not_detected"
        else:
            return "unknown"

    def _determine_confidence(self, status: str, module_health: str = "healthy") -> str:
        """Determine confidence level."""
        if module_health != "healthy":
            return "low"
        if status == "indicator_found":
            return "medium"
        if status == "not_detected":
            return "medium"
        return "low"

    def _make_explanation(self, service_name: str, status: str) -> str:
        """Generate a user-facing explanation."""
        explanations = {
            "indicator_found": f"An account may be associated with this email on {service_name}.",
            "likely": f"An account is likely associated with this email on {service_name}.",
            "not_detected": f"No account indicator was detected on {service_name}.",
            "unknown": f"The check for {service_name} returned an inconclusive result.",
            "rate_limited": f"The check for {service_name} was rate-limited. Try again later.",
            "unable_to_verify": f"Unable to complete the check for {service_name}.",
            "skipped": f"The check for {service_name} was skipped.",
        }
        return explanations.get(status, f"Check status for {service_name}: {status}")

    async def scan(self, email: str) -> ScanResultPayload:
        """
        Run all allowed modules against an email.
        Returns a normalised result payload.
        """
        if self.scanner_mode == "mock":
            return await MockScanner(self.allowed_modules).scan(email)

        return await self._live_scan(email)

    async def _live_scan(self, email: str) -> ScanResultPayload:
        """Run actual Holehe modules."""
        import httpx

        findings: list[ScanFinding] = []
        modules_done = 0
        modules_failed = 0
        total = len(self.allowed_modules)

        semaphore = asyncio.Semaphore(self.concurrency)

        async def run_module(module_name: str, module_info: dict[str, Any]):
            nonlocal modules_done, modules_failed
            async with semaphore:
                try:
                    result = await asyncio.wait_for(
                        self._run_holehe_module(email, module_name),
                        timeout=self.module_timeout,
                    )
                    # CRITICAL: Strip sensitive fields
                    result = self._strip_sensitive_fields(result)

                    status = self._map_status(result)
                    confidence = self._determine_confidence(status)
                    
                    findings.append(ScanFinding(
                        service_id=module_info["id"],
                        service_name=module_info["name"],
                        category=module_info.get("category", "other"),
                        sensitivity=module_info.get("sensitivity", "low"),
                        status=status,
                        status_label=status.replace("_", " ").title(),
                        confidence=confidence,
                        evidence_type="module_check",
                        engine={"name": "holehe", "version": "1.0", "module_health": "healthy"},
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        explanation=self._make_explanation(module_info["name"], status),
                        actions=[],
                    ))
                    modules_done += 1

                except asyncio.TimeoutError:
                    findings.append(ScanFinding(
                        service_id=module_info["id"],
                        service_name=module_info["name"],
                        category=module_info.get("category", "other"),
                        sensitivity=module_info.get("sensitivity", "low"),
                        status="unable_to_verify",
                        status_label="Unable to Verify",
                        confidence="low",
                        evidence_type="timeout",
                        engine={"name": "holehe", "version": "1.0", "module_health": "degraded"},
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        explanation=f"The check for {module_info['name']} timed out.",
                        actions=[],
                    ))
                    modules_failed += 1
                    modules_done += 1

                except Exception:
                    findings.append(ScanFinding(
                        service_id=module_info["id"],
                        service_name=module_info["name"],
                        category=module_info.get("category", "other"),
                        sensitivity=module_info.get("sensitivity", "low"),
                        status="unable_to_verify",
                        status_label="Unable to Verify",
                        confidence="low",
                        evidence_type="error",
                        engine={"name": "holehe", "version": "1.0", "module_health": "degraded"},
                        checked_at=datetime.now(timezone.utc).isoformat(),
                        explanation=f"An error occurred checking {module_info['name']}.",
                        actions=[],
                    ))
                    modules_failed += 1
                    modules_done += 1

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    *(run_module(name, info) for name, info in self.allowed_modules.items()),
                    return_exceptions=True,
                ),
                timeout=self.global_timeout,
            )
        except asyncio.TimeoutError:
            pass

        return ScanResultPayload(
            findings=findings,
            breaches=[],
            modules_total=total,
            modules_done=modules_done,
            modules_failed=modules_failed,
            coverage={"total": total, "done": modules_done, "failed": modules_failed},
        )

    async def _run_holehe_module(self, email: str, module_name: str) -> dict[str, Any]:
        """Run a single Holehe module."""
        import httpx

        # Import holehe dynamically
        try:
            import holehe.modules as holehe_modules
            module = getattr(holehe_modules, module_name, None)
            if module is None:
                # Try importing as holehe.modules.<name>
                import importlib
                mod = importlib.import_module(f"holehe.modules.{module_name}")
                module_func = getattr(mod, module_name, None)
                if module_func is None:
                    return {"name": module_name, "exists": None}
        except (ImportError, AttributeError):
            return {"name": module_name, "exists": None}

        # Run with httpx client
        out: list[dict] = []
        async with httpx.AsyncClient(timeout=self.module_timeout) as client:
            try:
                await module_func(email, client, out)
            except Exception:
                return {"name": module_name, "exists": None, "rateLimit": False}

        if out:
            return out[0]
        return {"name": module_name, "exists": None}
