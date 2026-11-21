"""Scanner worker — processes scan jobs from Redis queue."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import redis
import yaml

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.adapter import HoleheAdapter
from scanner.models import ScanResultPayload


def load_services_config() -> list[dict]:
    """Load enabled services from services.yaml."""
    # Try multiple paths
    for config_path in [
        Path(__file__).resolve().parent.parent.parent.parent / "content" / "services.yaml",
        Path("/app/content/services.yaml"),
    ]:
        if config_path.exists():
            with open(config_path) as f:
                data = yaml.safe_load(f)
            return [s for s in data.get("services", []) if s.get("enabled", False)]
    return []


def decrypt_queue_payload(blob: bytes, key_hex: str) -> bytes:
    """Decrypt a queue payload (AES-256-GCM)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = bytes.fromhex(key_hex)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(blob[:12], blob[12:], None)


def encrypt_queue_payload(plaintext: bytes, key_hex: str) -> bytes:
    """Encrypt a result payload."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import os as _os
    key = bytes.fromhex(key_hex)
    nonce = _os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def mask_email(email: str) -> str:
    """Mask email for safe inclusion in results."""
    if "@" not in email:
        return "***@***.***"
    local, domain = email.rsplit("@", 1)
    masked = (local[:2] + "***") if len(local) > 2 else (local[0] + "***")
    return f"{masked}@{domain}"


async def process_scan(email: str, scan_id: str) -> dict:
    """Run the scan and return results."""
    services = load_services_config()
    scanner_mode = os.environ.get("SCANNER_MODE", "mock")
    concurrency = int(os.environ.get("SCANNER_CONCURRENCY", "8"))
    module_timeout = float(os.environ.get("SCANNER_MODULE_TIMEOUT", "10"))
    global_timeout = float(os.environ.get("SCANNER_GLOBAL_TIMEOUT", "60"))

    adapter = HoleheAdapter(
        allowed_modules=services,
        concurrency=concurrency,
        module_timeout=module_timeout,
        global_timeout=global_timeout,
        scanner_mode=scanner_mode,
    )

    result = await adapter.scan(email)
    result.masked_email = mask_email(email)

    # HIBP integration (if API key available)
    hibp_key = os.environ.get("HIBP_API_KEY", "")
    if hibp_key and scanner_mode == "live":
        try:
            from scanner.hibp import check_breaches
            breaches = await check_breaches(email, hibp_key)
            result.breaches = breaches
            result.hibp_available = True
        except Exception:
            result.hibp_available = False
    elif scanner_mode == "mock":
        # Mock breaches already included
        pass
    else:
        result.hibp_available = False

    # Build action plan based on findings + breaches
    from scanner.recommendation import build_action_plan
    result.actions = build_action_plan(result.findings, result.breaches)

    return result.to_dict()


def worker_loop():
    """Main worker loop — pop jobs from Redis queue and process."""
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    queue_key = os.environ.get("SCANNER_QUEUE_KEY", "")

    if not queue_key:
        print("ERROR: SCANNER_QUEUE_KEY not set")
        sys.exit(1)

    r = redis.from_url(redis_url)
    print(f"Scanner worker started. Mode: {os.environ.get('SCANNER_MODE', 'mock')}")
    print(f"Listening on queue: fpx:scan_jobs")

    while True:
        try:
            # Blocking pop with 5-second timeout
            item = r.brpop("fpx:scan_jobs", timeout=5)
            if item is None:
                continue

            _, encrypted_payload = item

            # Decrypt job
            try:
                decrypted = decrypt_queue_payload(encrypted_payload, queue_key)
                job = json.loads(decrypted)
            except Exception as e:
                print(f"Failed to decrypt job: {e}")
                continue

            scan_id = job.get("scan_id", "")
            email = job.get("email", "")
            print(f"Processing scan: {scan_id[:8]}...")

            # Run the scan
            result = asyncio.run(process_scan(email, scan_id))

            # Encrypt and publish result
            result_json = json.dumps(result).encode()
            encrypted_result = encrypt_queue_payload(result_json, queue_key)

            result_key = f"fpx:scan_result:{scan_id}"
            r.set(result_key, encrypted_result, ex=3600)

            # Publish notification
            r.publish(f"fpx:scan_done:{scan_id}", "done")
            print(f"Scan complete: {scan_id[:8]}")

        except KeyboardInterrupt:
            print("Worker shutting down.")
            break
        except Exception as e:
            print(f"Worker error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    worker_loop()
