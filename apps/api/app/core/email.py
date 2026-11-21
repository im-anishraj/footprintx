"""Email sending: provider-agnostic (SMTP or Resend)."""
from __future__ import annotations

from .config import get_settings
from .logging import get_logger

logger = get_logger("email")


async def send_verification_email(
    to_email: str,
    otp: str,
    magic_link_url: str,
    scan_id: str,
) -> None:
    """Send the verification email with OTP and magic link."""
    settings = get_settings()
    subject = "FootprintX — Verify your email"
    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Inter, system-ui, sans-serif; color: #0F172A; max-width: 480px; margin: 0 auto; padding: 24px;">
  <h2 style="color: #4F46E5; margin-bottom: 8px;">FootprintX</h2>
  <p>Your verification code is:</p>
  <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; font-family: 'JetBrains Mono', monospace; padding: 16px; background: #F8FAFC; border-radius: 8px; text-align: center; margin: 16px 0;">{otp}</div>
  <p>Or click the link below:</p>
  <p><a href="{magic_link_url}" style="color: #4F46E5;">Verify my email</a></p>
  <p style="color: #475569; font-size: 14px;">This code expires in 10 minutes. If you didn't request this, ignore this email.</p>
  <hr style="border: none; border-top: 1px solid #E2E8F0; margin: 24px 0;">
  <p style="color: #94A3B8; font-size: 12px;">FootprintX — Know your footprint. Clean it up.</p>
</body>
</html>"""
    text_body = f"""FootprintX — Verify your email

Your verification code is: {otp}

Or use this link: {magic_link_url}

This code expires in 10 minutes. If you didn't request this, ignore this email.
"""

    if settings.email_provider == "smtp":
        await _send_smtp(to_email, subject, html_body, text_body)
    else:
        await _send_resend(to_email, subject, html_body, text_body)

    # Log only that an email was sent, never the address or OTP
    logger.info("verification_email_sent", scan_id=scan_id)


async def _send_smtp(
    to: str, subject: str, html: str, text: str
) -> None:
    """Send via SMTP (Mailpit in dev)."""
    import aiosmtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    settings = get_settings()

    msg = MIMEMultipart("alternative")
    msg["From"] = settings.email_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    await aiosmtplib.send(
        msg,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username or None,
        password=settings.smtp_password or None,
        use_tls=settings.smtp_use_tls,
    )


async def _send_resend(
    to: str, subject: str, html: str, text: str
) -> None:
    """Send via Resend API."""
    import httpx

    settings = get_settings()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {settings.resend_api_key}"},
            json={
                "from": settings.email_from,
                "to": [to],
                "subject": subject,
                "html": html,
                "text": text,
            },
        )
        resp.raise_for_status()
