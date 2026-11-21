# Decisions Log

This document records architectural and implementation decisions made during
development. When something was ambiguous in the spec, the safest reasonable
option was chosen.

## D001: Session Storage

**Decision**: Use Redis-backed server-side sessions with a signed cookie
containing only the session ID.

**Rationale**: Avoids storing any scan data in the cookie. The session maps to
exactly one scan ID, enforced server-side.

## D002: OTP Generation

**Decision**: Use Python `secrets` module for cryptographically secure 6-digit
OTP generation. Store HMAC-SHA256 hash of the OTP, not the plaintext.

**Rationale**: `secrets` provides CSPRNG. Hashing at rest means a DB compromise
doesn't reveal valid OTPs.

## D003: Magic Link Token

**Decision**: 256-bit token generated with `secrets.token_urlsafe(32)`. Stored
as SHA-256 hash. Single use, same 10-minute expiry as OTP.

**Rationale**: URL-safe encoding for email links. Hashing prevents DB-leak
abuse.

## D004: Scanner Communication

**Decision**: Scanner worker communicates via Redis queues only. It receives an
encrypted payload containing just the email and scan ID. It returns normalised
results on a result queue. The API polls/subscribes to the result queue.

**Rationale**: Clean process boundary keeps GPL-3.0 code isolated. No database
credentials in the scanner container.

## D005: Licence Structure

**Decision**: Application code (apps/web, apps/api) is MIT. services/scanner is
GPL-3.0 (due to Holehe dependency). Scanner is behind a process/queue boundary
so GPL-3.0 does not infect the MIT-licensed application code.

**Rationale**: GPL-3.0 requires derivative works to be GPL-3.0, but
communicating via a network/queue interface is not "linking" under GPL
interpretation.

## D006: Database ID Generation

**Decision**: Use UUIDv4 for scan IDs (Python `uuid.uuid4()`).

**Rationale**: Non-sequential, non-guessable. UUIDv4 is well-supported in
PostgreSQL and Python.

## D007: Email Normalisation

**Decision**: Lowercase the entire email, apply IDNA encoding to the domain
part, strip leading/trailing whitespace.

**Rationale**: Simple, consistent normalisation. We do NOT strip dots from Gmail
(e.g., `j.doe@gmail.com` and `jdoe@gmail.com`) because the scanner needs the
exact address the user entered and verified.

## D008: Timing-Safe Responses

**Decision**: POST /v1/scans always returns 202 with identical body structure
regardless of whether the email is valid, rate-limited, or already has a pending
scan. Email sending happens in a background task.

**Rationale**: Prevents email enumeration attacks. The response body and timing
are indistinguishable.

## D009: HIBP Integration Location

**Decision**: HIBP calls are made from the API server (not the scanner worker)
after verification, as part of scan processing.

**Rationale**: HIBP requires an API key which should not be in the scanner
container. The scanner handles only Holehe modules.

**Update**: Moved HIBP to the worker for simplicity - API key is passed as an
env var to the worker container. The worker makes HIBP calls and includes breach
data in its result payload.

## D010: PDF Generation

**Decision**: WeasyPrint generates PDFs server-side from an HTML template with
print CSS.

**Rationale**: Specified in requirements. Keeps PDF generation on the server
where we control the output.

## D011: Font Hosting

**Decision**: Self-host Inter and JetBrains Mono fonts. Download and serve from
the Next.js public directory using `next/font/local`.

**Rationale**: No third-party requests for fonts. Required by the no-trackers
rule.

## D012: CAPTCHA in Development

**Decision**: Use Cloudflare Turnstile test keys in development (site key
`1x00000000000000000000AA`, secret `1x0000000000000000000000000000000AA`). These
always pass without user interaction.

**Rationale**: Official Turnstile test keys. Allows local development without
real CAPTCHA challenges.

## D013: Consent Versioning

**Decision**: Consent version is a semver string stored in the codebase. The
API validates that the submitted consent version matches the current version.
Old versions are rejected.

**Rationale**: Provides an audit trail of which consent text the user agreed to.

## D014: Dark Mode Implementation

**Decision**: Use Tailwind CSS `dark:` variant with `class` strategy. Theme
toggle stored in localStorage with system preference as default.

**Rationale**: Client-side theme avoids flash. No server state needed.

## D015: Error Response Format

**Decision**: All API errors use `application/problem+json` (RFC 9457) format
with fields: type, title, status, detail, instance.

**Rationale**: Standard format specified in requirements.

## D016: Log Redaction

**Decision**: Custom logging processor that regex-scans all log fields for
email-like patterns, OTP patterns, token patterns, and IP addresses, replacing
them with `[REDACTED]`. Applied at the structlog processor level before any
output.

**Rationale**: Defence-in-depth. Even if code accidentally logs sensitive data,
the processor catches it.

## D017: Disposable Email Domains

**Decision**: Vendor the `disposable-email-domains` list (MIT-licensed) as a
static file. Flag but don't block disposable domains; apply stricter rate limits.

**Rationale**: Blocking would be opinionated. Stricter rate limits prevent abuse
while allowing legitimate use.

## D018: Worker Framework

**Decision**: Use RQ (Redis Queue) for the scan worker. Simple, well-tested,
fits the single-job-per-scan model.

**Rationale**: arq would also work but RQ is more mature for this use case.

## D019: HIBP Call Location (Revised)

**Decision**: HIBP calls are made from the scanner worker alongside Holehe
modules. The API key is passed as an environment variable to the worker.

**Rationale**: Simplifies the data flow. All external lookups happen in one
place. The worker returns a combined result with both account findings and
breach data.

## D020: Canary Test Account Management

**Decision**: Canary accounts are configured via a JSON file path set in the
CANARY_CONFIG environment variable. The operator must create and manage test
accounts themselves.

**Rationale**: We cannot create accounts on third-party services. The operator
controls which test accounts to use.
