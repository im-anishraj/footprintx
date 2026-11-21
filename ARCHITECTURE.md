# FootprintX Architecture

## Overview

FootprintX is a privacy-first digital footprint auditing tool. Users verify
email ownership, then receive a report of accounts associated with that email,
known data-breach exposure, and a prioritised cleanup plan.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           User Browser                             │
│  Next.js App (apps/web) — Vercel / static host                    │
└──────────────┬──────────────────────────────────────────────────────┘
               │ HTTPS (API calls, session cookie)
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        FastAPI (apps/api)                           │
│  REST endpoints (/v1/*), session management, rate limiting         │
│  OTP/magic-link verification, HIBP integration                     │
│  Encryption envelope, abuse counters                               │
├──────────────┬───────────────────┬──────────────────────────────────┤
│              │                   │                                  │
│   PostgreSQL │        Redis      │        Email (Resend/SMTP)      │
│   (scans,    │  (rate limits,    │        Mailpit in dev            │
│    results,  │   session store,  │                                  │
│    audit)    │   queue, canary)  │                                  │
└──────────────┴─────────┬─────────┴──────────────────────────────────┘
                         │ Redis Queue (encrypted payload)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Scanner Worker (services/scanner)                 │
│  GPL-3.0 isolated process — no DB credentials                      │
│  Holehe adapter with allow-list, field stripping                   │
│  Bounded concurrency, per-module timeouts                          │
│  Returns normalised results via Redis result queue                 │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Design Decisions

### Security Boundaries

1. **Scanner Isolation**: The scanner worker runs in a separate container with
   no database credentials. It receives only the email (encrypted) via Redis
   queue and returns normalised results. This keeps GPL-3.0 Holehe code behind
   a clean process boundary.

2. **Email Never Persisted**: Raw email addresses are never stored in the
   database. Only `HMAC-SHA256(normalised_email, SERVER_PEPPER)` is stored for
   abuse counters (30-day TTL).

3. **Envelope Encryption**: Scan results use AES-256-GCM with per-scan data
   keys wrapped by a master key. Key IDs support rotation.

4. **Session Binding**: Each scan gets its own session. The session cookie is
   HttpOnly, Secure, SameSite=Lax, and bound to exactly one scan ID. Cross-scan
   access returns 404 (not 403).

### Data Flow

1. User submits email + consent + CAPTCHA token
2. API validates, rate-checks, creates scan in `pending_verification`
3. OTP (6-digit) + magic link sent via email provider
4. User verifies → scan state moves to `queued`
5. Worker picks up job, runs allow-listed Holehe modules
6. Worker strips sensitive fields, normalises results
7. API encrypts and stores results
8. User views results, downloads report
9. Purge job deletes expired data every 10 minutes
10. User can delete immediately at any time

### State Machine

```
pending_verification → queued → running → completed
                                       → partial (some modules failed)
                                       → failed
completed/partial/failed → expired (after 24h)
                         → deleted (user action)
```

### Technology Choices

| Layer    | Technology              | Rationale                           |
|----------|------------------------|--------------------------------------|
| Web      | Next.js + TypeScript   | SSR, App Router, strong typing       |
| API      | FastAPI + Pydantic v2  | Async, validation, OpenAPI           |
| DB       | PostgreSQL             | ACID, encryption, JSON support       |
| Queue    | Redis + RQ             | Simple, reliable, TTL support        |
| Scanner  | Holehe (GPL-3.0)       | Established email-account checker    |
| Email    | Resend / SMTP          | Provider-agnostic                    |
| CAPTCHA  | Cloudflare Turnstile   | Privacy-friendly                     |
| Breach   | HIBP API v3            | Industry standard, attribution       |
| PDF      | WeasyPrint             | Server-side, CSS-based               |

### Module Categories

- Social Media
- Developer Platforms
- Creative & Design
- Music & Audio
- Fitness & Sports
- News & Media
- E-commerce & Marketplaces
- Gaming
- Productivity
- Education
- Professional
- Other

### Rate Limiting Strategy

- Per email-HMAC: 3 scans/day, 1 OTP/10min
- Per IP-hash: 10 requests/hour, 30 verify attempts/hour
- Global: circuit breaker on provider 429s
- Disposable domains: flagged, stricter limits

### File Structure

```
footprintx/
├── apps/
│   ├── web/                    # Next.js App Router
│   │   ├── src/
│   │   │   ├── app/            # Routes
│   │   │   ├── components/     # UI components
│   │   │   ├── lib/            # Utilities
│   │   │   └── styles/         # Global styles
│   │   └── ...config files
│   └── api/                    # FastAPI
│       ├── app/
│       │   ├── core/           # Config, security, encryption
│       │   ├── models/         # SQLAlchemy models
│       │   ├── routers/        # API endpoints
│       │   ├── services/       # Business logic
│       │   └── middleware/     # Logging, CORS, headers
│       ├── migrations/         # Alembic
│       └── tests/
├── services/
│   └── scanner/                # GPL-3.0 scanner worker
│       ├── scanner/            # Package
│       └── tests/
├── content/
│   ├── guides/                 # YAML fix guides
│   └── services.yaml           # Service catalog
├── docs/                       # Documentation
├── docker-compose.yml
└── ...root config files
```
