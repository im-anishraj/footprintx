# Third-Party Notices

This file lists all third-party dependencies, tools, and data sources used by
FootprintX, along with their licences.

## Core Dependencies

### Holehe
- **Source**: https://github.com/megadose/holehe
- **Licence**: GPL-3.0
- **Usage**: Email-to-account checking engine in services/scanner
- **Copyright**: Copyright (c) 2020 Palenath (megadose)
- **Note**: Isolated behind a process/queue boundary. services/scanner is
  licensed GPL-3.0 accordingly.

### Have I Been Pwned (HIBP) API v3
- **Source**: https://haveibeenpwned.com/API/v3
- **Licence**: API usage requires a paid API key and compliance with terms
- **Usage**: Breach data lookup for verified email addresses
- **Attribution**: "Breach data provided by Have I Been Pwned" displayed on
  results and methodology pages
- **Note**: Operator must review HIBP terms before launch. See docs/SETUP.md.

### disposable-email-domains
- **Source**: https://github.com/disposable-email-domains/disposable-email-domains
- **Licence**: MIT
- **Usage**: Flagging disposable email domains for stricter rate limiting
- **Copyright**: Copyright (c) disposable-email-domains contributors

## Frontend Dependencies

### Next.js
- **Source**: https://github.com/vercel/next.js
- **Licence**: MIT
- **Copyright**: Copyright (c) 2024 Vercel, Inc.

### Tailwind CSS
- **Source**: https://github.com/tailwindlabs/tailwindcss
- **Licence**: MIT
- **Copyright**: Copyright (c) Tailwind Labs, Inc.

### Radix UI Primitives
- **Source**: https://github.com/radix-ui/primitives
- **Licence**: MIT
- **Copyright**: Copyright (c) 2022 WorkOS

### Lucide Icons
- **Source**: https://github.com/lucide-icons/lucide
- **Licence**: ISC
- **Copyright**: Copyright (c) 2020 Lucide Contributors

### Inter Font
- **Source**: https://github.com/rsms/inter
- **Licence**: SIL Open Font License 1.1
- **Copyright**: Copyright (c) 2016-2020 The Inter Project Authors

### JetBrains Mono Font
- **Source**: https://github.com/JetBrains/JetBrainsMono
- **Licence**: SIL Open Font License 1.1
- **Copyright**: Copyright (c) 2020 The JetBrains Mono Project Authors

## Backend Dependencies

### FastAPI
- **Source**: https://github.com/tiangolo/fastapi
- **Licence**: MIT
- **Copyright**: Copyright (c) 2018 Sebastián Ramírez

### SQLAlchemy
- **Source**: https://github.com/sqlalchemy/sqlalchemy
- **Licence**: MIT
- **Copyright**: Copyright (c) 2005-2024 SQLAlchemy authors and contributors

### Alembic
- **Source**: https://github.com/sqlalchemy/alembic
- **Licence**: MIT
- **Copyright**: Copyright (c) 2009-2024 SQLAlchemy authors and contributors

### Pydantic
- **Source**: https://github.com/pydantic/pydantic
- **Licence**: MIT
- **Copyright**: Copyright (c) 2017-2024 Pydantic Services Inc.

### WeasyPrint
- **Source**: https://github.com/Kozea/WeasyPrint
- **Licence**: BSD 3-Clause
- **Copyright**: Copyright (c) 2011-2024 Simon Sapin and contributors

### RQ (Redis Queue)
- **Source**: https://github.com/rq/rq
- **Licence**: BSD 2-Clause
- **Copyright**: Copyright (c) 2012 Vincent Driessen and contributors

### httpx
- **Source**: https://github.com/encode/httpx
- **Licence**: BSD 3-Clause
- **Copyright**: Copyright (c) 2019-2024 Encode OSS Ltd.

## Development Dependencies

### Mailpit
- **Source**: https://github.com/axllent/mailpit
- **Licence**: MIT
- **Copyright**: Copyright (c) 2022-2024 Ralph Slooten

### Cloudflare Turnstile
- **Source**: https://developers.cloudflare.com/turnstile/
- **Licence**: Proprietary (free tier available)
- **Usage**: CAPTCHA verification; test keys used in development

## Data Sources

### Cloudflare Turnstile Test Keys
- Site key: `1x00000000000000000000AA` (always passes)
- Secret: `1x0000000000000000000000000000000AA` (always passes)
- Source: https://developers.cloudflare.com/turnstile/troubleshooting/testing/
