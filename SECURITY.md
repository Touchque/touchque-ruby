# Security Policy

Touchque is a 2FA/authentication product. We take reports about this SDK
seriously and will respond quickly.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security report.**

Email **security@touchque.com** with:

- A description of the issue and its impact.
- Steps to reproduce (a minimal example is ideal).
- The version affected.

We aim to acknowledge reports within 2 business days and to ship a fix or
mitigation within 90 days of a confirmed report, whichever the severity
warrants sooner. We'll credit you in the release notes unless you ask us not to.

## Scope

In scope: this SDK (the `touchque` Ruby gem) and its published releases. Signature
verification, secret handling, the guard token, and the framework adapters
(Rails, Rack) are all fair game.

Out of scope: the Touchque backend/API itself, the dashboard, and the mobile
app — report those to the same address, but they're a separate codebase with
their own release cycle.

## Supported versions

We support the latest major version. Fixes for older majors are made at our
discretion, prioritizing severity.

## Design notes for reviewers

- The API secret never leaves your server. Browser packages (`@touchque/web`,
  `@touchque/react`) only ever talk to *your* backend, which relays signed
  requests to Touchque.
- Every partner request is signed HMAC-SHA256 over
  `METHOD:path[?query]:timestamp:nonce:sha256(body)`; the nonce is single-use
  server-side for 10 minutes, and the timestamp window is ±5/-1 minutes.
- The step-up "guard token" (`X-TouchQue-Token`) that a partner's browser
  page echoes back is itself signed (HMAC, derived from the API secret) and
  binds one user + action + transaction-details digest; it can't be replayed
  for a different amount, recipient or user, and an approval is consumed
  exactly once server-side.
