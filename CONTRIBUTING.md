# Contributing

Thanks for considering a contribution to `touchque`, the Ruby SDK (gem).

## Setup

Ruby 3.1 or newer, and Node.js for the contract tests.

```bash
bundle install
```

## Running tests

```bash
bundle exec rake test
```

Some suites run **contract tests** against `testing/fake-touchque-api.mjs` — a
small, dependency-free Node server that verifies the SDK's HMAC request
signatures exactly like the real API does. These need `node` on `PATH`.

To check that the gem still builds:

```bash
gem build touchque.gemspec
```

## Making a change

1. If it touches the wire protocol or the step-up contract, update the
   fixtures in `fixtures/` and the fake API in `testing/` first.
2. Add tests. A behavior change without a test won't be merged.
3. Update `CHANGELOG.md` (Keep a Changelog format) under `## [Unreleased]`.
4. Keep code, comments, docs and error messages in English.
5. Don't add a runtime dependency: the gem uses only the standard library
   (`net/http`, `openssl`, `json`). The Rails and Rack integrations load only
   when the app already has Rails or Rack; test-only gems go in the `Gemfile`.

## Pull requests

- Describe what changed and why, not just what. If it's a breaking change,
  say so explicitly and explain the migration.
- CI must pass.

## Reporting a security issue

Please don't open a public issue — see [SECURITY.md](./SECURITY.md).
