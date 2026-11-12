# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [5.0.0] — 2026-11-12

### Breaking
- **Every name is spelled Touchque instead of TouchQue.** Code that uses the old names must be updated; nothing else changes. Old → new:
  - The module: `TouchQue` → `Touchque` (`TouchQue.client`, `.configure`, `.logger`, `.replay_cache`, `.login_options`, `.login_secret` and `.hosted_login` → `Touchque.client`, `Touchque.configure`...).
  - The client class: `TouchQue::Client` → `Touchque::Client`.
  - The error classes: `TouchQue::Error`, `TouchQue::APIError`, `TouchQue::NetworkError`, `TouchQue::RejectedError`, `TouchQue::TimeoutError`, `TouchQue::PasskeyRequiredError`, `TouchQue::ConfigError`, `TouchQue::WebhookSignatureError`, `TouchQue::WebhookReplayError`, `TouchQue::ApprovalError`, `TouchQue::ApprovalMismatchError`, `TouchQue::FeatureError` (and `FeatureNotInPlanError`, `FeatureReadOnlyError`, `FeatureOffError`), `TouchQue::HostedLoginError`, `TouchQue::MyAccountError`, `TouchQue::McpAuthError`, `TouchQue::IdJagError`, `TouchQue::AgentCardError` and `TouchQue::SecurityEventError` → `Touchque::Error`, `Touchque::APIError`, `Touchque::NetworkError` and so on.
  - Every other class and module under it: `TouchQue::Resources::*`, `TouchQue::Guard`, `TouchQue::Agent`, `TouchQue::OrgAgent`, `TouchQue::McpAuth`, `TouchQue::HostedLogin`, `TouchQue::SafeApproval`, `TouchQue::CodeReply`... → `Touchque::Resources::*`, `Touchque::Guard`, `Touchque::Agent`...
  - Rails: `TouchQue::Rails::Guard`, `TouchQue::Rails::Webhook`, `TouchQue::Rails::HostedLogin`, `TouchQue::Rails.login_routes` and `TouchQue::SessionsController` → `Touchque::Rails::Guard`, `Touchque::Rails::Webhook`, `Touchque::Rails::HostedLogin`, `Touchque::Rails.login_routes` and `Touchque::SessionsController`. `login_routes`' default controller is now `"touchque/sessions"` (was `"touch_que/sessions"`, the route name Rails derived from the old class name); change it if you passed it yourself.
  - Rack: `TouchQue::Rack::Relay` → `Touchque::Rack::Relay`.
  - The guard's header names (`Touchque::Guard::TOKEN_HEADER`, `OFFLINE_HEADER`, `CODE_HEADER`, `CODE_TYPE_HEADER`, `BROWSER_HEADER`): `X-TouchQue-Token`, `X-TouchQue-Offline`, `X-TouchQue-Code`, `X-TouchQue-Code-Type`, `X-TouchQue-Browser` → `X-Touchque-Token`, `X-Touchque-Offline`, `X-Touchque-Code`, `X-Touchque-Code-Type`, `X-Touchque-Browser`. HTTP header names are case-insensitive, so servers are unaffected.
  - The SDK's log lines start with `[Touchque]` (was `[TouchQue]`) and its error messages with `Touchque:`.
  - The same as before: the gem name `touchque`, `require "touchque"`, `config.touchque` and `credentials.touchque`, the `/touchque` mount path, the cookies, the JSON the API sends and receives, the `TQ_*` environment variables, and the signed EIP-712 type string `TouchQueGovernance(...)` that the Safe Guard contract hashes.

### Changed
- The README has an "Action types" section: define a type once (dashboard → Developers → Action types, or from code); the guard answers 500 `misconfigured` for an undefined name and 403 `action_disabled` for one turned off.

## [4.2.0] — not published (these changes ship in 5.0.0)

### Security
- **The offline approval-token check refuses another workspace's token.** `GET /agents/jwks.json` is one key set for every Touchque workspace, and the check used to compare `aud` only when you passed an audience, so a token Touchque signed for someone else's workspace (their own phone, any person's name, any details) could pass your executor. Now:
  - `agents.verify_approval_token(token, audience: nil, ...)` uses this workspace's own audience by default: `agents.approval_audience` asks `GET /agents/approval-audience` once (`touchque:workspace:<id>`) and keeps it.
  - `ApprovalToken.verify_with(token, jwks, audience:, ...)` requires the audience. A missing or empty one throws Touchque::ApprovalMismatchError (`audience is required`).
  - A token without `aud` is refused (`the approval token names no workspace`), as is one for another workspace (`the approval token is for another workspace`).
  - Breaking for callers of the low-level function who passed no audience: pass agents.approval_audience's value.
  - `redeemApproval` was already safe: Touchque compares `aud` with your workspace there.

### Added
- **`device_risk.search_events(...)`: search your workspace's Device risk identifications**, newest first, one page at a time (`GET /device-risk/events`): `from:`/`to:` (7 days by default, at most 90, within your retention), `signal:`, `step_up:`, `kind:`, `origin:`, `ip:` (an address or a CIDR range; never returned), `account:`, `visitor_id:`, `request_id:`, `limit:` (1 to 100) and the opaque `cursor:` from the previous page's `"nextCursor"`.
- `device_risk.check` returns `"engine"` (String or nil): the engine's state for this check; `"unavailable"` when the risk engine could not be reached and the verdict is a safe default (`"stepUp"` true), so an outage can be told apart from risk.
- **`webauthn.primary_availability`: is passkey sign-in on for your workspace?** `GET /webauthn/authenticate/primary/availability` answers `{ "enabled" => bool, "userVerification" => "required" | "preferred" | nil }`. Ask before your sign-in page shows its passkey button and passkey autofill; when it is off, `primary_options` answers 403 `passwordless_login_disabled`.
- `agents.get_workspace_policy`, the name every other Touchque SDK uses, as an alias of `agents.workspace_policy` (which stays; `set_workspace_policy` was already there).
- **Webhook events of Never Locked Out and the help desk**, the names the API sends: `Webhook::EVENT_RECOVERY_STARTED`, `EVENT_RECOVERY_DEVICE_BOUND`, `EVENT_RECOVERY_COOLING`, `EVENT_RECOVERY_COMPLETED`, `EVENT_RECOVERY_VETOED`, `EVENT_RECOVERY_EXPIRED`, `EVENT_RECOVERY_FAILED` and `EVENT_ASSIST_OPENED`, `EVENT_ASSIST_ENDED`, `EVENT_ASSIST_CHECK_PASSED`, `EVENT_ASSIST_CHECK_FAILED`, `EVENT_ASSIST_UNFROZEN`, `EVENT_ASSIST_CLAIM_CONFIRMED`, `EVENT_ASSIST_CLAIM_UNVERIFIED`.
- `SecurityEvents.poll` sends `Accept: application/json`, like the Node SDK (it sent Net::HTTP's `*/*`).
- README: "Shared Signals (security events from Touchque SSO)", verifying a pushed SET and polling; tests for the keys found through `/.well-known/ssf-configuration` and for a poll, against a local transmitter.
- **Shared Signals: receive the security events an identity provider sends after sign-in.** Touchque SSO sends Security Event Tokens (OpenID Shared Signals Framework 1.0) for an organization's members to the receivers its admin adds (Organization > Continuous access): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, RISC `account-disabled`, `credential-compromise`; `txn` carries the case code of Touchque's decision. `Touchque::SecurityEventVerifier.new(issuer:, audience:, jwks_uri:, jwks:, clock_skew:).verify(token)` returns `{ "jti", "issuer", "audience", "issued_at", "txn", "subject", "type", "name", "claims" }` or raises `Touchque::SecurityEventError` with the RFC 8935 code to answer in `error` (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`); `Touchque::SecurityEvents.poll(url:, token:, ack:, set_errs:, max_events:)` for poll delivery (RFC 8936); `SecurityEvents::TYPES`. The keys come from the issuer's `/.well-known/ssf-configuration`; a SET does not expire, so keep the jtis you handled. Tested against the shared vectors (`fixtures/security-event-vectors.json`).
- **Safe Guard: Safe transactions approved on the approver's phone, for TouchqueSafeGuard.** `tq.safe_guard.request(external_username, type, safe_tx, reference_id:, expires_in:)` sends the raw transaction (the phone decodes it itself and signs with a key only its biometrics unlock), `status(request_id)` and `wait_for_approval(request_id)` hand back the 105-byte approval. `Touchque::SafeApproval.verify(target, approval, approver_key, purpose:, approver_index:, rows: | display_digest:, now:)` checks it the way the guard does, without trusting Touchque: the Safe transaction hash (EIP-712, Keccak-256 here) and the governance hash computed here, the 149-byte message, low `s`, the one-day expiry window, the P-256 signature. `SafeApproval.with_approvals(owner_signatures, approvals)` for `execTransaction`, `SafeApproval.schedule_call(safe, governance_hash, approvals)` for a governance change; `safe_tx_hash`, `governance_hash`, `message`, `display_digest`. Tested against the shared vectors (`fixtures/safe-guard-vectors.json`).

### Fixed
- An empty `reference_id` is no reference, as for the API: `login.request` no longer sends `"referenceId": ""`, and `complete` (and so the guard) no longer raises `ApprovalMismatchError` after using up an approval started with `reference_id: ""`.
- The step-up guard (`Guard.run`, `require_touchque`, the relay's `/login`) answers the contract's 503 `unavailable` for any failure, an approval for another transaction included, instead of a bare 500. Every connection failure and garbled answer (`ENETUNREACH`, `EPIPE`, a bad status line...) now raises `Touchque::NetworkError`.
- Transaction details are trimmed like the API trims them (JavaScript's trim: no-break and other Unicode spaces too), so `complete` and `ApprovalProof.verify` no longer refuse details that start or end with such a space.
- `login.verify` passes `expires_in:` and `client_signals:` on to the request instead of dropping them.
- `Touchque::Rack::Relay` loads on first use: the documented Sinatra / plain Rack mount works without Rails and without `require "touchque/rack/relay"`.
- The relay answers 400 `invalid_credential_id` to `DELETE /passkey/credentials/{id}` with a malformed %-encoding instead of a 500.

### Security
- **Hosted login: an empty `iss` is refused too (RFC 9207).** `handle_callback` (and so the Rails `/callback`) already refused a callback whose `iss` names another issuer; one with an empty `iss=` now raises `issuer_mismatch` as well, before the code is exchanged. A callback without `iss` (a server that does not send it yet, or a nil value) is still accepted.
- `inspect` (and `pp`) of `Touchque::Client`, its `webhook`, `HostedLogin` and `MyAccount` no longer show the API key, the API secret, the client secret or the access token.
- `SafeApproval.verify` without `purpose:` accepts only an ordinary approval (`"approve"`). A schedule approval covers no Safe nonce or gas fields, so it is accepted only with `purpose: "schedule"`, never as permission to execute.
- Touchque Login (`HostedLogin`, `MyAccount`) refuses a plaintext `http://` domain except on this machine (`localhost`, `127.0.0.1`, `::1`, `*.localhost`), like `base_url`: codes, PKCE verifiers, the client secret and tokens never travel in the clear.

## [4.1.0] — not published (these changes ship in 5.0.0)

### Added
- **Device risk events like a device-intelligence event, without raw traits:** `deviceRisk.check` and `getEvent` answers carry `network`, `velocity` and `bot`: the address as the risk engine saw it (country, region, city, never coordinates; the operator; `type` isp, hosting or tor; `timezoneMismatch` when the browser's clock does not fit the address), the visitor's counts (accounts, sign-ups, countries, stored-id resets, identifications in the last hour and day) and one answer to "a bot?" (`detected`, `suspected` or `not_detected`, with reasons). The field the script tag fills may now carry its pointer summary after the requestId: pass it as it came.

### Changed
- **Silent by default.** Nothing goes to `$stderr` (`Kernel#warn`) on its own any more: the SDK's own problems (a misconfigured guard, a failed `on_challenge`, a relay error or a relay without `get_login_user`) go to `Touchque.logger` (`Touchque.logger = Rails.logger`); nil, the default, logs nothing.
- `ApprovalMismatchError` no longer names the other person in its message.

### Added
- **A code typed back on the phone:** `tq.login.request(..., reply: { kind: "code", key:, channel:, target: })`; `Touchque::CodeReply.new_key` and `Touchque::CodeReply.open(private_key, request_id, ct)` open `status(id)["reply"]["ct"]`.
- **Feature errors:** a feature your organization cannot use here (403 `feature_not_in_plan`, `feature_read_only`, `feature_off`) raises `FeatureNotInPlanError`, `FeatureReadOnlyError` or `FeatureOffError`, all `FeatureError` (`feature`, `feature_reason`) and still `APIError`.

First release of the Ruby SDK, at the same surface as the Node, Python, PHP, Go and .NET SDKs 4.1.0.

### Added
- **Webhook events `DEVICE_RISK_SIGNAL` and `DEVICE_RISK_ALERT`** (`Webhook::EVENT_DEVICE_RISK_*`): a Device risk signal that asks for more (identifiers, signals and the engine's verdict, never a trait), and an alert rule of the workspace that went off. Signed like every event.
- **Device risk in one line: `tq.device_risk.check(params[:touchque_request_id], event: "sign_in", external_username: email)`** with the script tag (`device.js`, `@touchque/web` 1.6.0), which fills that field. Pass it as it came: nil, empty, made up or expired is still a verdict (`report` missing, unknown, expired, invalid; the signal `device_identification_missing`, a number-matched step-up at most), never an exception. `Touchque::Resources::DeviceRisk::REPORTS`.
- **Device risk: `tq.device_risk.check(request_id, event:, external_username:, client_ip:)` and `tq.device_risk.get_event(request_id)`** (a paid add-on; 409 `device_risk_off` until the workspace turns it on), and `device_risk_request_id:` (or `device_risk:`) on `login.request` and `risk.check`. The page's requestId comes from `@touchque/web` `deviceRisk.identify`. Every signal only ever asks for more (`"stepUp"`, never a refusal); signals start in shadow.
- **Pairing a browser by QR code: `tq.qr_pairings`.** `create(key_thumbprint, client_ip:, user_agent:, browser:, os:, ttl_seconds:)` registers a pairing for the browser key your page holds (`@touchque/web` `browserKey.thumbprint()`) and returns `"uri"` (`touchque://pair-browser?...`) to show as a QR code; the nonce in it stays with you (Touchque keeps its hash). `get(pairing_id)` says who scanned it and how near the phone was (`"proximity"`), `refuse(pairing_id, reason:, message:)` tells the phone why your own checks said no. `login.request(..., qr_pairing:)` asks the phone that scanned, once, with number matching. `Resources::QrPairings.uri`, `REFUSAL_REASONS`.
- **Actions: the `agent.approval` trigger**, before an AI agent's request reaches the phone (`trigger: "agent.approval"`); only tightening counts: `api.deny`, `api.requirePasskey`, `api.stepUp`. See [Actions](https://support.touchque.com/actions).
- **Webhook reason `user_blocked_agent`** (`Webhook::REASON_USER_BLOCKED_AGENT`): the person rejected an AI agent's request with Block this agent on their phone; the agent may not ask them again, and 2FA is not frozen. `agents.list_blocks` can return the block reason `"phone"`.
- Request options and resources at the 4.1.0 surface: `challenge_digits:`, `expires_in:`, `client_signals:`, `security_changes:`, `destination:` and `locale:` on login requests; `client_signals:` on risk checks; the linked phone's posture on `auth.get_user`; `offline.totp_verifiers` + `Offline.match_totp_verifier` for a Touchque outage; Touchque Login email and SMS providers (`identity.set_delivery`) and attack protection; Mobile SDK settings with your own APNs key / FCM service account, `androidCerts` and `mobile.test_push`.
- **AI agents: events for a SIEM.** `agents.list_events(after:, since:, limit:)`: the workspace's agent events (`AGENT_*`, `AGENTS_*`) oldest first, each with its agent, person, approval and case code; keep `"next"` and pass it as `after:`.
- **AI agents: the workspace's policy and a passkey line.** `agents.workspace_policy` / `set_workspace_policy(policy)`: every agent's floor (an agent's own policy can only be stricter, field by field). `"requirePasskeyAbove" => { "TRY" => "10000.00" }` in any policy: over it the person approves with a passkey on your page (`"requiresPasskey"` on the approval), never on the phone or with a mandate; a background request gets 409 `interactive_required`. `Webhook::EVENT_AGENT_WORKSPACE_POLICY_CHANGED`. A second approver who answers sooner than a person can gets no token (status `blocked`, reason `inhuman_approval`).
- **Touchque Login: the approving app's name and custom-domain-only sign-in.** `identity.set_approver_app_name(name)`: the phone app the hosted pages tell customers to approve on ("Approve on the Acme app"; `nil` = your brand when the Mobile SDK is set up, else Touchque). `identity.set_custom_domain_only(true)`: serve sign-in only on the primary custom domain ({slug}.login.touchque.com redirects page loads there and refuses other calls; needs a verified primary domain with a working certificate). `identity.check_domain_certificate(domain_id)`: the domain's certificate at the sign-in edge now (`certificate`: pending, active or error).
- **Cross App Access (ID-JAG) and A2A agent cards.** `CrossAppAccess.request_id_jag` trades a member's ID token for an ID-JAG at the organization's identity provider, `redeem_id_jag` trades it for an access token at the other service (jwt-bearer); `IdJagVerifier` checks one at your own authorization server (typ, issuer, single audience, client, expiry, used once; `first_use` for a shared store). `AgentCard.verify` checks an A2A card's signatures (JWS over the RFC 8785 canonical card; `jku` only on the card's host or `trusted_jku_hosts`), `sign`, `canonical_json`.
- **`Touchque::Client`** (Ruby 3.1+, standard library only): `auth`, `login` (request, status,
  `verify` with an `on_challenge` block, `consume`, `report_fraud`, recovery codes), `webauthn`,
  `offline` (QR and typed codes, outage verifiers), `risk` (silent sign-ins), `action_types`
  (Second Thought questions), `actions` (Touchque Actions and their secrets), `recovery` (Never
  Locked Out), `assist` (help desk), `agents` (with the token vault, mandates, blocks, the kill
  switch, approval tokens), `identity` (the Touchque Login Management API), `mobile` (the Mobile
  SDK's server side, `push_from_webhook`) and `webhook` (signature, timestamp window, replay cache).
- `start` / `check` / `complete` and `Touchque::Guard.run`: the two-phase step-up contract shared
  by every Touchque server SDK, with offline codes, silent sign-ins, Vishing Shield, Mirror Alarm
  canaries and "Why?" case codes.
- `Touchque::RelayHandler` and `Touchque::Rack::Relay`: the routes `@touchque/web` calls, with rate limits.
- `Touchque::ApprovalProof`, `ApprovalToken`, `AgentKeys` (ES256 and EdDSA), `Touchque::Agent`
  (private_key_jwt + DPoP), `Touchque::OrgAgent` (Touchque SSO agents) and `Touchque::McpAuth`.
- `Touchque::HostedLogin` (Touchque Login OpenID Connect client) and `Touchque::MyAccount`;
  `Touchque::LoginSession` (encrypted, chunked cookies, readable by the Node SDK's sealSession).
- **Rails**: a Railtie (`config.touchque`, credentials), `Touchque::Rails::Guard`
  (`require_touchque`), `Touchque::Rails::Webhook` (`verify_touchque_webhook`),
  `Touchque::Rails::HostedLogin` (`/login`, `/callback`, `/logout`, `require_touchque_sign_in`)
  and `Touchque::Rails.login_routes`.
