# touchque (Ruby)

The official Ruby server SDK for [Touchque](https://touchque.com): push approvals with number
matching, passkeys, silent sign-ins, offline codes, verified webhooks, Touchque Actions, AI agent
approvals, Touchque Login (hosted sign-in and the Management API) and the server side of the
Mobile SDK. Rails integration included (a Railtie and controller concerns), plus a Rack relay for
Sinatra and any Rack app.

Ruby 3.1+, no runtime dependencies beyond the standard library (`net/http`, `openssl`, `json`).

📘 Full docs: **[support.touchque.com](https://support.touchque.com)**

## Install

```ruby
# Gemfile
gem "touchque"
```

## Setup

Get an API key and secret from your [Touchque dashboard](https://dashboard.touchque.com):

```bash
export TQ_API_KEY=tq_auth_your_key
export TQ_API_SECRET=your_api_secret
```

The secret signs every request: it belongs on your server only, never in a browser or an app.

```ruby
tq = Touchque.client                                             # from the environment, shared
tq = Touchque::Client.new(api_key: "tq_...", api_secret: "...")   # explicit
```

In Rails the Railtie reads `config.touchque` (or `credentials.touchque`, then the environment):

```ruby
# config/application.rb
config.touchque.api_key = Rails.application.credentials.dig(:touchque, :api_key)
config.touchque.api_secret = Rails.application.credentials.dig(:touchque, :api_secret)
```

## Quick start (Rails)

One line per protected action:

```ruby
class TransfersController < ApplicationController
  include Touchque::Rails::Guard
  require_touchque "SEND_MONEY", only: :create,
                   details: -> { { "Amount" => params.require(:amount), "To" => params.require(:to) } }

  def create
    touchque_approval   # only reached once the user approved on their phone
  end
end
```

Until the user approves on their phone the action answers
**`202 {"touchque": step, "token": "..."}`**. Your page shows `step` in its own design (the
matching number, or a QR code the first time the user links the app) and sends the same request
again with header `X-Touchque-Token: <token>`; [`@touchque/web`](https://www.npmjs.com/package/@touchque/web)
does this loop for you. Once approved the action runs **once**. Refusals answer 403 (rejected,
blocked), 408 (expired), 423 (frozen) or 429 (rate limited) with `Retry-After`.

The approving user is `current_user`'s email (else id, else username). For your login action
(nobody is signed in yet) pass `user: -> { session[:password_verified_user] }`.

**The end user's address.** The risk checks (Tor, location, impossible travel) and the location
shown on the phone use `request.remote_ip`: configure `config.action_dispatch.trusted_proxies`
behind a load balancer.

## Action types

`"SEND_MONEY"` above is an action type: one kind of approval, with the title the phone shows and
whether it is critical. Define each one once, in the dashboard (**Developers → Action types**)
or from code:

```ruby
tq.action_types.define("SEND_MONEY", name: "Send money", critical: true)
```

The guard refuses what is not ready. A name that is not defined is a setup error
(`Touchque::ConfigError`, "Unknown action …"): the guard answers 500 with `reason: "misconfigured"`. A type
turned off in the dashboard answers 403 with `reason: "action_disabled"`, which stops that kind of
approval at once, without a deploy.

## The three primitives (any framework)

```ruby
step = tq.start("SEND_MONEY", "jane@acme.com", details: { "Amount" => "250 EUR" })
# step["state"]: waiting (show step["number"]) | enroll (show step["enroll"]["qrCodeDataUrl"]) | passkey_required | blocked | frozen | rate_limited
now = tq.check(step["requestId"])
approval = tq.complete(step["requestId"], "jane@acme.com", "SEND_MONEY", details: { "Amount" => "250 EUR" })
# uses the approval once, and only for this user, action and amount
```

`Touchque::Guard.run(tq, user, action, token:, offline:, code:, ...)` is the whole two-phase
contract for Sinatra, Hanami or plain Rack.

## Waiting in one call

```ruby
result = tq.login.verify("jane@acme.com", type: "LOGIN", client_ip: request.remote_ip, user_agent: request.user_agent) do |c|
  # Number matching: show the number now; the phone asks for it.
  notify("Pick #{c["challengeCode"]} on your phone") if c["challengeCode"]
end
```

`verify` raises `Touchque::RejectedError`, `Touchque::TimeoutError` or
`Touchque::PasskeyRequiredError` (`reason` "policy": approve with a passkey; "step_up": the user
tapped Approve during a call and the request now waits for a passkey).

## Relay routes for `@touchque/web`

```ruby
# config/routes.rb
mount Touchque::Rack::Relay.new(
  get_user_id: ->(req) { req.session["user_email"] },
  # The user who already passed your password step. Binds /login and the offline routes to them.
  get_login_user: ->(req) { req.session["password_verified_user"] },
  on_authenticated: ->(req, response, info) { req.session["user_email"] = info["externalUsername"] },
  silent_sign_in: true   # a known browser with nothing new skips the push
) => "/touchque"
```

Routes: `POST /login`, `/enroll/start`, `GET /enroll/status`, `/offline/challenge|verify|totp`,
`/passkey/authenticate/options|verify`, `/passkey/login/options|verify`,
`/passkey/register/options|verify`, `GET /passkey/credentials`, `DELETE /passkey/credentials/:id`.
Pre-auth routes are rate limited (20 per IP, 5 per username a minute; pass `rate_limit: { store: }`
for Redis across processes). The offline routes stay off until `get_login_user` is set. Adding a
passkey for a user with a linked phone waits for the phone first.

## Webhooks

```ruby
class TouchqueWebhooksController < ActionController::API
  include Touchque::Rails::Webhook
  verify_touchque_webhook

  def create
    EndSession.call(touchque_webhook["requestId"]) if touchque_webhook["event"] == Touchque::Resources::Webhook::EVENT_APPROVAL_REVOKED
    head :ok
  end
end
```

The signature (your API secret over the canonical JSON), the signed timestamp (5 minutes) and the
`jti` are checked first: a bad one answers 401, a replay 200 without running your action again.
`Touchque.replay_cache` is in-process by default; with several Puma workers or hosts set one over
Redis (`check_and_set(jti, ttl_seconds)` with `SET NX EX`). Anywhere else:
`tq.webhook.verify(raw_body, signature_header, replay_cache: cache)`.

## Silent sign-ins

```ruby
risk = tq.risk.check(user, browser_proof: request.headers["X-Touchque-Browser"], client_ip: request.remote_ip)
sign_in(user) if risk["prompt"] == false   # a known browser, nothing new: no push
```

Fails closed: only an answer of exactly `prompt: false` skips the phone. `tq.risk.browsers(user)`
lists a user's known browsers; `forget_browsers(user)` forgets them (after a password reset).

## Passkeys, offline codes, recovery, help desk

- `tq.webauthn`: registration, second factor and passwordless sign-in options/verify, list and delete passkeys.
- `tq.offline`: QR challenge and typed codes with the phone offline; `totp_verifiers` +
  `Touchque::Resources::Offline.match_totp_verifier` check time-based codes while Touchque is unreachable.
- `tq.recovery` (Never Locked Out): vouchers, `start` (show `bindUri` as a QR), `status`, `veto`.
- `tq.assist` (help desk): `open`, `verify` (a 2-digit code the agent reads to the person), `spend`, `unfreeze`, `end`.
- `Touchque::ApprovalProof.verify(proof, request_id:, type:, details:, expected_public_key:)`: the
  phone's own signature over what it showed ("what you see is what you sign").

## Touchque Actions

```ruby
tq.actions.deploy("night-alert", trigger: "approval.decided",
                  template: { id: "alert", params: { channel: "slack", when: { countries: ["TR"] } } })
replay = tq.actions.dry_run(trigger: "login.request", code: code, limit: 500)
```

Plus `test`, `rollback`, `logs`, `metrics`, `templates`, `secrets`. Action code is JavaScript run
by Touchque in a sandbox, whatever language your server is in. Action types:
`tq.action_types.define("SEND_MONEY", name: "Send money", critical: true)`.

## AI agents

Your server registers agents (public key only) and checks their approvals; the agent signs in with its own key:

```ruby
keys = Touchque::AgentKeys.generate                   # where the agent runs; "ES256" or "EdDSA"
agent = tq.agents.create("Invoice bot", ["PAY_INVOICE"], public_key: keys["publicJwk"])

# The agent (TQ_AGENT_ID, TQ_AGENT_KEY): private_key_jwt + DPoP, never your API key.
bot = Touchque::Agent.new
approved = bot.require_approval("ayse@acme.com", "PAY_INVOICE", [payment]) { |s| say "Type #{s["challengeCode"]} on your phone" }

# Your server, right before it pays:
tq.agents.redeem_approval(approved["approvalToken"], user: "ayse@acme.com", authorization_details: payment)
```

Also: mandates (`request_mandate`), the token vault (`tq.agents.vault`, `bot.get_connection_token`),
policies, blocks, the kill switch, offline token checks (`verify_approval_token`).
`Touchque::OrgAgent` is an organization's agent on Touchque SSO (DPoP tokens for one app, token
exchange, CIBA, the token vault, shared accounts; GitHub Actions and Kubernetes tokens instead of
a stored key). `Touchque::McpAuth` protects an MCP server whose authorization server is Touchque SSO.

### Cross App Access (ID-JAG) and A2A agent cards

An organization's identity provider (Touchque SSO) can let one of its apps reach another service for a member with no consent screen (Cross App Access, ID-JAG, an open IETF draft): the app trades the member's ID token for an ID-JAG, then the ID-JAG for an access token at the other service. If you run an authorization server, the verifier checks an ID-JAG (issuer, single audience, your client, expiry, `typ`) and uses it once. Before your agent trusts another agent's A2A card, check its signatures (A2A 1.0 §8.4: JWS over the RFC 8785 canonical card); keys named by `jku` are only fetched from the card's own host or hosts you trust.

```ruby
jag = Touchque::CrossAppAccess.request_id_jag(issuer: "https://sso.touchque.com", client_id: client_id, client_secret: secret,
                                              id_token: id_token, audience: "https://auth.files.example")
tokens = Touchque::CrossAppAccess.redeem_id_jag(token_endpoint: "https://auth.files.example/token", client_id: "acme",
                                                client_secret: files_secret, assertion: jag["assertion"])

# Your own authorization server (jwt-bearer grant):
claims = Touchque::IdJagVerifier.new(issuer: "https://sso.touchque.com", audience: "https://auth.files.example")
                                .verify(params[:assertion], client_id: authenticated_client_id)

Touchque::AgentCard.verify(card_json, card_url: "https://agent.example/.well-known/agent-card.json")
```

## Shared Signals (security events from Touchque SSO)

When something happens to a member's account after sign-in (sessions revoked, credentials changed or compromised, a device out of compliance, the account disabled), Touchque SSO sends a Security Event Token (OpenID Shared Signals Framework 1.0) to the receivers the organization's admin adds (Organization > Continuous access). Your app ends the person's sessions or asks them to sign in again. The verifier reads the keys from the issuer's `/.well-known/ssf-configuration` and checks the signature, `typ`, issuer, audience and the one event. A SET does not expire: keep the `jti`s you handled and skip a repeat.

```ruby
SSF = Touchque::SecurityEventVerifier.new(issuer: "https://sso.touchque.com", audience: "https://app.example.com")

# Push (RFC 8935): the SET is the request body (application/secevent+jwt).
def create
  event = SSF.verify(request.raw_post)   # "name": session-revoked, credential-change, account-disabled...
  end_sessions_of(event["subject"]["email"]) if event["name"] == "session-revoked"
  head :accepted
rescue Touchque::SecurityEventError => e
  render json: { err: e.error, description: e.message }, status: e.error == "temporarily_unavailable" ? 503 : 400
end

# Poll (RFC 8936): acknowledge what you handled on the next call.
ack = []
loop do
  out = Touchque::SecurityEvents.poll(url: poll_url, token: stream_token, ack: ack, max_events: 50, return_immediately: true)
  ack = out["sets"].map do |jti, set|
    handle(SSF.verify(set))
    jti
  end
  break if ack.empty? && !out["more_available"]
end
```

`verify` returns `"jti"`, `"issuer"`, `"audience"`, `"issued_at"`, `"txn"` (the case code of Touchque's decision), `"subject"`, `"type"`, `"name"` and `"claims"`, or raises `Touchque::SecurityEventError` whose `error` is the RFC 8935 code to answer (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`; `temporarily_unavailable` when the issuer's keys could not be read). Report a SET you refuse while polling with `set_errs: { jti => { "err" => e.error, "description" => e.message } }`.

## Touchque Login (hosted sign-in)

```ruby
# config/application.rb
config.touchque.login = { domain: "acme.login.touchque.com", client_id: "...", client_secret: "...",
                          scope: "openid profile email offline_access" }

# config/routes.rb
Touchque::Rails.login_routes(self)        # GET /login, /callback, /logout

class AccountController < ApplicationController
  include Touchque::Rails::HostedLogin
  before_action :require_touchque_sign_in
  def show = render(json: touchque_session["user"])
end
```

The session lives in encrypted cookies (AES-256-GCM, split when large, no session store needed;
keyed from `config.touchque.session_secret` or `secret_key_base`) and is refreshed before the
access token expires. `Touchque::HostedLogin` is the OpenID Connect client underneath (PKCE, ID
and access token checks, refresh, token exchange, CIBA, the token vault, client credentials,
logout); your API checks access tokens with `verify_access_token(token, audience:, required_scopes:)`.
`login.my_account(access_token)` is the customer's own account API. The Management API is
`tq.identity` (users, roles, organizations, apps, connections, imports and exports, attack
protection, email and SMS providers).

## Mobile SDK (your own app approves)

```ruby
e = tq.mobile.create_enrollment(user_id)                          # the app spends e["enrollmentToken"]
push = Touchque::Resources::Mobile.push_from_webhook(event)        # a MOBILE_PUSH webhook → APNs payload / FCM data
```

Or give Touchque your APNs key / FCM service account (`update_settings(apns:, fcm:)`) and it pushes for you.

## Pairing a browser by QR code

Your page shows a QR code, the person scans it with the Touchque app, and the phone that scanned is the one asked to approve, with number matching. Your page sends the thumbprint of its browser key (`@touchque/web` `browserKey.thumbprint()`); the nonce in the QR never leaves your server (Touchque keeps its hash).

```ruby
p = tq.qr_pairings.create(key_thumbprint, client_ip: request.remote_ip, user_agent: request.user_agent)
# show p["uri"] (touchque://pair-browser?...) as a QR code; poll:
now = tq.qr_pairings.get(p["pairingId"])            # waiting -> scanned -> confirmed
tq.login.request(now["externalUsername"], qr_pairing: p["pairingId"]) if now["state"] == "confirmed"
# or: tq.qr_pairings.refuse(p["pairingId"], reason: "device_not_approved", message: "Ask IT to approve this computer.")
```

`get` says `scanned` / `confirmed` once a phone holding one of your users' accounts read it (with `proximity`: same network, same country), `reported` when the person said someone told them to scan it (their 2FA freezes). `refuse` tells the phone why your own checks said no.

## A code typed back on the phone

When a sign-in needs a code another service sent the person (a text message, WhatsApp, e-mail), ask them to type it on the phone instead. The phone encrypts it to a one-time key you made for this request: Touchque only ever holds the ciphertext. Such a request lives 5 minutes.

```ruby
key = Touchque::CodeReply.new_key   # keep key["privateKey"] for this request
sent = tq.login.request(user, reply: { kind: "code", key: key["publicKey"], channel: "sms", target: "+**********26" })
status = tq.login.status(sent["requestId"])   # once CONFIRMED
code = status["reply"] && Touchque::CodeReply.open(key["privateKey"], sent["requestId"], status["reply"]["ct"])
```

## Safe Guard (Safe transactions approved on the phone)

TouchqueSafeGuard is a transaction guard for a Safe: a transaction runs only with approvals signed by the P-256 keys on its approvers' phones. You send the raw transaction; the phone decodes it itself, shows its own rows and signs what it computed with a key only its biometrics unlock. Delegatecalls, changes to the Safe and proxy upgrades are governance: scheduled, time-locked and vetoable. A phone without that key yet gets `409 crypto_key_missing`.

```ruby
target = { "chainId" => 1, "safe" => safe, "guard" => guard,
           "tx" => { "to" => to, "value" => 0, "data" => data, "operation" => 0, "nonce" => 42 } }
sent = tq.safe_guard.request("treasurer@acme.com", "safe_payment", target.merge( # an action type from your dashboard
  "config" => { "threshold" => 2, "govThreshold" => 3, "govDelay" => 172_800, "exitDelay" => 259_200 },
  "batchTargets" => [multi_send_call_only],
  "approverIndex" => 0 # this approver's index in the guard
))
done = tq.safe_guard.wait_for_approval(sent["requestId"]) # 5 minutes at most
approval = done["safeTx"]["approval"]

# Check it yourself: your own transaction, the approver's key from the guard on chain, and what
# you are about to do with it: "approve" runs this transaction, "schedule" starts a governance change.
purpose = done["safeTx"]["purpose"] == "schedule" ? "schedule" : "approve"
check = Touchque::SafeApproval.verify(target, approval, approver_key, purpose: purpose, approver_index: 0)
raise "approval refused: #{check["reason"]}" unless check["valid"]

if purpose == "approve"
  signatures = Touchque::SafeApproval.with_approvals(owner_signatures, [approval]) # execTransaction(..., signatures)
else
  data = Touchque::SafeApproval.schedule_call(safe, check["governanceHash"], [approval]) # a call to the guard; runs after govDelay
end
```

`Touchque::SafeApproval.verify` makes the guard's check off chain, so a co-signer or your own server never has to trust Touchque: it computes the Safe transaction hash (EIP-712) and the governance hash from the raw fields, rebuilds the 149-byte message the phone signed and checks the P-256 signature. `purpose:` defaults to `"approve"`: a schedule approval covers no Safe nonce or gas fields, so it is accepted only when you pass `purpose: "schedule"`, never as permission to execute. It refuses a high `s`, an approval that expired or is valid for more than a day, another approver index, and, when you pass `rows:` or `display_digest:` from your own decoding, rows the phone did not show. `"reason"` is `approval_malformed`, `public_key_invalid`, `approver_index_mismatch`, `approval_expired`, `rows_differ`, `high_s` or `signature_invalid`. `safe_tx_hash`, `governance_hash`, `message` and `display_digest` are public too.

## Errors, case codes and retries

| Error | When |
| --- | --- |
| `Touchque::APIError` | Touchque answered with an error: `status`, `code` (`device_not_linked`, `already_used`...), `case_code`, `retry_after`, `data` |
| `Touchque::NetworkError` | the request never reached Touchque (safe to retry) |
| `Touchque::RejectedError`, `TimeoutError`, `PasskeyRequiredError` | `verify` outcomes |
| `Touchque::WebhookSignatureError`, `WebhookReplayError` | webhooks |
| `Touchque::ApprovalError`, `ApprovalMismatchError` | agent approvals |
| `Touchque::ConfigError` | a missing key, an unknown action type, a wrong argument |

A feature your organization cannot use here raises a `Touchque::FeatureError` (still an `APIError`, status 403) with `feature` (`device_risk`, `ai_agents`…) and `feature_reason`: `FeatureNotInPlanError`, `FeatureReadOnlyError` or `FeatureOffError` — not in its plan (an owner or admin adds it in the Touchque dashboard), being turned off (reads work for 14 days, changes are refused) or switched off on this Touchque deployment.

**"Why?" case codes.** Refusals and pushes carry a 6-character case code (`K7P-2QX`): show it
("Tell your support team: K7P-2QX"); your team opens the whole decision by it in the dashboard.

**Retries.** Every request is signed with a one-time nonce, so the SDK never replays one. Retry
`Touchque::NetworkError` at the call site; on 429 / 423 wait `retry_after` seconds. The client
never follows redirects and refuses plain `http://` except for localhost.

## Logging

The SDK writes nothing to `$stderr` on its own. To see its own problems (a misconfigured guard, a failed `on_challenge`, a relay without `get_login_user`), set a logger: `Touchque.logger = Rails.logger` (or any `Logger`). Lines carry an error's class and message, never the request.

## Development

```bash
bundle install
bundle exec rake test   # needs Node.js: the tests run against testing/fake-touchque-api.mjs and fixtures/
gem build touchque.gemspec
```

## License

MIT
