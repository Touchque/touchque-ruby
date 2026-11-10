#!/usr/bin/env node
// Shared fake Touchque API for the contract tests of every server SDK (Node, Python, PHP, Go,
// .NET, Ruby, Java), @touchque/web and the SSO backend's integration tests.
// No dependencies. Verifies request signatures like the real API
// (HMAC-SHA256 over METHOD:path[?query]:timestamp:nonce:sha256(body)), so
// every SDK's signing is tested too. It is stricter than the API is until
// 2026-12-31: a request with a query string must sign the path and the query
// (the API still takes a path-only signature with a Deprecation header until
// then, and answers 401 SIGNATURE_LEGACY_REJECTED after). The timestamp may
// be at most 5 minutes old and at most 1 minute ahead, as in the API.
//
//   node testing/fake-touchque-api.mjs   → prints {"port":NNNN} on stdout
//   API key: tq_test_key   API secret: test_secret
//
// Feature gate: /__test/opts { featureRefused: 'feature_not_in_plan' | 'feature_read_only' | 'feature_off',
// feature } makes every signed call answer 403 { error, feature, message } until it is set to null.
// TouchQue Login: /identity/* answers signed calls with { ok: true } (lists, jobs: their shapes).
// QR pairing: POST /qr-pairings, GET /qr-pairings/{id}, POST /qr-pairings/{id}/outcome; the phone's side
// is test control: POST /__test/qr-scan {id?, user, proximity?, confirm?}, /__test/qr-report {id?},
// /__test/qr-decline {id?}; /login/request with qrPairing asks once, number matched, for the user that scanned.
// Test control (unsigned): GET /__test/requests, POST /__test/link {user}, /__test/approve {id?, via?, provisional?, reply?, replyCode?},
// /__test/reject {id?}, /__test/escalate {id?} (Vishing Shield: the phone tap
// moved the request to a passkey), /__test/reconfirm {id?}, /__test/revoke
// {id?, reason?}, /__test/opts {...} (canary: true adds `canary` to new
// requests; silent: true makes POST /risk/check answer prompt:false for an
// everyday action), /__test/reset; GET /__test/calls, GET /__test/last-check
// (the body of the last POST /risk/check, or null)
//
// Silent sign-ins: POST /login/request remembers `browserProof`; approving
// such a request (not provisional) makes that browser known to
// GET /risk/browsers until POST /risk/browsers/forget.
//
// Never Locked Out: /recovery/* keeps vouchers and cases in memory. A linked
// user can vouch. POST /__test/recovery {id?, to} moves a case to VOUCHING
// (the new phone bound, codes 11, 12, ...), COOLING or COMPLETED.
//
// TouchQue Actions: /actions* keeps Actions, versions and secret names in
// memory (no code runs: test and dry-run answer empty results). A version that
// asks for a capability is pending_approval until POST /__test/approve-version
// {slug, number} (the dashboard's phone approval).
//
// AI agents: /agents* keeps agents and the kill switch in memory. The agent's
// own calls (POST /agents/token, GET /agents/me) are not HMAC-signed: they
// are checked like the API does it, with a private_key_jwt assertion
// (ES256 / EdDSA, iss = sub = agent id, aud = this server's /agents/token,
// jti once) and DPoP proofs (htm, htu, iat, jti once, ath, bound key).
// Approvals: POST /agents/approvals makes a login request (approve or reject
// it with /__test/approve, /__test/reject); once approved, GET
// /agents/approvals/:id hands out an approval token signed with the fake's
// own key (GET /agents/jwks.json), and POST /agents/approvals/redeem uses it once.
//
// Help desk: /assist* keeps sessions in memory; the person's phone answers a
// check on POST /__test/assist {requestId?, action: approve|wrong_number|not_me|coached|decline}.
import http from 'node:http';
import crypto from 'node:crypto';

const API_KEY = 'tq_test_key';
const API_SECRET = 'test_secret';

let state;
function reset() {
  state = {
    requests: [], linked: new Set(), pending: new Set(), calls: [], opts: {}, seq: 0,
    actions: new Map([['LOGIN', { critical: false }], ['SEND_MONEY', { critical: true }], ['PASSKEY_ENROLL', { critical: true }]]),
    usedEnrollApprovals: new Set(),
    challenges: new Map(), usedNonces: new Set(),
    browsers: [], lastCheck: null,
    vouchers: new Map(), recoveries: [],
    flows: new Map(), secrets: new Map(),
    agents: new Map(), agentTokens: new Map(), agentJtis: new Set(), killSwitch: { engaged: false }, approvals: new Map(),
    orgAgents: new Map(), orgAgentTokens: new Map(), cibaRequests: new Map(), sharedAsks: new Map(), vaultConnections: new Map(), vaultTokens: new Map(),
    qrPairings: new Map(),
    assists: new Map(),
  };
}
reset();

const toPairs = (d) => (!d ? null : Array.isArray(d) ? d.map((x) => ({ label: String(x.label), value: String(x.value) }))
  : Object.entries(d).map(([label, value]) => ({ label, value: String(value) })));
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const b64u = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// RFC 7638 thumbprint of the proof's key, like the API (object or base64url JSON
// string). The fake does not check the signature; an unreadable proof gets a
// stable stand-in so tests can still tell browsers apart.
function browserThumbprint(proof) {
  try {
    const p = typeof proof === 'string' ? JSON.parse(Buffer.from(proof, 'base64url').toString('utf8')) : proof;
    const { crv, kty, x, y } = p.jwk;
    if (typeof x !== 'string' || typeof y !== 'string') throw new Error('no key');
    return b64u(crypto.createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest());
  } catch {
    return b64u(crypto.createHash('sha256').update(typeof proof === 'string' ? proof : JSON.stringify(proof)).digest());
  }
}
// The engine's English texts for the reason codes the fake answers with.
const REASON_TEXT = {
  known_browser: 'This browser proved its device-bound key',
  recent_approval: 'Approved on the phone in this browser 3 h ago',
  same_phone: 'The same phone approved this browser',
  familiar_network: 'Country and network seen in earlier approved sign-ins',
  no_risk_signal: 'No risk signal',
  no_browser_key: 'No device-bound browser key was presented',
  new_browser: 'This browser has not been approved on the phone for this account',
  critical_action: 'The action is critical',
  passkey_required: 'The workspace requires a passkey for this action',
  number_match_requested: 'The risk check asked for number matching',
  phone_not_linked: 'No phone is linked to this account',
};
const reasons = (...codes) => codes.map((code) => ({ code, text: REASON_TEXT[code] }));
// Like the API: only a real second factor makes a browser known (a confirmed push that is not provisional, a passkey).
function rememberBrowser(r) {
  if (!r.browserProof || r.status !== 'CONFIRMED' || r.provisional) return;
  const thumbprint = browserThumbprint(r.browserProof);
  const now = new Date().toISOString();
  const lastMfaMethod = r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push';
  const known = state.browsers.find((x) => x.user === r.user && x.thumbprint === thumbprint);
  if (known) Object.assign(known, { lastMfaAt: now, lastMfaMethod, lastSeenAt: now });
  else state.browsers.push({ user: r.user, thumbprint, label: 'Browser', createdAt: now, lastMfaAt: now, lastMfaMethod, lastSeenAt: now, lastSilentAt: null });
}

function verifySignature(req, rawBody) {
  const key = req.headers['x-api-key'];
  const sig = req.headers['x-signature'];
  const ts = req.headers['x-timestamp'];
  const nonce = req.headers['x-nonce'];
  if (key !== API_KEY) return 'bad_key';
  if (!sig || !ts || !nonce) return 'missing_headers';
  if (String(nonce).length < 16) return 'short_nonce';
  if (state.usedNonces.has(nonce)) return 'nonce_reused';
  // Like the API (API_TIMESTAMP_TOLERANCE_MS, API_TIMESTAMP_FUTURE_SLACK_MS): at most 5 minutes old, at most 1 minute ahead.
  const tsMs = /^\d+$/.test(String(ts).trim()) ? Number(String(ts).trim()) : Date.parse(ts);
  const now = Date.now();
  if (!Number.isFinite(tsMs) || tsMs < now - 5 * 60 * 1000 || tsMs > now + 60 * 1000) return 'bad_timestamp';
  const signs = (p) => {
    const expected = crypto.createHmac('sha256', API_SECRET).update(`${req.method}:${p}:${ts}:${nonce}:${sha256(rawBody)}`).digest('hex');
    return expected.length === String(sig).length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(sig)));
  };
  if (!signs(req.url)) {
    // The path without its query: the old signing form, which leaves the query unsigned (see the header).
    const [path] = req.url.split('?');
    return path !== req.url && signs(path) ? 'legacy_signature' : 'bad_signature';
  }
  state.usedNonces.add(nonce);
  return null;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

// What the API says with each feature refusal.
const FEATURE_MESSAGES = {
  feature_not_in_plan: 'This feature is not part of your organization’s plan.',
  feature_read_only: 'This feature is being turned off: it can be read and exported, not changed.',
  feature_off: 'This feature is not available yet.',
};

// The phone's half of a code reply (POST /login/request `reply`): ECDH P-256 with a one-time key,
// HKDF-SHA256 (salt: the request id, info "touchque-code-reply-v1"), AES-256-GCM with
// "touchque-code-reply:<request id>" as additional data; "v1.<its key, x9.63>.<nonce|ciphertext|tag>".
function sealReply(publicKey, requestId, code) {
  const raw = Buffer.from(publicKey, 'base64url');
  const peer = crypto.createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33, 65).toString('base64url') }, format: 'jwk' });
  const eph = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: peer });
  const key = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(requestId, 'utf8'), Buffer.from('touchque-code-reply-v1', 'utf8'), 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(Buffer.from(`touchque-code-reply:${requestId}`, 'utf8'));
  const body = Buffer.concat([c.update(Buffer.from(code, 'utf8')), c.final()]);
  const jwk = eph.publicKey.export({ format: 'jwk' });
  const epk = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  return `v1.${epk.toString('base64url')}.${Buffer.concat([nonce, body, c.getAuthTag()]).toString('base64url')}`;
}

const routes = [];
const route = (method, pattern, fn) => routes.push({ method, re: new RegExp(`^${pattern}$`), fn });
const pick = (id) => (id ? state.requests.find((r) => r.id === id) : state.requests[state.requests.length - 1]);
// A test hook for a request that does not exist (no id and none made yet, or an unknown id) answers 404, not a crash.
const pickOr404 = (res, id) => {
  const r = pick(id);
  if (!r) send(res, 404, { error: 'no request' });
  return r;
};

// ── test control ──
route('POST', '/__test/reset', (req, res) => { reset(); send(res, 200, { ok: true }); });
route('POST', '/__test/link', (req, res, b) => { state.linked.add(b.user); send(res, 200, { ok: true }); });
route('POST', '/__test/opts', (req, res, b) => { state.opts = { ...state.opts, ...b }; send(res, 200, state.opts); });
route('POST', '/__test/approve', (req, res, b) => {
  const r = pickOr404(res, b.id); if (!r) return;
  r.status = 'CONFIRMED'; r.confirmedVia = b.via || 'DEVICE'; r.provisional = Boolean(b.provisional);
  // A request made with `reply`: what the phone typed back, encrypted to the caller's key. `reply` is a
  // ciphertext the test sealed; `replyCode` a code the fake seals like the phone does.
  if (r.reply && typeof b.reply === 'string') r.replyAnswer = { ct: b.reply, at: new Date().toISOString() };
  if (r.reply && typeof b.replyCode === 'string') r.replyAnswer = { ct: sealReply(r.reply.key, r.id, b.replyCode), at: new Date().toISOString() };
  // A Safe Guard request: the fake does not decode; the test hands it the server's view with the phone's approval.
  if (r.safeTx && b.safeTx && typeof b.safeTx === 'object') r.safeView = { ...r.safeView, ...b.safeTx };
  rememberBrowser(r);
  send(res, 200, { id: r.id });
});
// Like the API's Vishing Shield: still PENDING, now passkey-only, the phone was refused.
route('POST', '/__test/escalate', (req, res, b) => { const r = pickOr404(res, b.id); if (!r) return; r.requiresPasskey = true; r.challengeCode = undefined; send(res, 200, { id: r.id }); });
route('POST', '/__test/reconfirm', (req, res, b) => { const r = pickOr404(res, b.id); if (!r) return; r.reconfirmedAt = new Date().toISOString(); send(res, 200, { id: r.id }); });
route('POST', '/__test/revoke', (req, res, b) => { const r = pickOr404(res, b.id); if (!r) return; r.revokedAt = new Date().toISOString(); r.revokeReason = b.reason || 'COACHED'; send(res, 200, { id: r.id }); });
route('POST', '/__test/reject', (req, res, b) => {
  const r = pickOr404(res, b.id); if (!r) return;
  r.status = 'REJECTED';
  // reason COACHED: "someone on the phone told me to" (GET /login/status rejectReason).
  if (b.reason === 'COACHED') r.rejectReason = 'user_reported_coached';
  send(res, 200, { id: r.id });
});
// QR pairing, the phone's side: scanned by the phone holding `user` (confirm: the person went on).
const qrPick = (id) => (id ? state.qrPairings.get(id) : [...state.qrPairings.values()].pop());
const qrPickOr404 = (res, id) => {
  const q = qrPick(id);
  if (!q) send(res, 404, { error: 'no pairing' });
  return q;
};
route('POST', '/__test/qr-scan', (req, res, b) => {
  const q = qrPickOr404(res, b.id); if (!q) return;
  if (q.state !== 'waiting') return send(res, 409, { code: 'already_scanned' });
  Object.assign(q, {
    state: b.confirm === false ? 'scanned' : 'confirmed', user: b.user, scannedAt: new Date().toISOString(),
    proximity: b.proximity || { sameNetwork: true, sameCountry: true, warnings: [] },
  });
  send(res, 200, { id: q.id, state: q.state });
});
route('POST', '/__test/qr-confirm', (req, res, b) => { const q = qrPickOr404(res, b.id); if (!q) return; q.state = 'confirmed'; send(res, 200, { id: q.id, state: q.state }); });
route('POST', '/__test/qr-report', (req, res, b) => { const q = qrPickOr404(res, b.id); if (!q) return; q.state = 'reported'; q.reportedAt = new Date().toISOString(); send(res, 200, { id: q.id }); });
route('POST', '/__test/qr-decline', (req, res, b) => {
  const q = qrPickOr404(res, b.id); if (!q) return;
  q.state = 'refused'; q.outcome = { reason: 'declined', message: 'Declined on the phone', caseCode: null, deviceCode: null, at: new Date().toISOString() };
  send(res, 200, { id: q.id });
});
route('GET', '/__test/qr-pairings', (req, res) => send(res, 200, [...state.qrPairings.values()]));
route('GET', '/__test/calls', (req, res) => send(res, 200, state.calls));
// The requests so far ({ id, user, type, status, reply }): a test approves one person's by id.
route('GET', '/__test/requests', (req, res) => send(res, 200, state.requests.map((r) => ({ id: r.id, user: r.user, type: r.type, status: r.status, reply: r.reply || null }))));
route('POST', '/__test/recovery', (req, res, b) => {
  const c = b.id ? state.recoveries.find((x) => x.recoveryId === b.id) : state.recoveries[state.recoveries.length - 1];
  if (!c) return send(res, 404, { error: 'no recovery' });
  c.status = b.to;
  if (b.to === 'VOUCHING') { c.newPhoneBound = true; c.vouchers.forEach((v, i) => Object.assign(v, { state: 'pending', code: String(11 + i) })); }
  if (b.to === 'COOLING') { c.vouchers.forEach((v) => Object.assign(v, { state: 'approved', code: null })); c.approvals = c.vouchers.length; c.coolOffUntil = new Date(Date.now() + 3600000).toISOString(); }
  if (b.to === 'COMPLETED') { c.method = 'vouch'; c.completedAt = new Date().toISOString(); c.endedReason = 'cooling_off_ended'; }
  send(res, 200, { id: c.recoveryId, status: c.status });
});
route('POST', '/__test/approve-version', (req, res, b) => {
  const a = state.flows.get(b.slug);
  const v = a && a.versions.find((x) => x.number === b.number);
  if (!v) return send(res, 404, { error: 'no such version' });
  Object.assign(v, { status: 'ready', approvedCapabilities: v.capabilities, approvedAt: new Date().toISOString() });
  a.activeVersion = v.number;
  send(res, 200, { ok: true });
});
route('GET', '/__test/last-check', (req, res) => send(res, 200, state.lastCheck));

// ── API ──
// Like the API, simplified: a destination is known when it is in `known`, and
// looks like one when it has the same length, start and end but is not the same.
function destinationCheck(d) {
  const flat = (v) => String(v).replace(/\s+/g, '').toUpperCase();
  const value = flat(d.value);
  const known = (Array.isArray(d.known) ? d.known : []).map(flat);
  if (known.includes(value)) return { known: true, lookalike: [] };
  const like = known.find((k) => k.length === value.length && k.slice(0, 4) === value.slice(0, 4) && k.slice(-4) === value.slice(-4));
  return { known: false, lookalike: like ? [{ field: d.kind === 'payee' ? 'name' : d.kind, reason: 'same_start_and_end', similarTo: `${like.slice(0, 4)}…${like.slice(-4)}` }] : [] };
}
route('POST', '/login/request', (req, res, b) => {
  const { externalUsername: user, type, referenceId = null, details } = b;
  if (!state.linked.has(user)) return send(res, 404, { code: 'device_not_linked', error: 'No linked device found for this user' });
  // "Why?": every decision names a case code (refusals: REF-USE, pushes: K7P-2QX, checks: CHK-2QX).
  if (state.opts.frozen) return send(res, 423, { code: 'frozen', error: 'frozen', retryAfter: 900, caseCode: 'REF-USE' }, { 'Retry-After': '900' });
  if (state.opts.rateLimited) return send(res, 429, { code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60, caseCode: 'REF-USE' }, { 'Retry-After': '60' });
  const action = state.actions.get(type);
  if (!action) return send(res, 400, { code: 'unknown_action', error: `Invalid action type: ${type}` });
  // Like the API: a QR pairing asks the phone that scanned it, for that user, once it went on, once.
  let pairing = null;
  if (b.qrPairing !== undefined && b.qrPairing !== null) {
    pairing = state.qrPairings.get(b.qrPairing);
    if (!pairing) return send(res, 404, { code: 'pairing_not_found', error: 'qrPairing is not a pairing of this workspace, or it has expired' });
    if (pairing.state !== 'confirmed') return send(res, 409, { code: 'pairing_not_confirmed', error: `The pairing is ${pairing.state}, not confirmed on the phone` });
    if (pairing.user !== user) return send(res, 409, { code: 'pairing_other_user', error: 'The pairing was scanned for another user' });
  }
  if (state.opts.blocked) return send(res, 403, { code: 'blocked', reason: state.opts.blocked, error: 'blocked', caseCode: 'REF-USE' });
  // Like the API: an approval given during a call and not re-confirmed yet pauses critical actions.
  if (action.critical && state.requests.some((x) => x.user === user && x.status === 'CONFIRMED' && x.provisional && !x.reconfirmedAt && !x.revokedAt)) {
    return send(res, 403, { code: 'blocked', reason: 'provisional', error: 'blocked', caseCode: 'REF-USE' });
  }
  const r = {
    id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user, type, referenceId, details: toPairs(details),
    status: 'PENDING', consumed: false,
    challengeCode: state.opts.passkeyOnly ? undefined : (state.opts.numberMatch || action.critical || b.requireNumberMatch === true ? '47' : undefined),
    requiresPasskey: state.opts.passkeyOnly || undefined,
    browserProof: b.browserProof || undefined,
    reply: b.reply && typeof b.reply === 'object' ? b.reply : undefined,
    pairing: pairing ? { id: pairing.id, keyThumbprint: pairing.keyThumbprint } : undefined,
  };
  if (pairing) {
    r.challengeCode = '47';
    Object.assign(pairing, { state: 'requested', requestId: r.id });
  }
  state.requests.push(r);
  const why = [...(r.requiresPasskey ? ['passkey_required'] : []), ...(action.critical ? ['critical_action'] : []), ...(state.opts.numberMatch ? ['number_match_requested'] : [])];
  send(res, 200, {
    message: 'Request sent', requestId: r.id, challengeCode: r.challengeCode, expiresAt: new Date(Date.now() + 30000).toISOString(), requiresPasskey: r.requiresPasskey,
    caseCode: 'K7P-2QX', ...(why.length && { reasons: reasons(...why) }),
    ...(state.opts.telemetry && { telemetryToken: 'tt_test' }),
    ...(state.opts.canary && { canary: { url: `http://127.0.0.1:${server.address().port}/c/canary-${r.id}.gif` } }),
    ...(b.destination && typeof b.destination === 'object' && { destination: destinationCheck(b.destination) }),
  });
});
const shieldFields = (r) => ({
  provisional: Boolean(r.provisional), reconfirmedAt: r.reconfirmedAt || null, revoked: Boolean(r.revokedAt), revokeReason: r.revokeReason || null,
});
const assurance = (r) => ({ phishingResistant: r.confirmedVia === 'WEBAUTHN', method: r.confirmedVia === 'WEBAUTHN' ? 'passkey' : 'push' });
route('GET', '/login/status/([^/]+)', (req, res, b, m) => {
  const r = pick(decodeURIComponent(m[1]));
  if (!r || r.id !== decodeURIComponent(m[1])) return send(res, 404, { code: 'not_found' });
  send(res, 200, {
    status: r.status, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details, consumed: r.consumed,
    requiresPasskey: r.requiresPasskey, confirmedVia: r.confirmedVia || null, assurance: r.status === 'CONFIRMED' ? assurance(r) : null,
    ...(r.status === 'CONFIRMED' && r.replyAnswer && { reply: r.replyAnswer }),
    ...(r.status === 'REJECTED' && r.rejectReason && { rejectReason: r.rejectReason }),
    ...(r.pairing && { pairing: r.pairing }),
    ...shieldFields(r),
  });
});

// ── Safe Guard ──
// Like the API, simplified: the fake does not decode the transaction. Its view (class, hashes,
// purpose) comes from opts.safeTxView, the approval from /__test/approve { safeTx: { … } }.
route('POST', '/safe-guard/approvals', (req, res, b) => {
  const { externalUsername: user, type, safeTx, referenceId = null } = b;
  if (typeof user !== 'string' || !user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (typeof type !== 'string' || !type) return send(res, 400, { code: 'invalid_request', error: 'type (an action type you defined) is required' });
  if (!safeTx || typeof safeTx !== 'object' || !safeTx.tx || typeof safeTx.tx !== 'object') return send(res, 400, { code: 'invalid_safe_tx', error: 'safeTx.tx must be an object' });
  if (!Number.isInteger(safeTx.approverIndex)) return send(res, 400, { code: 'invalid_safe_tx', error: 'safeTx.approverIndex must be an integer from 0 to 31' });
  if (!state.linked.has(user)) return send(res, 404, { code: 'device_not_linked', error: 'No linked device found for this user' });
  const view = { class: 'ordinary', flags: [], safeTxHash: null, governanceHash: null, purpose: 'approve', ...state.opts.safeTxView };
  const r = {
    id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user, type, referenceId, details: null,
    status: 'PENDING', consumed: false, safeTx, safeView: view,
  };
  state.requests.push(r);
  send(res, 200, {
    message: 'Request sent', requestId: r.id, expiresAt: new Date(Date.now() + 1000 * (b.expiresIn || 300)).toISOString(), caseCode: 'K7P-2QX',
    safeTx: { class: view.class, flags: view.flags, safeTxHash: view.safeTxHash, governanceHash: view.governanceHash, rows: view.rows || [] },
  });
});
route('GET', '/safe-guard/approvals/([^/]+)', (req, res, b, m) => {
  const r = state.requests.find((x) => x.id === decodeURIComponent(m[1]) && x.safeTx);
  if (!r) return send(res, 404, { code: 'not_found', error: 'No such approval' });
  const v = r.safeView;
  send(res, 200, {
    requestId: r.id, externalUsername: r.user, status: r.status, provisional: Boolean(r.provisional),
    safeTx: {
      class: v.class, flags: v.flags, safeTxHash: v.safeTxHash, governanceHash: v.governanceHash, purpose: v.purpose, approverIndex: r.safeTx.approverIndex,
      ...(r.status === 'CONFIRMED' && v.approval && { approval: v.approval, expiresAt: v.expiresAt }),
    },
  });
});

// ── QR pairing (the partner's side) ──
const qrView = (q) => ({
  pairingId: q.id, state: q.state, keyThumbprint: q.keyThumbprint, expiresAt: q.expiresAt, requestId: q.requestId || null,
  ...(q.user && {
    externalUsername: q.user, scannedAt: q.scannedAt, confirmedAt: null, proximity: q.proximity,
    phone: { country: q.proximity && q.proximity.sameCountry === false ? 'DE' : 'TR', location: null }, browser: { country: 'TR', location: null },
  }),
  ...(q.outcome && { outcome: q.outcome }),
  ...(q.reportedAt && { reportedAt: q.reportedAt }),
});
route('POST', '/qr-pairings', (req, res, b) => {
  const shape = /^[A-Za-z0-9_-]{43}$/;
  if (!shape.test(String(b.nonceHash || '')) || !shape.test(String(b.keyThumbprint || ''))) return send(res, 400, { code: 'invalid_request', error: 'nonceHash and keyThumbprint must be base64url SHA-256 (43 characters)' });
  const id = b64u(crypto.randomBytes(16));
  const q = { id, state: 'waiting', keyThumbprint: b.keyThumbprint, nonceHash: b.nonceHash, browser: b.browser || null, os: b.os || null, expiresAt: new Date(Date.now() + (b.ttlSeconds || 120) * 1000).toISOString() };
  state.qrPairings.set(id, q);
  send(res, 201, { pairingId: id, expiresAt: q.expiresAt });
});
route('GET', '/qr-pairings/([^/]+)', (req, res, b, m) => {
  const q = state.qrPairings.get(decodeURIComponent(m[1]));
  if (!q) return send(res, 404, { code: 'not_found', error: 'Pairing not found' });
  send(res, 200, qrView(q));
});
route('POST', '/qr-pairings/([^/]+)/outcome', (req, res, b, m) => {
  const q = state.qrPairings.get(decodeURIComponent(m[1]));
  if (!q) return send(res, 404, { code: 'not_found', error: 'Pairing not found' });
  if (!['scanned', 'confirmed'].includes(q.state)) return send(res, 409, { code: 'not_open', error: `The pairing is ${q.state}` });
  Object.assign(q, { state: 'refused', outcome: { reason: b.reason, message: b.message, caseCode: b.caseCode || null, deviceCode: b.deviceCode || null, at: new Date().toISOString() } });
  send(res, 200, qrView(q));
});
route('POST', '/login/([^/]+)/consume', (req, res, b, m) => {
  const r = state.requests.find((x) => x.id === m[1]);
  if (!r) return send(res, 404, { code: 'not_found' });
  if (r.status !== 'CONFIRMED') return send(res, 409, { code: r.status === 'REJECTED' ? 'rejected' : r.status === 'EXPIRED' ? 'expired' : 'not_approved' });
  if (r.consumed) return send(res, 409, { code: 'already_used' });
  if (r.revokedAt) return send(res, 409, { code: 'revoked' });
  r.consumed = true;
  send(res, 200, {
    consumed: true, requestId: r.id, externalUsername: r.user, type: r.type, referenceId: r.referenceId, details: r.details,
    confirmedVia: r.confirmedVia, assurance: assurance(r), approvalProof: null, ...shieldFields(r),
  });
});
route('POST', '/login/([^/]+)/report-fraud', (req, res, b, m) => {
  const r = state.requests.find((x) => x.id === m[1]);
  if (!r) return send(res, 404, { code: 'not_found' });
  const reason = b.reason === undefined ? 'other' : b.reason;
  if (!['chargeback', 'account_takeover', 'social_engineering', 'other'].includes(reason)) return send(res, 400, { code: 'invalid_reason' });
  if (b.note !== undefined && (typeof b.note !== 'string' || b.note.length > 500)) return send(res, 400, { code: 'invalid_note' });
  const alreadyReported = Boolean(r.fraudReported);
  r.fraudReported = { reason, note: b.note || null };
  send(res, 200, { reported: true, alreadyReported, requestId: r.id });
});
route('POST', '/login/recovery', (req, res, b) => send(res, 200, { success: true }));
// Silent sign-ins. Sends nothing to the phone; never 404 for an unknown user (that would reveal who has 2FA).
route('POST', '/risk/check', (req, res, b) => {
  state.lastCheck = b;
  if (typeof b.externalUsername !== 'string' || !b.externalUsername) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (state.opts.rateLimited) return send(res, 429, { code: 'rate_limited', error: 'too_many_login_requests', retryAfter: 60 }, { 'Retry-After': '60' });
  const ask = (assurance, ...codes) => send(res, 200, { prompt: true, reasons: reasons(...codes), assurance, silentMode: 'enforce', caseCode: 'CHK-2QX' });
  if (!state.linked.has(b.externalUsername)) return ask('normal', 'phone_not_linked');
  if ((state.actions.get(b.type || 'LOGIN') || {}).critical) return ask('normal', 'critical_action');
  if (state.opts.silent) {
    return send(res, 200, {
      prompt: false, reasons: reasons('known_browser', 'recent_approval', 'same_phone', 'familiar_network', 'no_risk_signal'), assurance: 'high', silentMode: 'enforce',
      caseCode: 'CHK-2QX',
    });
  }
  return ask('normal', b.browserProof ? 'new_browser' : 'no_browser_key');
});
// Device risk: an identification (requestId from deviceRisk.identify, or a relayed
// report) checked for an account; GET /device-risk/events/:requestId reads one.
// The fake keeps nothing; "flagged" (as the report or in the requestId) answers
// with a signal in shadow. As the real API: no requestId (or an empty one) is
// report "missing", one that is not a dre_ id or has "unknown" in it is
// "unknown", both with device_identification_missing in shadow; never an error.
const FAKE_VISITOR = 'tqv_fakeVisitor00000001';
const deviceVerdict = (flagged) => ({
  signals: flagged ? [{ code: 'device_many_accounts', text: 'Many accounts used from this one device', strength: 'number_match', enforced: false, evidence: { last24h: 4 } }] : [],
  stepUp: false, wouldStepUp: flagged, requires: 'none', mode: 'shadow',
});
route('POST', '/device-risk/check', (req, res, b) => {
  state.lastDeviceRisk = b;
  const id = typeof b.requestId === 'string' && b.requestId ? b.requestId : null;
  const raw = typeof b.deviceRisk === 'string' && b.deviceRisk ? b.deviceRisk : null;
  if (b.event !== undefined && !['sign_in', 'sign_up', 'password_reset', 'approval'].includes(b.event)) return send(res, 400, { code: 'invalid_request', error: 'event must be one of sign_in, sign_up, password_reset, approval' });
  const missing = !id && !raw ? 'missing' : (id && (!/^dre_[A-Za-z0-9_-]{22}$/.test(id) || id.includes('unknown')) ? 'unknown' : null);
  if (missing) {
    return send(res, 200, {
      report: missing, requestId: null, visitorId: null, confidence: null, visitor: null, counts: null,
      signals: [{ code: 'device_identification_missing', text: 'The page sent no device identification, or one that does not verify (the tag removed or blocked; ad blockers do it too)', strength: 'number_match', enforced: false }],
      stepUp: false, wouldStepUp: true, requires: 'none', mode: 'shadow', caseCode: 'DRK-3MS',
    });
  }
  const flagged = (id || raw).includes('flagged');
  send(res, 200, {
    report: 'ok', requestId: id || 'dre_fakeRequest0000000000', visitorId: FAKE_VISITOR, confidence: flagged ? 0.81 : 0.99,
    visitor: { firstSeenAt: new Date(0).toISOString(), lastSeenAt: new Date(0).toISOString(), seenCount: 2, matchedBy: flagged ? 'traits' : 'key', sealed: true, status: 'none', labels: { os: 'macOS', browser: 'Chrome', browserMajor: 130 } },
    counts: { accounts_24h: flagged ? 4 : 1, accounts_30d: flagged ? 4 : 1, signups_24h: 0, countries_24h: 1, resets_7d: 0 },
    ...deviceVerdict(flagged), caseCode: 'DRK-2QX',
  });
});
route('GET', '/device-risk/events/([^/]+)', (req, res, b, m) => {
  const id = decodeURIComponent(m[1]);
  if (!/^dre_[A-Za-z0-9_-]{22}$/.test(id) || id.includes('unknown')) return send(res, 404, { code: 'not_found', error: 'No identification with this requestId in this workspace.' });
  const flagged = id.includes('flagged');
  send(res, 200, {
    requestId: id, visitorId: FAKE_VISITOR, confidence: flagged ? 0.81 : 0.99, matchedBy: flagged ? 'traits' : 'key', sealed: true, purpose: 'sign_up',
    origin: 'https://shop.example.test', country: 'TR', createdAt: new Date(0).toISOString(), usedAt: null, externalUsername: null,
    visitor: { firstSeenAt: new Date(0).toISOString(), lastSeenAt: new Date(0).toISOString(), seenCount: 2, status: 'none', labels: { os: 'macOS', browser: 'Chrome' } },
    facts: { codes: [], evidence: { tamper: [], vm: [], privateWindow: null }, reset: false, twins: false, privateWindow: false },
    verdict: { action: 'ALLOW', available: true, ...deviceVerdict(flagged), caseCode: null, rulesVersion: 'fake' },
  });
});
// GET /device-risk/events: three made-up identifications, newest first, filtered
// by account / signal / stepUp / visitorId, one page of `limit` behind an opaque
// cursor (the index of the next one, as the real API's cursor is opaque too).
// The query as it came is kept for the SDKs' tests (GET /__test/last-device-risk-search).
const FAKE_EVENTS = [
  { requestId: 'dre_fakeEvent00000000003', at: '2026-11-09T10:02:00.000Z', visitorId: FAKE_VISITOR, kind: 'sign_in', origin: 'https://shop.example.test', externalUsername: 'ada@example.com', country: 'TR', network: null, confidence: 0.99, matchedBy: 'key', sealed: true, stepUp: true, signals: [{ code: 'device_tampered', enforced: true }], caseCode: 'DRK-3EV', bot: { result: 'not_detected', reasons: [] } },
  { requestId: 'dre_fakeEvent00000000002', at: '2026-11-09T10:01:00.000Z', visitorId: FAKE_VISITOR, kind: 'sign_in', origin: 'https://shop.example.test', externalUsername: 'ada@example.com', country: 'TR', network: null, confidence: 0.99, matchedBy: 'key', sealed: true, stepUp: false, signals: [], caseCode: null, bot: { result: 'not_detected', reasons: [] } },
  { requestId: 'dre_fakeEvent00000000001', at: '2026-11-09T10:00:00.000Z', visitorId: 'tqv_fakeVisitor00000002', kind: 'sign_up', origin: 'https://shop.example.test', externalUsername: 'bob@example.com', country: 'DE', network: null, confidence: 0.6, matchedBy: 'new', sealed: false, stepUp: false, signals: [{ code: 'device_many_accounts', enforced: false }], caseCode: null, bot: { result: 'not_detected', reasons: [] } },
];
route('GET', '/device-risk/events', (req, res) => {
  const q = Object.fromEntries(new URL(req.url, 'http://x').searchParams);
  state.lastDeviceRiskSearch = q;
  const limit = q.limit === undefined ? 25 : Number(q.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) return send(res, 400, { code: 'invalid_limit', error: 'limit must be 1 to 100' });
  if (q.ip !== undefined && !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(q.ip)) return send(res, 400, { code: 'invalid_ip', error: 'ip must be an address or a CIDR range like 203.0.113.0/24' });
  let start = 0;
  if (q.cursor !== undefined) {
    const n = Number(Buffer.from(q.cursor, 'base64url').toString('utf8'));
    if (!Number.isInteger(n) || n < 1) return send(res, 400, { code: 'invalid_cursor', error: 'cursor must be the nextCursor of an earlier answer' });
    start = n;
  }
  const hits = FAKE_EVENTS.filter((e) => (!q.account || e.externalUsername === q.account)
    && (!q.visitorId || e.visitorId === q.visitorId)
    && (!q.signal || e.signals.some((x) => x.code === q.signal))
    && (q.stepUp === undefined || String(e.stepUp) === q.stepUp));
  const page = hits.slice(start, start + limit);
  const next = start + limit < hits.length ? Buffer.from(String(start + limit)).toString('base64url') : null;
  send(res, 200, { events: page, nextCursor: next, from: '2026-11-02T10:00:00.000Z', to: '2026-11-09T10:03:00.000Z', signalTexts: {} });
});
route('GET', '/__test/last-device-risk-search', (req, res) => send(res, 200, state.lastDeviceRiskSearch || {}));
const browserView = ({ user, ...rest }) => rest;
route('GET', '/risk/browsers', (req, res) => {
  const user = new URL(req.url, 'http://x').searchParams.get('externalUsername');
  if (!user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  send(res, 200, { browsers: state.browsers.filter((x) => x.user === user).map(browserView) });
});
route('POST', '/risk/browsers/forget', (req, res, b) => {
  if (typeof b.externalUsername !== 'string' || !b.externalUsername) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  const gone = (x) => x.user === b.externalUsername && (!b.thumbprint || x.thumbprint === b.thumbprint);
  const forgotten = state.browsers.filter(gone).length;
  state.browsers = state.browsers.filter((x) => !gone(x));
  send(res, 200, { forgotten });
});
// Never Locked Out: vouchers and recovery cases (a linked user can vouch).
const voucherView = (user) => ({
  externalUsername: user,
  vouchers: (state.vouchers.get(user) || []).map((v) => (state.linked.has(v) ? { externalUsername: v, eligible: true } : { externalUsername: v, eligible: false, reason: 'no_phone' })),
  updatedAt: null,
  probationUntil: null,
});
const RECOVERY_OPEN = ['AWAITING_DEVICE', 'VOUCHING', 'COOLING'];
const recoveryView = ({ bindCode, bindUri, ...c }) => c;
route('POST', '/recovery/vouchers', (req, res, b) => {
  if (typeof b.externalUsername !== 'string' || !b.externalUsername || !Array.isArray(b.vouchers)) return send(res, 400, { code: 'invalid_request', error: 'externalUsername and vouchers are required' });
  if (!state.linked.has(b.externalUsername) && !state.pending.has(b.externalUsername)) return send(res, 404, { code: 'user_not_found', error: 'No TouchQue user with this externalUsername' });
  state.vouchers.set(b.externalUsername, [...new Set(b.vouchers.filter((v) => typeof v === 'string' && v && v !== b.externalUsername))].slice(0, 5));
  send(res, 200, voucherView(b.externalUsername));
});
route('GET', '/recovery/vouchers', (req, res) => {
  const user = new URL(req.url, 'http://x').searchParams.get('externalUsername');
  if (!user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (!state.linked.has(user) && !state.pending.has(user)) return send(res, 404, { code: 'user_not_found', error: 'No TouchQue user with this externalUsername' });
  send(res, 200, voucherView(user));
});
route('POST', '/recovery/start', (req, res, b) => {
  const user = b.externalUsername;
  if (typeof user !== 'string' || !user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' });
  if (!state.linked.has(user)) return send(res, 404, { code: 'device_not_linked', error: 'This user has no linked phone' });
  if (state.opts.blocked) return send(res, 403, { code: 'blocked', reason: 'risk', error: 'blocked' });
  const open = state.recoveries.find((c) => c.externalUsername === user && RECOVERY_OPEN.includes(c.status) && c.status !== 'AWAITING_DEVICE');
  if (open) return send(res, 409, { code: 'recovery_in_progress', recoveryId: open.recoveryId, error: 'A recovery for this user is already running.' });
  const required = Math.max(2, Number(b.required) || 0);
  const pool = [...(state.vouchers.get(user) || []), ...(Array.isArray(b.fallbackVouchers) ? b.fallbackVouchers : [])];
  const eligible = [...new Set(pool)].filter((v) => v !== user && state.linked.has(v)).slice(0, 5);
  if (eligible.length < required) return send(res, 409, { code: 'not_enough_vouchers', required, eligible: eligible.length, error: 'Not enough vouchers' });
  const id = `00000000-0000-4000-9000-${String(++state.seq).padStart(12, '0')}`;
  const bindCode = `bind-${state.seq}`;
  const c = {
    recoveryId: id, externalUsername: user, method: 'vouch', status: 'AWAITING_DEVICE', required, approvals: 0,
    vouchers: eligible.map((v) => ({ externalUsername: v, source: (state.vouchers.get(user) || []).includes(v) ? 'nominated' : 'fallback', state: 'waiting', code: null })),
    oldPhone: { notified: false, code: null }, coolOffMinutes: Math.max(15, Number(b.coolOffMinutes) || 60), coolOffUntil: null,
    elevated: false, reasons: [], location: null, newPhoneBound: false, expiresAt: new Date(Date.now() + 900000).toISOString(),
    completedAt: null, endedReason: null, endedBy: null, createdAt: new Date().toISOString(), receipts: [],
  };
  state.recoveries.push(c);
  send(res, 201, { ...c, bindCode, bindUri: `touchque://recover?id=${id}&code=${bindCode}`, riskContext: { level: 'none', reasons: [] } });
});
route('GET', '/recovery', (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const user = q.get('externalUsername');
  const open = q.get('open') === 'true';
  if (!user && !open) return send(res, 400, { code: 'invalid_request', error: 'Pass externalUsername, or open=true' });
  const list = state.recoveries.filter((c) => (!user || c.externalUsername === user) && (!open || RECOVERY_OPEN.includes(c.status)));
  send(res, 200, { recoveries: list.slice().reverse().map(recoveryView) });
});
route('GET', '/recovery/([^/]+)', (req, res, b, m) => {
  const c = state.recoveries.find((x) => x.recoveryId === decodeURIComponent(m[1]));
  if (!c) return send(res, 404, { code: 'recovery_not_found', error: 'Recovery not found' });
  send(res, 200, recoveryView(c));
});
route('POST', '/recovery/([^/]+)/veto', (req, res, b, m) => {
  const c = state.recoveries.find((x) => x.recoveryId === decodeURIComponent(m[1]));
  if (!c) return send(res, 404, { code: 'recovery_not_found', error: 'Recovery not found' });
  if (!RECOVERY_OPEN.includes(c.status)) return send(res, 409, { code: 'recovery_not_open', status: c.status, error: `This recovery is already ${c.status.toLowerCase()}` });
  Object.assign(c, { status: 'VETOED', endedReason: b.reason || 'partner_veto', endedBy: b.by || 'partner' });
  send(res, 200, recoveryView(c));
});

// Help desk assist sessions, as the API: a linked user has a phone to check
// on; a check's number is returned to the partner and the test answers for
// the phone on POST /__test/assist.
const assistView = (a) => ({
  id: a.id, externalUsername: a.externalUsername, status: a.status === 'OPEN' && Date.parse(a.expiresAt) <= Date.now() ? 'ENDED' : a.status,
  agent: a.agent, reason: a.reason, notified: a.notify, openedAt: a.openedAt, expiresAt: a.expiresAt, endedAt: a.endedAt, endedReason: a.endedReason,
  phone: state.linked.has(a.externalUsername), frozen: !!a.frozen,
  checks: a.checks.map(({ challengeCode, ...c }) => c),
});
const assistOf = (res, id) => {
  const a = state.assists.get(decodeURIComponent(id));
  if (!a) send(res, 404, { code: 'assist_not_found', error: 'Assist session not found' });
  return a;
};
const assistOpen = (res, a) => {
  if (a.status === 'OPEN' && Date.parse(a.expiresAt) > Date.now()) return true;
  send(res, 409, { code: 'assist_not_open', error: 'This assist session has ended. Start a new one.' });
  return false;
};
route('POST', '/assist', (req, res, b) => {
  const user = typeof b.externalUsername === 'string' ? b.externalUsername : '';
  if (!user || !b.agent || typeof b.agent.name !== 'string' || !b.agent.name) return send(res, 400, { code: 'invalid_request', error: 'externalUsername and agent.name are required' });
  if (!state.linked.has(user) && !state.pending.has(user)) return send(res, 404, { code: 'user_not_found', error: 'No TouchQue user with this externalUsername' });
  const ref = b.agent.ref || b.agent.name;
  for (const old of state.assists.values()) if (old.externalUsername === user && old.agent.ref === ref && old.status === 'OPEN') Object.assign(old, { status: 'ENDED', endedAt: new Date().toISOString(), endedReason: 'replaced' });
  const id = `00000000-0000-4000-b000-${String(++state.seq).padStart(12, '0')}`;
  const ttl = Math.min(120, Math.max(5, Number(b.ttlMinutes) || 30));
  const a = {
    id, externalUsername: user, agent: { ref, name: b.agent.name, title: b.agent.title || null }, reason: b.reason || null, notify: b.notify !== false,
    status: 'OPEN', openedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + ttl * 60000).toISOString(), endedAt: null, endedReason: null, frozen: false, checks: [],
  };
  state.assists.set(id, a);
  send(res, 201, assistView(a));
});
route('GET', '/assist', (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const user = q.get('externalUsername');
  const openOnly = q.get('open') === 'true';
  if (!user && !openOnly) return send(res, 400, { code: 'invalid_request', error: 'Pass externalUsername, or open=true' });
  const list = [...state.assists.values()].filter((a) => (!user || a.externalUsername === user) && (!openOnly || assistView(a).status === 'OPEN'));
  send(res, 200, { sessions: list.reverse().slice(0, 50).map(assistView) });
});
route('GET', '/assist/([^/]+)', (req, res, b, m) => { const a = assistOf(res, m[1]); if (a) send(res, 200, assistView(a)); });
route('POST', '/assist/([^/]+)/end', (req, res, b, m) => {
  const a = assistOf(res, m[1]);
  if (!a) return;
  if (a.status === 'OPEN') Object.assign(a, { status: 'ENDED', endedAt: new Date().toISOString(), endedReason: b.reason || 'ended' });
  send(res, 200, assistView(a));
});
route('POST', '/assist/([^/]+)/verify', (req, res, b, m) => {
  const a = assistOf(res, m[1]);
  if (!a || !assistOpen(res, a)) return;
  if (typeof b.action !== 'string' || !/^[a-z][a-z0-9_]*$/.test(b.action)) return send(res, 400, { code: 'invalid_request', error: 'action must be lowercase letters, digits and underscores' });
  if (!state.linked.has(a.externalUsername)) return send(res, 409, { code: 'no_phone', route: 'never_locked_out', error: 'This person has no working TouchQue phone to check.' });
  if (a.checks.length >= 10) return send(res, 429, { code: 'rate_limited', error: 'Too many checks in this session. Start a new one.' });
  const requestId = `00000000-0000-4000-c000-${String(++state.seq).padStart(12, '0')}`;
  const challengeCode = String(crypto.randomInt(10, 100));
  const expiresAt = new Date(Date.now() + 120000).toISOString();
  a.checks.push({ requestId, action: b.action, actionText: b.actionText || b.action.replace(/_/g, ' '), outcome: 'pending', createdAt: new Date().toISOString(), spentAt: null, expiresAt, challengeCode });
  send(res, 201, { requestId, challengeCode, expiresAt, action: b.action });
});
const assistSpend = (res, a, requestId, action) => {
  const c = a.checks.find((x) => x.requestId === requestId);
  if (!c || c.action !== action || c.spentAt || c.outcome !== 'verified') {
    send(res, 428, { code: 'check_required', error: 'Check the person on their phone first: the help desk reads them the number, they type it and approve.' });
    return null;
  }
  c.spentAt = new Date().toISOString();
  return c;
};
route('POST', '/assist/([^/]+)/spend', (req, res, b, m) => {
  const a = assistOf(res, m[1]);
  if (!a || !assistOpen(res, a)) return;
  if (assistSpend(res, a, b.requestId, b.action)) send(res, 200, assistView(a));
});
route('POST', '/assist/([^/]+)/unfreeze', (req, res, b, m) => {
  const a = assistOf(res, m[1]);
  if (!a || !assistOpen(res, a)) return;
  if (!assistSpend(res, a, b.requestId, 'unlock')) return;
  const was = a.frozen;
  a.frozen = false;
  send(res, 200, { unfrozen: was, session: assistView(a) });
});
route('POST', '/__test/assist', (req, res, b) => {
  const checks = [...state.assists.values()].flatMap((a) => a.checks.map((c) => ({ a, c })));
  const hit = b.requestId ? checks.find((x) => x.c.requestId === b.requestId) : checks.filter((x) => x.c.outcome === 'pending').pop();
  if (!hit) return send(res, 404, { error: 'no check' });
  const outcome = { approve: 'verified', wrong_number: 'wrong_number', not_me: 'not_me', coached: 'coached', decline: 'declined' }[b.action];
  if (!outcome) return send(res, 400, { error: 'action: approve|wrong_number|not_me|coached|decline' });
  hit.c.outcome = outcome;
  if (outcome === 'not_me' || outcome === 'coached') hit.a.frozen = true;
  send(res, 200, { requestId: hit.c.requestId, outcome, challengeCode: hit.c.challengeCode });
});

// ── TouchQue Actions (in memory; nothing runs) ──
const TRIGGERS = ['login.request', 'risk.check', 'approval.decided', 'shield.decision', 'fraud.reported', 'device.linked', 'device.keys_lost', 'user.unlinked', 'passkey.added', 'passkey.removed', 'recovery.updated'];
const flowView = (a) => ({ slug: a.slug, name: a.name, trigger: a.trigger, enabled: a.enabled, order: a.order, onFailure: a.onFailure, activeVersion: a.activeVersion, createdAt: a.createdAt, updatedAt: a.updatedAt });
const versionView = (a, v, withCode = false) => {
  const { key, code, ...rest } = v;
  return { ...rest, active: a.activeVersion === v.number, ...(withCode && { code }) };
};
const flowOf = (res, slug) => {
  const a = state.flows.get(decodeURIComponent(slug));
  if (!a) send(res, 404, { code: 'action_not_found', error: `No Action named ${slug}.` });
  return a;
};
route('GET', '/actions/triggers', (req, res) => send(res, 200, {
  triggers: TRIGGERS.map((name) => ({ name, phase: name === 'login.request' || name === 'risk.check' ? 'pre' : 'post', decisions: [], effects: [], capabilities: [] })),
  capabilities: [{ name: 'skip_number_match', trigger: 'login.request' }, { name: 'override_block', trigger: 'login.request' }, { name: 'allow_silent', trigger: 'risk.check' }],
  limits: { cpuMs: 50, memoryMb: 16, preTriggerBudgetMs: 300 },
}));
route('GET', '/actions/templates', (req, res) => send(res, 200, { templates: ['alert', 'block_or_step_up', 'require_passkey_for_role', 'always_ask_when'].map((id) => ({ id, name: id, description: '', triggers: TRIGGERS, params: {} })) }));
route('POST', '/actions/templates/([^/]+)/render', (req, res, b, m) => {
  if (!TRIGGERS.includes(b.trigger)) return send(res, 400, { code: 'invalid_request', error: 'trigger is required' });
  send(res, 200, { code: `// Made with the "${m[1]}" template.\nexports.onExecute = async (event, api) => {};\n`, secrets: m[1] === 'alert' ? ['SLACK_WEBHOOK_URL'] : [], allowedHosts: [], capabilities: [] });
});
route('GET', '/actions/secrets', (req, res) => send(res, 200, { secrets: [...state.secrets.values()].map(({ value, ...rest }) => rest).sort((x, y) => x.name.localeCompare(y.name)) }));
route('PUT', '/actions/secrets/([^/]+)', (req, res, b, m) => {
  if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(m[1])) return send(res, 400, { code: 'invalid_request', error: 'bad secret name' });
  if (typeof b.value !== 'string' || !b.value) return send(res, 400, { code: 'invalid_request', error: 'value is required' });
  const now = new Date().toISOString();
  const had = state.secrets.get(m[1]);
  state.secrets.set(m[1], { name: m[1], value: b.value, createdAt: had ? had.createdAt : now, updatedAt: now });
  const { value, ...view } = state.secrets.get(m[1]);
  send(res, had ? 200 : 201, view);
});
route('DELETE', '/actions/secrets/([^/]+)', (req, res, b, m) => (state.secrets.delete(m[1])
  ? send(res, 200, { deleted: true }) : send(res, 404, { code: 'secret_not_found', error: `No secret named ${m[1]}.` })));
route('GET', '/actions/events', (req, res) => send(res, 200, { events: [] }));
route('POST', '/actions/test', (req, res, b) => send(res, 200, {
  outcome: 'ok', error: null, durationMs: 1, cpuMs: 0.5, calls: [], notifications: [], logs: [], reasons: [], wouldBe: null,
  eventId: b.eventId || null, event: b.event || {}, assumedCapabilities: b.capabilities || [], note: 'Notifications are not sent by a test run.',
}));
route('POST', '/actions/dry-run', (req, res, b) => send(res, 200, {
  trigger: b.trigger || null, evaluated: 0, from: null, to: null, matched: 0, changed: 0, transitions: {}, notifications: {}, errors: 0, timeouts: 0,
  errorSamples: [], p50Ms: 0, p95Ms: 0, samples: [], assumedCapabilities: b.capabilities || [],
}));
route('GET', '/actions', (req, res) => send(res, 200, {
  actions: [...state.flows.values()].map((a) => ({ ...flowView(a), pendingApproval: a.versions.filter((v) => v.status === 'pending_approval').length })),
}));
route('PUT', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const slug = m[1];
  const existing = state.flows.get(slug);
  if (existing && b.trigger !== undefined && b.trigger !== existing.trigger) return send(res, 409, { code: 'trigger_mismatch', error: `${slug} runs on ${existing.trigger}` });
  const trigger = existing ? existing.trigger : b.trigger;
  if (!TRIGGERS.includes(trigger)) return send(res, 400, { code: 'invalid_request', error: 'trigger is required' });
  const code = b.code !== undefined ? b.code : (b.template ? `// template ${b.template.id}\nexports.onExecute = async () => {};\n` : undefined);
  if (typeof code !== 'string' || !code.trim()) return send(res, 400, { code: 'invalid_request', error: 'code is required' });
  if (/^\s*exports\.onExecute\s*=\s*\{\s*$/.test(code)) return send(res, 400, { code: 'action_invalid', error: 'SyntaxError' });
  const now = new Date().toISOString();
  const a = existing || { slug, name: slug, trigger, enabled: true, order: 100, onFailure: 'continue', activeVersion: null, versions: [], createdAt: now };
  const capabilities = b.capabilities || [];
  const key = JSON.stringify({ code, capabilities, allowedHosts: b.allowedHosts || [], secrets: b.secrets || [] });
  let v = a.versions[a.versions.length - 1];
  if (!v || v.key !== key) {
    v = {
      number: a.versions.length + 1, key, code, codeHash: sha256(key), capabilities, approvedCapabilities: [],
      allowedHosts: b.allowedHosts || [], secrets: b.secrets || [], template: b.template || null,
      status: capabilities.length ? 'pending_approval' : 'ready', createdAt: now, createdBy: 'api:test', approvedAt: null,
    };
    a.versions.push(v);
  }
  if (b.activate !== false && v.status === 'ready') a.activeVersion = v.number;
  for (const k of ['name', 'order', 'enabled', 'onFailure']) if (b[k] !== undefined) a[k] = b[k];
  a.updatedAt = now;
  state.flows.set(slug, a);
  send(res, existing ? 200 : 201, {
    action: flowView(a), version: versionView(a, v), deployed: a.activeVersion === v.number,
    approval: v.status === 'pending_approval' ? { required: true, capabilities: v.capabilities, message: 'Waits for an admin\'s phone approval in the dashboard.' } : null,
    warnings: [],
  });
});
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  const active = a.versions.find((v) => v.number === a.activeVersion);
  send(res, 200, { action: flowView(a), code: (active || a.versions[a.versions.length - 1] || {}).code || null, versions: [...a.versions].reverse().map((v) => versionView(a, v)) });
});
route('PATCH', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  for (const k of ['name', 'order', 'enabled', 'onFailure']) if (b[k] !== undefined) a[k] = b[k];
  send(res, 200, { action: flowView(a) });
});
route('DELETE', '/actions/([a-z0-9][a-z0-9-]{1,62})', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  state.flows.delete(a.slug);
  send(res, 200, { deleted: true });
});
route('POST', '/actions/([a-z0-9][a-z0-9-]{1,62})/rollback', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  const target = b.version !== undefined
    ? a.versions.find((v) => v.number === b.version)
    : [...a.versions].reverse().find((v) => v.status === 'ready' && v.number < (a.activeVersion || Infinity)) || a.versions.find((v) => v.number === a.activeVersion);
  if (!target) return send(res, 404, { code: 'version_not_found', error: 'No such version.' });
  if (target.status !== 'ready') return send(res, 409, { code: 'version_not_runnable', error: `Version ${target.number} is ${target.status}.` });
  a.activeVersion = target.number;
  send(res, 200, { action: flowView(a), version: versionView(a, target) });
});
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})/versions/([^/]+)', (req, res, b, m) => {
  const a = flowOf(res, m[1]);
  if (!a) return;
  const v = a.versions.find((x) => x.number === Number(m[2]));
  if (!v) return send(res, 404, { code: 'version_not_found', error: 'No such version.' });
  send(res, 200, versionView(a, v, true));
});
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})/logs', (req, res, b, m) => { if (flowOf(res, m[1])) send(res, 200, { logs: [] }); });
route('GET', '/actions/([a-z0-9][a-z0-9-]{1,62})/metrics', (req, res, b, m) => {
  if (!flowOf(res, m[1])) return;
  const window = new URL(req.url, 'http://x').searchParams.get('window') || '24h';
  send(res, 200, { window, runs: 0, errors: 0, timeouts: 0, errorRate: 0, p50Ms: 0, p95Ms: 0, decisions: {}, notifications: { sent: 0, failed: 0, skipped: 0 } });});
route('POST', '/auth/generate-secret', (req, res, b) => {
  const u = b.externalUsername;
  if (state.linked.has(u)) return send(res, 409, { error: 'already linked' });
  if (state.pending.has(u)) return send(res, 409, { error: 'Secret already generated' });
  state.pending.add(u);
  send(res, 200, { secret: 'S', qrCodeDataUrl: `data:image/png;base64,QR-${u}`, externalUsername: u, expiresAt: 'soon', ttlMs: 300000, recoveryCodes: ['r1'] });
});
route('POST', '/auth/secret/reset', (req, res, b) => {
  const u = b.externalUsername;
  state.linked.delete(u);
  state.pending.add(u);
  send(res, 200, { success: true, secret: 'S2', qrCodeDataUrl: `data:image/png;base64,QR2-${u}`, externalUsername: u, recoveryCodes: ['r2'] });
});
// A healthy phone posture, like the real API's `device` on a user with a linked phone.
const DEVICE_POSTURE = {
  platform: 'ios', model: 'iPhone15,3', osVersion: '18.1', securityPatch: null, appVersion: '1.0.0', screenLock: true,
  biometrics: 'face', jailbroken: false, compromised: false, hardwareKey: true, attestation: 'apple-appattest', signed: true,
  reportedAt: '2026-10-25T10:00:00.000Z', lastSeenAt: '2026-10-25T10:00:00.000Z', linkedAt: '2026-10-20T09:00:00.000Z',
  state: 'healthy', issues: [],
};
route('GET', '/users/([^/]+)', (req, res, b, m) => {
  const u = decodeURIComponent(m[1]);
  if (!state.linked.has(u) && !state.pending.has(u)) return send(res, 404, { error: 'not found' });
  send(res, 200, { externalUsername: u, deviceId: state.linked.has(u) ? 'dev-1' : null, used: state.linked.has(u), frozen: false, device: state.linked.has(u) ? DEVICE_POSTURE : null });
});
route('POST', '/action-types', (req, res, b) => {
  const secondThought = b.secondThought !== undefined ? b.secondThought : (state.actions.get(b.type)?.secondThought ?? null);
  state.actions.set(b.type, { critical: !!b.critical, secondThought });
  send(res, 200, { id: 'a1', type: b.type, name: b.name, description: b.description || '', critical: !!b.critical, active: true, secondThought });
});
route('GET', '/action-types', (req, res) => send(res, 200, [...state.actions.entries()].map(([type, a]) => ({ type, ...a }))));
// Like the real API: a QR that follows a push is tied to it. A request the phone REJECTED kills the QR
// (none is issued, a code is refused), and a push with number matching makes the QR show the same number.
route('POST', '/offline/challenge', (req, res, b) => {
  if (state.opts.offlineDisabled) return send(res, 403, { error: 'offline_sign_disabled', code: 'offline_sign_disabled' });
  const linked = b.requestId ? state.requests.find((x) => x.id === b.requestId) : undefined;
  if (b.requestId && !linked) return send(res, 404, { error: 'request_not_found' });
  if (linked && linked.status === 'REJECTED') return send(res, 409, { error: 'request_rejected' });
  if (linked && linked.requiresPasskey) return send(res, 403, { error: 'passkey_required', reason: 'passkey_required' });
  const id = `ch-${++state.seq}`;
  state.challenges.set(id, { user: b.externalUsername, type: b.type, used: false, requestId: linked && linked.id });
  const challengeCode = (linked && linked.challengeCode) || (b.requireNumberMatch === true ? '47' : undefined);
  send(res, 200, { challengeId: id, qr: 'TQ2.x', qrDataUrl: 'data:image/png;base64,OFFLINE', expiresAt: 'soon', expiresInSeconds: 120, totpAvailable: true, ...(challengeCode ? { challengeCode } : {}) });
});
route('POST', '/offline/verify', (req, res, b) => {
  const ch = state.challenges.get(b.challengeId);
  if (!ch) return send(res, 404, { approved: false, reason: 'unknown_challenge' });
  if (ch.used) return send(res, 410, { approved: false, reason: 'used' });
  if (ch.requestId && (state.requests.find((x) => x.id === ch.requestId) || {}).status === 'REJECTED') return send(res, 410, { approved: false, reason: 'request_rejected' });
  if (ch.requestId && (state.requests.find((x) => x.id === ch.requestId) || {}).requiresPasskey) return send(res, 403, { approved: false, reason: 'passkey_required' });
  if (b.code !== 'ABCD123') return send(res, 401, { approved: false, reason: 'invalid_code', attemptsLeft: 4 });
  ch.used = true;
  send(res, 200, { approved: true, challengeId: b.challengeId, externalUsername: ch.user, type: ch.type });
});
route('POST', '/offline/totp/verify', (req, res, b) => {
  if (b.requestId && (state.requests.find((x) => x.id === b.requestId) || {}).status === 'REJECTED') return send(res, 410, { approved: false, reason: 'request_rejected' });
  if (b.requestId && (state.requests.find((x) => x.id === b.requestId) || {}).requiresPasskey) return send(res, 403, { approved: false, reason: 'passkey_required' });
  if (b.code !== '123456') return send(res, 401, { approved: false, reason: 'invalid_code' });
  send(res, 200, { approved: true, externalUsername: b.externalUsername });
});
// Outage verifiers: every linked user's code is K7P2QXA at every step (both labels), hashed like the API.
route('POST', '/offline/totp/verifiers', (req, res, b) => {
  if (state.opts.outageVerifiersDisabled) return send(res, 403, { error: 'outage_verifiers_disabled' });
  const names = Array.isArray(b.externalUsernames) ? b.externalUsernames : [];
  if (!names.length || names.length > 1000) return send(res, 400, { error: 'externalUsernames: 1 to 1000 user names' });
  const now = Math.floor(Date.now() / 30000);
  const fromStep = Number.isInteger(b.fromStep) ? b.fromStep : now;
  const steps = Number.isInteger(b.steps) ? b.steps : 480;
  const users = names.filter((u) => state.linked.has(u)).map((u) => {
    const salt = crypto.randomBytes(16);
    const parts = [];
    for (let i = 0; i < steps; i++) {
      const h = crypto.pbkdf2Sync('K7P2QXA', Buffer.concat([salt, Buffer.from(`:${fromStep + i}`)]), 10, 4, 'sha256');
      parts.push(h, h);
    }
    return { externalUsername: u, fromStep, salt: salt.toString('base64'), digests: Buffer.concat(parts).toString('base64') };
  });
  send(res, 200, { stepSeconds: 30, fromStep, steps, notAfterStep: fromStep + steps - 1, kdf: { name: 'pbkdf2-sha256', iterations: 10, length: 4 }, users });
});
// Like the API: a user with a linked phone needs an approved PASSKEY_ENROLL first, used once.
route('POST', '/webauthn/register/options', (req, res, b) => {
  const { externalUsername: user, approvalRequestId } = b;
  if (state.linked.has(user)) {
    if (!approvalRequestId) return send(res, 403, { code: 'enrollment_approval_required', error: 'enrollment_approval_required', action: 'PASSKEY_ENROLL' });
    const r = state.requests.find((x) => x.id === approvalRequestId);
    if (!r || r.user !== user || r.type !== 'PASSKEY_ENROLL' || r.status !== 'CONFIRMED') return send(res, 403, { code: 'enrollment_approval_invalid', error: 'enrollment_approval_invalid' });
    if (state.usedEnrollApprovals.has(r.id)) return send(res, 403, { code: 'enrollment_approval_used', error: 'enrollment_approval_used' });
    state.usedEnrollApprovals.add(r.id);
  }
  send(res, 200, { challenge: 'reg-challenge', rp: { id: 'example.com', name: 'Example' }, user: { name: user } });
});
// A workspace with passkey sign-in on (TenantPolicy.passwordlessLoginEnabled).
route('GET', '/webauthn/authenticate/primary/availability', (req, res) => send(res, 200, { enabled: true, userVerification: 'preferred' }));
route('GET', '/webauthn/credentials', (req, res) => send(res, 200, { credentials: [] }));
// Like the API since 3.3.0: the user the passkey belongs to is required.
route('DELETE', '/webauthn/credentials/([^/]+)', (req, res) => (new URL(req.url, 'http://x').searchParams.get('externalUsername')
  ? send(res, 200, { deleted: true })
  : send(res, 400, { code: 'invalid_request', error: 'externalUsername is required' })));

// ── Mobile SDK (the partner's own app as the approver) ──
// The SDK's side is test control: POST /__test/mobile-enroll { enrollmentToken, platform? }
// spends a token like POST /mobile/enroll and links the user.
const mobileState = () => (state.mobile ??= { enrollments: new Map(), devices: new Map(), settings: { iosAppIds: [], androidPackages: [], androidCerts: {}, attestation: 'optional', enrollTtlSeconds: 600, push: { ios: 'webhook', android: 'webhook', apns: null, fcm: null }, updatedAt: null } });
const mobileDeviceView = (d, linked) => ({
  deviceId: d.deviceId, externalUsername: d.user, platform: d.platform, appId: d.appId || null, sdkVersion: d.sdkVersion || null, attestation: null,
  status: d.revokedAt ? 'revoked' : 'active', revokedReason: d.revokedReason || null, revokedAt: d.revokedAt || null, enrolledAt: d.enrolledAt, lastSeenAt: d.enrolledAt,
  ...(linked !== undefined && { linked }), hardwareKey: { registered: true, attestation: null, lostAt: null }, pushToken: false, posture: null,
});
const mobileActive = (user) => [...mobileState().devices.values()].find((d) => d.user === user && !d.revokedAt);
route('POST', '/mobile/enrollments', (req, res, b) => {
  const user = typeof b.externalUsername === 'string' ? b.externalUsername.trim() : '';
  if (!user) return send(res, 400, { code: 'invalid_request', error: 'externalUsername must be a string of 1 to 255 characters' });
  const ms = mobileState();
  const current = mobileActive(user);
  if ((current || state.linked.has(user)) && b.replace !== true) {
    return send(res, 409, { code: 'already_enrolled', error: 'This user already approves from a device. Send replace: true to move them to a new one.', deviceId: current?.deviceId || 'touchque-app', channel: current ? 'mobile_sdk' : 'touchque_app', ...(current && { platform: current.platform }) });
  }
  for (const [k, e] of ms.enrollments) if (e.user === user && !e.usedAt) ms.enrollments.delete(k);
  const token = `tqe_${b64u(crypto.randomBytes(32))}`;
  const e = { id: crypto.randomUUID(), user, replace: b.replace === true, expiresAt: new Date(Date.now() + (b.ttlSeconds || ms.settings.enrollTtlSeconds) * 1000).toISOString() };
  ms.enrollments.set(token, e);
  send(res, 201, { enrollmentId: e.id, enrollmentToken: token, externalUsername: user, expiresAt: e.expiresAt, replace: e.replace, ...(current && { replacesDeviceId: current.deviceId }) });
});
route('POST', '/__test/mobile-enroll', (req, res, b) => {
  const ms = mobileState();
  const e = ms.enrollments.get(b.enrollmentToken);
  if (!e) return send(res, 404, { code: 'enrollment_not_found', error: 'This enrollment token is not valid' });
  if (e.usedAt) return send(res, 409, { code: 'enrollment_used', error: 'This enrollment token was already used' });
  const old = mobileActive(e.user);
  if (old) Object.assign(old, { revokedAt: new Date().toISOString(), revokedReason: 'replaced' });
  e.usedAt = new Date().toISOString();
  const d = { deviceId: crypto.randomUUID(), user: e.user, platform: b.platform || 'ios', appId: b.appId || null, sdkVersion: '1.0.0', enrolledAt: e.usedAt };
  ms.devices.set(d.deviceId, d);
  state.linked.add(e.user);
  send(res, 201, { deviceId: d.deviceId, externalUsername: e.user });
});
route('GET', '/mobile/devices', (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const status = q.get('status') || 'active';
  const list = [...mobileState().devices.values()]
    .filter((d) => !q.get('externalUsername') || d.user === q.get('externalUsername'))
    .filter((d) => status === 'all' || (status === 'active' ? !d.revokedAt : Boolean(d.revokedAt)));
  send(res, 200, { devices: list.reverse().map((d) => mobileDeviceView(d)), nextCursor: null });
});
route('GET', '/mobile/devices/([^/]+)', (req, res, b, m) => {
  const d = mobileState().devices.get(decodeURIComponent(m[1]));
  if (!d) return send(res, 404, { code: 'device_not_found', error: 'No mobile SDK device with this id in this workspace' });
  send(res, 200, { device: mobileDeviceView(d, !d.revokedAt) });
});
route('DELETE', '/mobile/devices/([^/]+)', (req, res, b, m) => {
  const d = mobileState().devices.get(decodeURIComponent(m[1]));
  if (!d) return send(res, 404, { code: 'device_not_found', error: 'No mobile SDK device with this id in this workspace' });
  const wasLinked = !d.revokedAt;
  if (wasLinked) { Object.assign(d, { revokedAt: new Date().toISOString(), revokedReason: 'removed' }); state.linked.delete(d.user); }
  send(res, 200, { removed: true, wasLinked });
});
// A test push: which way it would go (TouchQue with your key, or the webhook).
route('POST', '/mobile/devices/([^/]+)/test-push', (req, res, b, m) => {
  const ms = mobileState();
  const d = ms.devices.get(decodeURIComponent(m[1]));
  if (!d) return send(res, 404, { code: 'device_not_found', error: 'No mobile SDK device with this id in this workspace' });
  if (d.revokedAt) return send(res, 409, { code: 'device_revoked', error: 'This device no longer approves for anyone' });
  send(res, 200, { via: ms.settings.push[d.platform] === 'touchque' ? 'touchque' : 'webhook', ok: true });
});
route('GET', '/mobile/settings', (req, res) => send(res, 200, { settings: mobileState().settings }));
route('PUT', '/mobile/settings', (req, res, b) => {
  const ms = mobileState();
  if (b.attestation !== undefined && !['off', 'optional', 'required'].includes(b.attestation)) return send(res, 400, { code: 'invalid_settings', error: 'attestation must be one of off, optional, required' });
  for (const k of ['iosAppIds', 'androidPackages', 'androidCerts', 'attestation', 'enrollTtlSeconds']) if (b[k] !== undefined) ms.settings[k] = b[k];
  // The workspace's own push keys: TouchQue sends the push for that platform (the keys are never shown back).
  if (b.apns !== undefined) {
    if (b.apns !== null && !/^[A-Z0-9]{10}$/.test(b.apns.keyId || '')) return send(res, 400, { code: 'invalid_settings', error: 'apns.keyId must be the 10-character key id' });
    ms.settings.push.apns = b.apns && { keyId: b.apns.keyId, teamId: b.apns.teamId, topic: b.apns.topic, production: b.apns.production === true };
    ms.settings.push.ios = b.apns ? 'touchque' : 'webhook';
  }
  if (b.fcm !== undefined) {
    const sa = typeof b.fcm?.serviceAccount === 'string' ? JSON.parse(b.fcm.serviceAccount) : b.fcm?.serviceAccount;
    ms.settings.push.fcm = b.fcm && { projectId: sa?.project_id, clientEmail: sa?.client_email };
    ms.settings.push.android = b.fcm ? 'touchque' : 'webhook';
  }
  ms.settings.updatedAt = new Date().toISOString();
  send(res, 200, { settings: ms.settings });
});

// ── AI agents ──
const AGENT_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';
const newAgentId = () => `agt_${[...crypto.randomBytes(20)].map((b) => AGENT_ALPHABET[b % AGENT_ALPHABET.length]).join('')}`;
const jwkThumbprint = (k) => b64u(crypto.createHash('sha256').update(JSON.stringify(k.kty === 'EC' ? { crv: k.crv, kty: k.kty, x: k.x, y: k.y } : { crv: k.crv, kty: k.kty, x: k.x })).digest());
function agentKey(jwk) {
  if (!jwk || typeof jwk !== 'object' || 'd' in jwk) return null;
  const ec = jwk.kty === 'EC' && jwk.crv === 'P-256' && typeof jwk.x === 'string' && typeof jwk.y === 'string';
  const ed = jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string';
  if (!ec && !ed) return null;
  const clean = ec ? { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, alg: 'ES256' } : { kty: 'OKP', crv: 'Ed25519', x: jwk.x, alg: 'EdDSA' };
  return { ...clean, kid: jwk.kid || jwkThumbprint(clean), addedAt: new Date().toISOString() };
}
const agentView = (a) => ({
  id: a.id, name: a.name, description: a.description || null, platform: a.platform || 'custom', owner: { email: a.ownerEmail || 'owner@example.com', userId: 'user-1' },
  status: a.status, statusReason: a.statusReason || null,
  blocked: state.killSwitch.engaged ? 'workspace_paused' : a.status === 'active' ? null : a.status,
  allowedTypes: a.allowedTypes, policy: { requestsPer10Min: 60, requestsPerUserPer10Min: 5, amountPerRequest: {}, amountPerDay: {}, background: 'non_critical', newRecipients: 'ask', recipientAllowlist: null, ...(a.policy || {}) },
  keys: a.keys.map(({ kid, kty, crv, alg, addedAt }) => ({ kid, kty, crv, alg, addedAt })),
  reviewAt: a.reviewAt, lastUsedAt: a.lastUsedAt || null, createdBy: 'key:test', createdAt: a.createdAt, updatedAt: a.updatedAt,
});
const agentOf = (res, id) => {
  const a = state.agents.get(id);
  if (!a) send(res, 404, { code: 'agent_not_found', error: 'Agent not found' });
  return a;
};
const touch = (a, data) => Object.assign(a, data, { updatedAt: new Date().toISOString() });
route('POST', '/agents', (req, res, b) => {
  const keys = (b.publicKeys || (b.publicKey ? [b.publicKey] : [])).map(agentKey);
  if (!b.name || !Array.isArray(b.allowedTypes) || !b.allowedTypes.length) return send(res, 400, { code: 'invalid_request', error: 'name and allowedTypes are required' });
  if (!keys.length || keys.some((k) => !k)) return send(res, 400, { code: 'invalid_key', error: 'publicKey must be an EC P-256 or OKP Ed25519 public JWK' });
  const unknown = b.allowedTypes.filter((t) => !state.actions.has(t));
  if (unknown.length) return send(res, 400, { code: 'unknown_type', error: `Not an active action type of this workspace: ${unknown.join(', ')}` });
  const now = new Date().toISOString();
  const a = { id: newAgentId(), name: b.name, description: b.description, platform: b.platform, ownerEmail: b.ownerEmail, allowedTypes: b.allowedTypes, keys, status: 'active', reviewAt: new Date(Date.now() + (b.reviewInDays || 90) * 86400000).toISOString(), createdAt: now, updatedAt: now };
  state.agents.set(a.id, a);
  send(res, 201, { agent: agentView(a) });
});
route('GET', '/agents', (req, res) => {
  const status = new URL(req.url, 'http://x').searchParams.get('status');
  send(res, 200, { agents: [...state.agents.values()].filter((a) => !status || a.status === status).map(agentView), killSwitch: state.killSwitch });
});
route('PUT', '/agents/kill-switch', (req, res, b) => {
  if (typeof b.engaged !== 'boolean') return send(res, 400, { code: 'invalid_request', error: 'engaged must be true or false' });
  state.killSwitch = b.engaged ? { engaged: true, since: new Date().toISOString(), by: 'key:test', reason: b.reason || null } : { engaged: false };
  send(res, 200, { killSwitch: state.killSwitch });
});
// The workspace's agent events for a SIEM: none here, the cursor handed back.
route('GET', '/agents/events', (req, res) => {
  const after = new URL(req.url, 'http://x').searchParams.get('after');
  send(res, 200, { events: [], next: after || 'cursor-0', hasMore: false });
});
// The workspace's policy: every agent's floor (kept as given).
route('GET', '/agents/workspace-policy', (req, res) => send(res, 200, { policy: state.workspacePolicy || {} }));
route('PUT', '/agents/workspace-policy', (req, res, b) => {
  state.workspacePolicy = (b && b.policy) || {};
  send(res, 200, { policy: state.workspacePolicy });
});
route('GET', '/agents/me', (req, res) => {
  const a = req.agent;
  send(res, 200, { agent: { id: a.id, name: a.name, platform: a.platform || 'custom', allowedTypes: a.allowedTypes, reviewAt: a.reviewAt, owner: { email: a.ownerEmail || 'owner@example.com' } }, workspace: { companyName: 'Fake workspace' }, scope: req.agentScope });
});
route('GET', '/agents/(?!jwks|approval-audience$)([^/]+)', (req, res, b, m) => { const a = agentOf(res, m[1]); if (a) send(res, 200, { agent: agentView(a) }); });
route('PATCH', '/agents/([^/]+)', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  if (a.status === 'revoked') return send(res, 409, { code: 'agent_revoked', error: 'A revoked agent cannot change' });
  const { name, description, ownerEmail, platform, allowedTypes, reviewInDays } = b;
  touch(a, { ...(name && { name }), ...(description !== undefined && { description }), ...(ownerEmail && { ownerEmail }), ...(platform && { platform }), ...(allowedTypes && { allowedTypes }), ...(reviewInDays && { reviewAt: new Date(Date.now() + reviewInDays * 86400000).toISOString() }) });
  send(res, 200, { agent: agentView(a) });
});
route('DELETE', '/agents/([^/]+)', (req, res, b, m) => { const a = agentOf(res, m[1]); if (a) { touch(a, { status: 'revoked', statusReason: 'revoked_by_partner' }); send(res, 200, { agent: agentView(a) }); } });
route('POST', '/agents/([^/]+)/keys', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  const k = agentKey(b.publicKey);
  if (!k) return send(res, 400, { code: 'invalid_key', error: 'publicKey must be a public JWK' });
  if (a.keys.some((x) => x.kid === k.kid)) return send(res, 409, { code: 'key_exists', error: 'kid exists' });
  if (a.keys.length >= 3) return send(res, 409, { code: 'key_limit', error: 'at most 3 keys' });
  touch(a, { keys: [...a.keys, k] });
  send(res, 201, { agent: agentView(a) });
});
route('DELETE', '/agents/([^/]+)/keys/([^/]+)', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  const kid = decodeURIComponent(m[2]);
  if (!a.keys.some((k) => k.kid === kid)) return send(res, 404, { code: 'key_not_found', error: 'No key with that kid' });
  if (a.keys.length === 1) return send(res, 409, { code: 'last_key', error: 'Add the new key before removing the last one' });
  touch(a, { keys: a.keys.filter((k) => k.kid !== kid) });
  send(res, 200, { agent: agentView(a) });
});
route('POST', '/agents/([^/]+)/suspend', (req, res, b, m) => { const a = agentOf(res, m[1]); if (a) { touch(a, { status: 'suspended', statusReason: b.reason || 'suspended_by_partner' }); send(res, 200, { agent: agentView(a) }); } });
route('PUT', '/agents/([^/]+)/policy', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  const p = b.policy || {};
  if (p.background !== undefined && !['non_critical', 'never'].includes(p.background)) return send(res, 400, { code: 'invalid_policy', error: 'background must be non_critical or never' });
  touch(a, { policy: p });
  send(res, 200, { agent: agentView(a) });
});
route('GET', '/agents/([^/]+)/blocks', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  send(res, 200, { blocks: (a.blocks || []).map((u) => ({ externalUsername: u, reason: 'not_me', approvalId: null, createdAt: new Date().toISOString() })) });
});
route('DELETE', '/agents/([^/]+)/blocks/([^/]+)', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  const user = decodeURIComponent(m[2]);
  if (!(a.blocks || []).includes(user)) return send(res, 404, { code: 'block_not_found', error: 'This person has not stopped this agent' });
  a.blocks = a.blocks.filter((u) => u !== user);
  send(res, 200, { lifted: true });
});
// The person said "this wasn't me" to an agent's request (the API blocks on the phone's answer).
route('POST', '/__test/agent-block', (req, res, b) => {
  const a = state.agents.get(b.agentId);
  if (!a) return send(res, 404, { error: 'no agent' });
  a.blocks = [...new Set([...(a.blocks || []), b.user])];
  send(res, 200, { ok: true });
});
route('POST', '/agents/([^/]+)/resume', (req, res, b, m) => {
  const a = agentOf(res, m[1]); if (!a) return;
  if (a.status === 'revoked') return send(res, 409, { code: 'agent_revoked', error: 'A revoked agent cannot change' });
  touch(a, { status: 'active', statusReason: null });
  send(res, 200, { agent: agentView(a) });
});

// The agent's own proofs, checked like the API.
function jwsDecode(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('not a compact JWS');
  const json = (p) => JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  return { header: json(parts[0]), payload: json(parts[1]), input: Buffer.from(`${parts[0]}.${parts[1]}`), sig: Buffer.from(parts[2], 'base64url') };
}
function jwsVerify(d, jwk) {
  const want = d.header.alg === 'ES256' ? 'EC' : d.header.alg === 'EdDSA' ? 'OKP' : null;
  if (!want || jwk.kty !== want) throw new Error('alg does not fit the key');
  const key = crypto.createPublicKey({ key: jwk.kty === 'EC' ? { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y } : { kty: 'OKP', crv: jwk.crv, x: jwk.x }, format: 'jwk' });
  const ok = d.header.alg === 'ES256'
    ? crypto.verify('sha256', d.input, { key, dsaEncoding: 'ieee-p1363' }, d.sig)
    : crypto.verify(null, d.input, key, d.sig);
  if (!ok) throw new Error('signature does not verify');
}
const baseOf = (req) => `http://${req.headers.host}`;
function dpopJkt(req, path, token) {
  const d = jwsDecode(req.headers.dpop);
  if (d.header.typ !== 'dpop+jwt' || !d.header.jwk || 'd' in d.header.jwk) throw new Error('DPoP: typ must be dpop+jwt with a public jwk');
  jwsVerify(d, d.header.jwk);
  const p = d.payload;
  if (p.htm !== req.method) throw new Error('DPoP: htm');
  if (String(p.htu).split(/[?#]/)[0] !== `${baseOf(req)}${path}`) throw new Error(`DPoP: htu must be ${baseOf(req)}${path}`);
  if (Math.abs(p.iat - Date.now() / 1000) > 60) throw new Error('DPoP: iat is not fresh');
  if (token && p.ath !== b64u(crypto.createHash('sha256').update(token).digest())) throw new Error('DPoP: ath');
  const jkt = jwkThumbprint(d.header.jwk);
  if (!p.jti || state.agentJtis.has(`dpop:${jkt}:${p.jti}`)) throw new Error('DPoP: jti already used');
  state.agentJtis.add(`dpop:${jkt}:${p.jti}`);
  return jkt;
}
function agentToken(req, res, b) {
  const oauth = (status, error, description, extra = {}) => send(res, status, { error, error_description: description, ...extra }, { 'Cache-Control': 'no-store' });
  if (b.grant_type !== 'client_credentials') return oauth(400, 'unsupported_grant_type', 'grant_type must be client_credentials');
  if (b.client_assertion_type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') return oauth(401, 'invalid_client', 'client_assertion_type');
  let jkt;
  try { jkt = dpopJkt(req, '/agents/token', null); } catch (e) { return oauth(400, 'invalid_dpop_proof', e.message); }
  let a;
  let kid;
  try {
    const d = jwsDecode(b.client_assertion);
    a = state.agents.get(d.payload.iss);
    if (!a || d.payload.sub !== a.id) throw new Error('iss and sub must both be the agent id');
    const key = a.keys.find((k) => k.kid === d.header.kid) || (a.keys.length === 1 && !d.header.kid ? a.keys[0] : null);
    if (!key) throw new Error('unknown kid for this agent');
    jwsVerify(d, key);
    const aud = Array.isArray(d.payload.aud) ? d.payload.aud : [d.payload.aud];
    if (!aud.includes(`${baseOf(req)}/agents/token`) && !aud.includes(baseOf(req))) throw new Error('aud');
    const now = Date.now() / 1000;
    if (!(d.payload.exp > now) || d.payload.exp - (d.payload.iat || now) > 300) throw new Error('expired or too long-lived');
    if (!d.payload.jti || state.agentJtis.has(`assert:${a.id}:${d.payload.jti}`)) throw new Error('jti already used');
    state.agentJtis.add(`assert:${a.id}:${d.payload.jti}`);
    kid = key.kid;
  } catch (e) {
    return oauth(401, 'invalid_client', `client_assertion: ${e.message}`);
  }
  const blocked = state.killSwitch.engaged ? 'workspace_paused' : a.status !== 'active' ? a.status : null;
  if (blocked) return oauth(400, 'unauthorized_client', `This agent may not act now (${blocked})`, { reason: blocked });
  const all = ['agent:read', 'approvals:request', 'approvals:read', 'vault:read'];
  const scope = b.scope ? String(b.scope).split(' ').filter(Boolean) : all;
  if (scope.some((x) => !all.includes(x))) return oauth(400, 'invalid_scope', 'unknown scope');
  const token = `tqat_${crypto.randomBytes(32).toString('base64url')}`;
  state.agentTokens.set(token, { agentId: a.id, kid, jkt, scope: scope.join(' '), exp: Date.now() + 600000 });
  a.lastUsedAt = new Date().toISOString();
  return oauth(200, undefined, undefined, { access_token: token, token_type: 'DPoP', expires_in: 600, scope: scope.join(' ') });
}
/** An agent-token call: null when it may go on (req.agent set), else the answer was sent. */
function agentAuth(req, res, path, scope) {
  const deny = (status, code, error, extra = {}) => { send(res, status, { code, error, ...extra }, { 'WWW-Authenticate': `DPoP error="${code}"` }); return false; };
  const [kind, token] = String(req.headers.authorization || '').split(' ');
  if (!/^dpop$/i.test(kind || '') || !token) return deny(401, 'invalid_token', 'An agent calls with Authorization: DPoP <token>');
  const entry = state.agentTokens.get(token);
  if (!entry || entry.exp < Date.now()) return deny(401, 'invalid_token', 'The token is unknown or expired');
  let jkt;
  try { jkt = dpopJkt(req, path, token); } catch (e) { return deny(401, 'invalid_dpop_proof', e.message); }
  if (jkt !== entry.jkt) return deny(401, 'invalid_token', 'The DPoP proof is not signed by the bound key');
  const a = state.agents.get(entry.agentId);
  if (!a.keys.some((k) => k.kid === entry.kid)) return deny(401, 'invalid_token', 'The key this token was issued to has been removed');
  const blocked = state.killSwitch.engaged ? 'workspace_paused' : a.status !== 'active' ? a.status : null;
  if (blocked) { send(res, 403, { code: 'agent_blocked', reason: blocked, error: `This agent may not act now (${blocked})` }); return false; }
  if (scope && !entry.scope.split(' ').includes(scope)) { send(res, 403, { code: 'insufficient_scope', error: `This call needs the ${scope} scope` }); return false; }
  req.agent = a;
  req.agentScope = entry.scope;
  return true;
}
const AGENT_SCOPES = { 'GET /agents/me': 'agent:read', 'POST /agents/approvals': 'approvals:request', 'POST /agents/vault/token': 'vault:read' };

// Approval tokens: the fake's own ES256 key, like the API's.
const APPROVAL_KEY = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const APPROVAL_JWK = (() => {
  const { x, y } = APPROVAL_KEY.publicKey.export({ format: 'jwk' });
  const pub = { kty: 'EC', crv: 'P-256', x, y };
  return { ...pub, kid: jwkThumbprint(pub), alg: 'ES256', use: 'sig' };
})();
function signApproval(claims) {
  const input = `${b64u(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'touchque-approval+jwt', kid: APPROVAL_JWK.kid })))}.${b64u(Buffer.from(JSON.stringify(claims)))}`;
  return `${input}.${b64u(crypto.sign('sha256', Buffer.from(input), { key: APPROVAL_KEY.privateKey, dsaEncoding: 'ieee-p1363' }))}`;
}
const WORKSPACE = 'fake-workspace';
const approvalState = (r, ap) => {
  if (ap.redeemed) return 'redeemed';
  if (r.status === 'PENDING') return 'pending';
  if (r.status === 'REJECTED') return 'rejected';
  if (r.revokedAt) return 'revoked';
  if (r.provisional && !r.reconfirmedAt) return 'provisional';
  return 'approved';
};
route('GET', '/agents/jwks.json', (req, res) => send(res, 200, { keys: [APPROVAL_JWK] }));
// The aud of this workspace's approval tokens (the SDKs' offline check requires it).
route('GET', '/agents/approval-audience', (req, res) => send(res, 200, { audience: `touchque:workspace:${WORKSPACE}` }));
// Mandates: approved with /__test/approve like any request; uses take from them at once.
const mandateView = (m) => {
  const r = state.requests.find((x) => x.id === m.requestId);
  const status = m.revoked ? 'revoked' : r.status === 'PENDING' ? 'pending' : r.status === 'REJECTED' ? 'rejected' : m.usedCount >= m.maxCount ? 'exhausted' : 'active';
  return {
    mandateId: m.id, status, externalUsername: m.user, type: m.type, maxCount: m.maxCount, usedCount: m.usedCount,
    maxTotal: m.maxTotal, used: { currency: m.maxTotal.currency, amount: m.used.toFixed(2) }, recipients: m.recipients,
    validUntil: m.validUntil, ...(status === 'pending' && { challengeCode: '47' }), revokedAt: m.revoked ? m.revoked : null,
  };
};
route('POST', '/agents/mandates', (req, res, b) => {
  const a = req.agent;
  if (!a.allowedTypes.includes(b.type)) return send(res, 403, { code: 'type_not_allowed', error: 'type not allowed' });
  if (!Number.isInteger(b.maxCount) || !b.maxTotal) return send(res, 400, { code: 'invalid_authorization_details', error: 'maxCount and maxTotal are required' });
  if (!state.linked.has(b.externalUsername)) return send(res, 404, { code: 'device_not_linked', error: 'No linked device found for this user' });
  const r = { id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user: b.externalUsername, type: b.type, details: [{ label: 'AI agent', value: a.name }], status: 'PENDING', challengeCode: '47' };
  state.requests.push(r);
  const m = {
    id: `10000000-0000-4000-8000-${String(state.seq).padStart(12, '0')}`, requestId: r.id, agentId: a.id, user: b.externalUsername, type: b.type,
    maxCount: b.maxCount, maxTotal: { currency: String(b.maxTotal.currency).toUpperCase(), amount: Number(b.maxTotal.amount).toFixed(2) }, usedCount: 0, used: 0,
    recipients: (b.recipients || []).map((x) => `iban:${String(x).replace(/\s+/g, '').toUpperCase()}`), validUntil: new Date(Date.now() + (b.validFor || 86400) * 1000).toISOString(),
  };
  (state.mandates = state.mandates || new Map()).set(m.id, m);
  send(res, 201, mandateView(m));
});
route('GET', '/agents/mandates/([0-9a-f-]{36})', (req, res, b, m) => {
  const md = state.mandates?.get(m[1]);
  if (!md || md.agentId !== req.agent.id) return send(res, 404, { code: 'mandate_not_found', error: 'Mandate not found' });
  send(res, 200, mandateView(md));
});
route('POST', '/agents/mandates/([0-9a-f-]{36})/revoke', (req, res, b, m) => {
  const md = state.mandates?.get(m[1]);
  if (!md || md.agentId !== req.agent.id) return send(res, 404, { code: 'mandate_not_found', error: 'Mandate not found' });
  md.revoked = md.revoked || new Date().toISOString();
  send(res, 200, mandateView(md));
});
route('GET', '/agents/([^/]+)/mandates', (req, res, b, m) => {
  const user = new URL(req.url, 'http://x').searchParams.get('externalUsername');
  send(res, 200, { mandates: [...(state.mandates?.values() || [])].filter((x) => x.agentId === m[1] && (!user || x.user === user)).map(mandateView) });
});
route('POST', '/agents/([^/]+)/mandates/([^/]+)/revoke', (req, res, b, m) => {
  const md = state.mandates?.get(m[2]);
  if (!md || md.agentId !== m[1]) return send(res, 404, { code: 'mandate_not_found', error: 'Mandate not found' });
  md.revoked = md.revoked || new Date().toISOString();
  send(res, 200, mandateView(md));
});
route('POST', '/agents/approvals', (req, res, b) => {
  const a = req.agent;
  if (!a.allowedTypes.includes(b.type)) return send(res, 403, { code: 'type_not_allowed', error: `This agent may not ask approvals for ${b.type}` });
  const ad = b.authorizationDetails;
  if (!Array.isArray(ad) || !ad.length || ad.some((d) => !d || typeof d.type !== 'string')) return send(res, 400, { code: 'invalid_authorization_details', error: 'authorizationDetails must list 1 to 5 entries' });
  if ((a.blocks || []).includes(b.externalUsername)) return send(res, 403, { code: 'blocked_by_person', reason: 'not_me', error: 'This person stopped this agent from asking them for approvals' });
  if (!state.linked.has(b.externalUsername)) return send(res, 404, { code: 'device_not_linked', error: 'No linked device found for this user' });
  const presence = b.presence || 'interactive';
  if (presence === 'background' && a.policy?.background === 'never') return send(res, 403, { code: 'background_not_allowed', error: 'This agent may only ask while a person is in the conversation' });
  if (b.mandateId) {
    const md = state.mandates?.get(b.mandateId);
    if (!md || md.agentId !== a.id) return send(res, 404, { code: 'mandate_not_found', error: 'No such mandate for this agent' });
    const view = mandateView(md);
    if (view.status !== 'active') return send(res, 409, { code: `mandate_${view.status}`, error: `The mandate is ${view.status}` });
    const total = ad.reduce((n, d) => n + Number((d.instructedAmount || d.amount || {}).amount || 0), 0);
    if (md.used + total > Number(md.maxTotal.amount)) return send(res, 409, { code: 'mandate_exceeded', error: 'The mandate has no room left for this request' });
    md.usedCount += 1;
    md.used += total;
    const r = { id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user: b.externalUsername, type: b.type, details: [{ label: 'AI agent', value: a.name }], status: 'CONFIRMED', consumed: false };
    state.requests.push(r);
    state.approvals.set(r.id, { agentId: a.id, authorizationDetails: ad, presence, jti: `jti-${r.id}`, redeemed: false, mandateId: md.id });
    return send(res, 201, { approvalId: r.id, status: 'approved', presence, mandate: mandateView(md), caseCode: 'K7P-2QX' });
  }
  if (presence === 'background' && state.actions.get(b.type)?.critical) return send(res, 403, { code: 'background_not_allowed', error: 'A critical action needs presence interactive' });
  const r = {
    id: `00000000-0000-4000-8000-${String(++state.seq).padStart(12, '0')}`, user: b.externalUsername, type: b.type, referenceId: b.referenceId || null,
    details: [{ label: 'AI agent', value: a.name }], status: 'PENDING', consumed: false, challengeCode: presence === 'interactive' ? '47' : undefined,
  };
  state.requests.push(r);
  state.approvals.set(r.id, { agentId: a.id, authorizationDetails: ad, presence, jti: `jti-${r.id}`, redeemed: false, jkt: [...state.agentTokens.values()].find((t) => t.agentId === a.id)?.jkt });
  send(res, 201, { approvalId: r.id, status: 'pending', presence, ...(r.challengeCode && { challengeCode: r.challengeCode }), expiresAt: new Date(Date.now() + (b.expiresIn || 300) * 1000).toISOString(), caseCode: 'K7P-2QX' });
});
route('GET', '/agents/approvals/([0-9a-f-]{36})', (req, res, b, m) => {
  const ap = state.approvals.get(m[1]);
  const r = state.requests.find((x) => x.id === m[1]);
  if (!ap || !r || ap.agentId !== req.agent.id) return send(res, 404, { code: 'approval_not_found', error: 'Approval not found' });
  const status = approvalState(r, ap);
  const now = Math.floor(Date.now() / 1000);
  send(res, 200, {
    approvalId: r.id, status, presence: ap.presence, expiresAt: new Date(Date.now() + 300000).toISOString(), caseCode: 'K7P-2QX',
    ...(status === 'pending' && r.challengeCode && { challengeCode: r.challengeCode }),
    ...(status === 'approved' && {
      tokenExpiresIn: 300,
      approvalToken: signApproval({
        iss: baseOf(req), aud: `touchque:workspace:${WORKSPACE}`, sub: r.user, act: { sub: ap.agentId, name: req.agent.name },
        authorization_details: ap.authorizationDetails, txn: r.id, type: r.type, jti: ap.jti, iat: now, exp: now + 300,
        cnf: { jkt: ap.jkt }, amr: ['hwk', 'mfa', 'user'], number_matched: Boolean(r.challengeCode), presence: ap.presence, details: r.details, cc: 'K7P-2QX',
      }),
    }),
  });
});
// The agents' token vault: tokens are kept as given, never refreshed here.
const vaultView = (c) => ({ name: c.name, provider: c.provider, clientId: c.clientId, hasClientSecret: true, options: c.options, agentIds: c.agentIds, connected: [...state.vaultTokens.keys()].filter((k) => k.startsWith(`${c.name}\n`)).length, createdAt: c.createdAt, updatedAt: c.createdAt });
const vaultAccount = (key, t) => ({ connection: key.split('\n')[0], externalUsername: key.split('\n')[1], scopes: t.scopes, canRefresh: Boolean(t.refreshToken), lastUsedAt: t.lastUsedAt || null, lastAgentId: t.lastAgentId || null, createdAt: t.createdAt, updatedAt: t.createdAt });
route('GET', '/agents/vault/connections', (req, res) => send(res, 200, { connections: [...state.vaultConnections.values()].map(vaultView) }));
route('PUT', '/agents/vault/connections/([a-z0-9-]+)', (req, res, b, m) => {
  if (!b.provider || !b.clientId) return send(res, 400, { code: 'invalid_request', error: 'provider and clientId are required' });
  const had = state.vaultConnections.get(m[1]);
  const c = { name: m[1], provider: b.provider, clientId: b.clientId, options: { ...(b.tenant && { tenant: b.tenant }), ...(b.issuer && { issuer: b.issuer }) }, agentIds: b.agentIds || had?.agentIds || [], createdAt: had?.createdAt || new Date().toISOString() };
  state.vaultConnections.set(m[1], c);
  send(res, had ? 200 : 201, { connection: vaultView(c) });
});
route('DELETE', '/agents/vault/connections/([a-z0-9-]+)', (req, res, b, m) => {
  if (!state.vaultConnections.delete(m[1])) return send(res, 404, { code: 'connection_not_found', error: 'No such connection' });
  let n = 0;
  for (const k of [...state.vaultTokens.keys()]) if (k.startsWith(`${m[1]}\n`)) { state.vaultTokens.delete(k); n += 1; }
  send(res, 200, { removed: true, tokensDeleted: n });
});
route('PUT', '/agents/vault/accounts/([a-z0-9-]+)/([^/]+)', (req, res, b, m) => {
  if (!state.vaultConnections.has(m[1])) return send(res, 404, { code: 'connection_not_found', error: 'No such connection' });
  if (!b.accessToken) return send(res, 400, { code: 'invalid_request', error: 'accessToken is required' });
  const key = `${m[1]}\n${decodeURIComponent(m[2])}`;
  const t = { accessToken: b.accessToken, refreshToken: b.refreshToken || null, expiresIn: b.expiresIn || null, scopes: b.scope ? String(b.scope).split(' ') : [], createdAt: new Date().toISOString() };
  state.vaultTokens.set(key, t);
  send(res, 200, { account: vaultAccount(key, t) });
});
route('GET', '/agents/vault/accounts', (req, res) => {
  const who = new URL(req.url, 'http://x').searchParams.get('externalUsername');
  send(res, 200, { accounts: [...state.vaultTokens.entries()].filter(([k]) => k.endsWith(`\n${who}`)).map(([k, t]) => vaultAccount(k, t)) });
});
route('DELETE', '/agents/vault/accounts/([a-z0-9-]+)/([^/]+)', (req, res, b, m) => {
  if (!state.vaultTokens.delete(`${m[1]}\n${decodeURIComponent(m[2])}`)) return send(res, 404, { code: 'account_not_found', error: 'No tokens kept' });
  send(res, 200, { removed: true });
});
route('POST', '/agents/vault/token', (req, res, b) => {
  const c = state.vaultConnections.get(b.connection);
  if (!c) return send(res, 404, { code: 'connection_not_found', error: 'No such connection' });
  if (!c.agentIds.includes(req.agent.id)) return send(res, 403, { code: 'connection_not_allowed', error: 'This agent may not use that connection' });
  const t = state.vaultTokens.get(`${b.connection}\n${b.externalUsername}`);
  if (!t) return send(res, 404, { code: 'not_connected', error: 'No tokens kept for that person on that connection' });
  Object.assign(t, { lastUsedAt: new Date().toISOString(), lastAgentId: req.agent.id });
  send(res, 200, { access_token: t.accessToken, token_type: 'Bearer', ...(t.expiresIn && { expires_in: t.expiresIn }), scope: b.scope || t.scopes.join(' '), connection: c.name });
});
route('POST', '/agents/approvals/redeem', (req, res, b) => {
  let claims;
  try {
    const d = jwsDecode(b.token);
    if (d.header.typ !== 'touchque-approval+jwt' || d.header.kid !== APPROVAL_JWK.kid) throw new Error('not an approval token');
    jwsVerify(d, APPROVAL_JWK);
    claims = d.payload;
  } catch (e) {
    return send(res, 401, { code: 'invalid_token', error: e.message });
  }
  if (claims.exp * 1000 <= Date.now()) return send(res, 401, { code: 'token_expired', error: 'expired' });
  const ap = state.approvals.get(claims.txn);
  if (!ap || ap.jti !== claims.jti) return send(res, 401, { code: 'invalid_token', error: 'Unknown approval' });
  if (ap.redeemed) return send(res, 409, { code: 'already_redeemed', error: 'This approval was already used' });
  ap.redeemed = true;
  const r = state.requests.find((x) => x.id === claims.txn);
  r.consumed = true;
  send(res, 200, { approval: {
    id: r.id, externalUsername: r.user, type: r.type, agent: { id: ap.agentId, name: claims.act.name }, authorizationDetails: ap.authorizationDetails,
    details: r.details, presence: ap.presence, numberMatched: Boolean(r.challengeCode), decidedAt: new Date().toISOString(), approvalProof: null, caseCode: 'K7P-2QX',
  } });
});

// ── TouchQue Login Management API (/identity): signed like every partner call;
// answers only what the SDKs read back. Tests look at GET /__test/calls.
function identityEcho(req, res, b, m) {
  const path = m[0];
  if (req.method === 'GET' && /^\/identity\/users-(imports|exports)\/[^/]+$/.test(path)) return send(res, 200, { id: path.split('/').pop(), status: 'done', summary: {} });
  const list = { '/identity/roles': 'roles', '/identity/organizations': 'organizations', '/identity/clients': 'clients', '/identity/apis': 'apis', '/identity/connections': 'connections' }[path];
  if (req.method === 'GET' && list) return send(res, 200, { [list]: [] });
  return send(res, 200, { ok: true });
}
// TouchQue SSO's token endpoint for an organization's AI agents: its key or its
// platform's token, a DPoP proof, one app per token.
// The "platform" is this fake: /__test/workload-token signs RS256 tokens as ${base}/__test/issuer.
const workloadKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
route('POST', '/__test/org-agent', (req, res, b) => {
  state.orgAgents.set(b.agentId, { id: b.agentId, keys: b.publicKey ? [b.publicKey] : [], workload: b.workload || null, audiences: b.audiences || [], scopes: b.scopes || [], delegation: b.delegation || [], sharedAccounts: b.sharedAccounts || [], status: b.status || 'active' });
  send(res, 200, { ok: true });
});
route('POST', '/__test/workload-token', (req, res, b) => {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'w1', typ: 'JWT' })));
  const body = b64u(Buffer.from(JSON.stringify({ iss: `${baseOf(req)}/__test/issuer`, sub: b.sub, aud: b.aud, iat: now, exp: now + 300, jti: crypto.randomUUID() })));
  const sig = crypto.sign('sha256', Buffer.from(`${head}.${body}`), workloadKey.privateKey);
  send(res, 200, { token: `${head}.${body}.${b64u(sig)}` });
});
// The agent behind a request at /sso/token or /sso/bc-authorize: { a, via } or throws.
function orgAgentAuth(req, b) {
  const a = state.orgAgents.get(b.client_id);
  if (!a) throw new Error('Unknown agent');
  let via;
  const d = jwsDecode(b.client_assertion);
  if (d.payload.iss === a.id) {
    const key = a.keys.find((k) => !d.header.kid || k.kid === d.header.kid);
    if (!key || d.payload.sub !== a.id) throw new Error('unknown key');
    jwsVerify(d, key);
    const aud = Array.isArray(d.payload.aud) ? d.payload.aud : [d.payload.aud];
    if (!aud.includes(`${baseOf(req)}/sso/token`) && !aud.includes(baseOf(req))) throw new Error('aud');
    via = 'key';
  } else {
    if (!a.workload || d.payload.iss !== `${baseOf(req)}/__test/issuer`) throw new Error('no trust policy names this issuer');
    if (d.header.alg !== 'RS256' || !crypto.verify('sha256', d.input, workloadKey.publicKey, d.sig)) throw new Error('bad signature');
    if (d.payload.aud !== a.workload.audience || d.payload.sub !== a.workload.subject) throw new Error('does not match the trust policy');
    via = 'workload';
  }
  if (!(d.payload.exp > Date.now() / 1000) || !d.payload.jti || state.agentJtis.has(`org:${d.payload.jti}`)) throw new Error('expired or used');
  state.agentJtis.add(`org:${d.payload.jti}`);
  return { a, via };
}
function orgTarget(a, b) {
  const aud = b.resource || (a.audiences.length === 1 ? a.audiences[0] : null);
  if (!aud || !a.audiences.includes(aud)) return { error: ['invalid_target', 'This agent may not get tokens for that app'] };
  const scope = b.scope ? String(b.scope).split(' ').filter(Boolean) : a.scopes;
  if (scope.some((x) => !a.scopes.includes(x))) return { error: ['invalid_scope', 'scope'] };
  return { aud, scope };
}
route('POST', '/sso/token', (req, res, b) => {
  const oauth = (status, error, description, extra = {}) => send(res, status, { error, error_description: description, ...extra }, { 'Cache-Control': 'no-store' });
  const grants = ['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange', 'urn:openid:params:grant-type:ciba'];
  if (!grants.includes(b.grant_type)) return oauth(400, 'unsupported_grant_type', 'An agent uses client_credentials, token exchange or CIBA');
  let a;
  let via;
  try { ({ a, via } = orgAgentAuth(req, b)); } catch (e) { return oauth(401, 'invalid_client', `client_assertion: ${e.message}`); }
  let jkt;
  try { jkt = dpopJkt(req, '/sso/token', null); } catch (e) { return oauth(400, 'invalid_dpop_proof', e.message); }
  if (a.status !== 'active') return oauth(400, 'unauthorized_client', `This agent may not get tokens now (${a.status})`);
  const mint = (fields) => {
    const token = `fakeoat_${crypto.randomBytes(24).toString('base64url')}`;
    state.orgAgentTokens.set(token, { agentId: a.id, jkt, via, ...fields });
    return token;
  };
  if (b.grant_type === 'urn:openid:params:grant-type:ciba') {
    const r = state.cibaRequests.get(b.auth_req_id);
    if (!r || r.agentId !== a.id || r.state === 'issued') return oauth(400, 'invalid_grant', 'Unknown or used auth_req_id');
    if (r.state === 'pending') return oauth(400, 'authorization_pending', 'The member has not answered yet');
    if (r.state === 'denied') return oauth(400, 'access_denied', 'The member did not approve');
    r.state = 'issued';
    const token = mint({ aud: r.aud, sub: r.user, act: a.id });
    return oauth(200, undefined, undefined, { access_token: token, token_type: 'DPoP', expires_in: 300, scope: r.scope.join(' '), ...(r.details && { authorization_details: r.details }) });
  }
  // The token vault: a member's own token at another service (connection 'google' is connected for every member here).
  if (b.grant_type === 'urn:ietf:params:oauth:grant-type:token-exchange' && b.requested_token_type === 'urn:touchque:params:oauth:token-type:connection-access-token') {
    if (!a.delegation.includes('token_exchange')) return oauth(400, 'unauthorized_client', 'This agent may not act for members with their token');
    if (!String(b.subject_token || '').startsWith('member:')) return oauth(400, 'invalid_grant', 'subject_token');
    if (b.connection !== 'google') return oauth(400, 'invalid_grant', 'The member has not connected that account (federated_connection_refresh_token_not_found)');
    return oauth(200, undefined, undefined, { access_token: `ya29.${String(b.subject_token).slice('member:'.length)}`, issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', token_type: 'Bearer', expires_in: 3599, scope: b.scope || 'openid email', connection: 'google' });
  }
  const t = orgTarget(a, b);
  if (t.error) return oauth(400, ...t.error);
  if (b.grant_type === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    if (!a.delegation.includes('token_exchange')) return oauth(400, 'unauthorized_client', 'This agent may not act for members with their token');
    if (b.subject_token_type !== 'urn:ietf:params:oauth:token-type:access_token' || !String(b.subject_token || '').startsWith('member:')) return oauth(400, 'invalid_grant', 'subject_token');
    const token = mint({ aud: t.aud, sub: String(b.subject_token).slice('member:'.length), act: a.id });
    return oauth(200, undefined, undefined, { access_token: token, issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', token_type: 'DPoP', expires_in: 300, scope: t.scope.join(' ') });
  }
  const token = mint({ aud: t.aud });
  return oauth(200, undefined, undefined, { access_token: token, token_type: 'DPoP', expires_in: 300, scope: t.scope.join(' ') });
});
// CIBA: the agent asks a member; /__test/ciba-answer stands for the member's phone.
route('POST', '/sso/bc-authorize', (req, res, b) => {
  const oauth = (status, error, description) => send(res, status, { error, error_description: description }, { 'Cache-Control': 'no-store' });
  let a;
  try { ({ a } = orgAgentAuth(req, b)); } catch (e) { return oauth(401, 'invalid_client', `client_assertion: ${e.message}`); }
  if (!a.delegation.includes('ciba')) return oauth(400, 'unauthorized_client', 'This agent may not ask members for approval');
  if (!b.login_hint) return oauth(400, 'invalid_request', 'login_hint is required');
  const t = orgTarget(a, b);
  if (t.error) return oauth(400, ...t.error);
  let details = null;
  try { details = b.authorization_details ? JSON.parse(b.authorization_details) : null; } catch { return oauth(400, 'invalid_authorization_details', 'not JSON'); }
  const id = crypto.randomBytes(16).toString('base64url');
  state.cibaRequests.set(id, { agentId: a.id, user: b.login_hint, aud: t.aud, scope: t.scope, details, bindingMessage: b.binding_message || null, state: 'pending' });
  send(res, 200, { auth_req_id: id, expires_in: 60, interval: 1, binding_code: '42' });
});
// An agent asks a member's extension to open a shared account; /__test/shared-ask-answer stands for the member and their phone.
route('POST', '/sso/agents/shared-accounts/asks', (req, res, b) => {
  const oauth = (status, error, description) => send(res, status, { error, error_description: description }, { 'Cache-Control': 'no-store' });
  let a;
  try { ({ a } = orgAgentAuth(req, b)); } catch (e) { return oauth(401, 'invalid_client', `client_assertion: ${e.message}`); }
  if (!a.sharedAccounts.length) return oauth(400, 'unauthorized_client', 'This agent may not ask to open shared accounts');
  if (!a.sharedAccounts.includes(b.account)) return oauth(400, 'invalid_target', 'This agent may not ask for that shared account');
  if (!b.login_hint) return oauth(400, 'invalid_request', 'login_hint must name a member who may open this shared account');
  const id = crypto.randomBytes(18).toString('base64url');
  state.sharedAsks.set(id, { agentId: a.id, account: b.account, user: b.login_hint, message: b.binding_message || null, status: 'waiting_member' });
  send(res, 200, { ask_id: id, status: 'waiting_member', open_url: `${baseOf(req)}/agent-ask?ask=${id}`, expires_in: 600 });
});
route('POST', '/sso/agents/shared-accounts/asks/([A-Za-z0-9_-]+)', (req, res, b, m) => {
  let a;
  try { ({ a } = orgAgentAuth(req, b)); } catch (e) { return send(res, 401, { error: 'invalid_client', error_description: e.message }); }
  const ask = state.sharedAsks.get(m[1]);
  if (!ask || ask.agentId !== a.id) return send(res, 200, { status: 'expired' });
  send(res, 200, { status: ask.status, ...(ask.reason && { reason: ask.reason }) });
});
route('POST', '/__test/shared-ask-answer', (req, res, b) => {
  const ask = state.sharedAsks.get(b.askId);
  if (!ask) return send(res, 404, { error: 'no ask' });
  Object.assign(ask, { status: b.status, ...(b.reason && { reason: b.reason }) });
  send(res, 200, { ok: true, message: ask.message });
});
route('POST', '/__test/ciba-answer', (req, res, b) => {
  const r = state.cibaRequests.get(b.authReqId);
  if (!r) return send(res, 404, { error: 'no request' });
  r.state = b.approve ? 'approved' : 'denied';
  send(res, 200, { ok: true, bindingMessage: r.bindingMessage, details: r.details });
});
// An app the agent calls with its token: the DPoP proof must be for this request and the token's key.
route('GET', '/__test/resource', (req, res) => {
  const [kind, token] = String(req.headers.authorization || '').split(' ');
  const entry = /^dpop$/i.test(kind || '') && state.orgAgentTokens.get(token);
  if (!entry) return send(res, 401, { error: 'invalid_token' });
  let jkt;
  try { jkt = dpopJkt(req, '/__test/resource', token); } catch (e) { return send(res, 401, { error: 'invalid_dpop_proof', error_description: e.message }); }
  if (jkt !== entry.jkt) return send(res, 401, { error: 'invalid_token', error_description: 'not the bound key' });
  send(res, 200, { ok: true, sub: entry.sub || entry.agentId, aud: entry.aud, via: entry.via, ...(entry.act && { act: entry.act }) });
});

// An MCP authorization server for the SDKs' McpAuth tests (TouchQue SSO's issuer <sso>/mcp):
// RFC 8414 metadata at /.well-known/oauth-authorization-server/mcp-as, its JWKS, and
// /__test/mcp-token signing an at+jwt with { sub, aud, scope, jkt?, expiresIn?, iss? }.
const mcpKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
route('GET', '/.well-known/oauth-authorization-server/mcp-as', (req, res) => {
  send(res, 200, { issuer: `${baseOf(req)}/mcp-as`, jwks_uri: `${baseOf(req)}/__test/mcp-jwks`, token_endpoint: `${baseOf(req)}/__test/none` });
});
route('GET', '/__test/mcp-jwks', (req, res) => {
  send(res, 200, { keys: [{ ...mcpKey.publicKey.export({ format: 'jwk' }), kid: 'mcp-1', alg: 'RS256', use: 'sig' }] });
});
route('POST', '/__test/mcp-token', (req, res, b) => {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'mcp-1', typ: b.typ || 'at+jwt' })));
  const body = b64u(Buffer.from(JSON.stringify({
    iss: b.iss || `${baseOf(req)}/mcp-as`, sub: b.sub || 'user-1', aud: b.aud, client_id: 'https://tool.example/client.json', scope: b.scope || '',
    iat: now, exp: now + (b.expiresIn ?? 600), jti: crypto.randomUUID(), org_id: 'org-1', email: 'ada@acme.com', type: 'mcp', ...(b.jkt && { cnf: { jkt: b.jkt } }),
  })));
  const sig = crypto.sign('sha256', Buffer.from(`${head}.${body}`), mcpKey.privateKey);
  send(res, 200, { token: `${head}.${body}.${b64u(sig)}` });
});

// Cross App Access (ID-JAG) for the SDKs' tests: an identity provider at <base>/idp (discovery, its
// JWKS is the MCP issuer's), POST /idp/token trading subject_token idtoken:<sub> for an ID-JAG
// (client tqapp_test / tqs_test, Basic or form), POST /__test/id-jag minting one with any claims, and
// a resource authorization server at POST /rs/token taking it (jwt-bearer) for an access token.
const signIdJag = (req, claims, typ = 'oauth-id-jag+jwt') => {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'mcp-1', typ })));
  const body = b64u(Buffer.from(JSON.stringify({ iss: `${baseOf(req)}/idp`, sub: 'user-1', jti: crypto.randomUUID(), iat: now, exp: now + 300, ...claims })));
  return `${head}.${body}.${b64u(crypto.sign('sha256', Buffer.from(`${head}.${body}`), mcpKey.privateKey))}`;
};
const xaaClient = (req, b) => {
  const basic = /^Basic\s+(.+)$/i.exec(String(req.headers.authorization || ''));
  const [id, secret] = basic ? Buffer.from(basic[1], 'base64').toString('utf8').split(':').map(decodeURIComponent) : [b.client_id, b.client_secret];
  return id === 'tqapp_test' && secret === 'tqs_test' ? id : null;
};
route('GET', '/idp/.well-known/openid-configuration', (req, res) => {
  send(res, 200, { issuer: `${baseOf(req)}/idp`, jwks_uri: `${baseOf(req)}/__test/mcp-jwks`, token_endpoint: `${baseOf(req)}/idp/token`, identity_chaining_requested_token_types_supported: ['urn:ietf:params:oauth:token-type:id-jag'] });
});
route('POST', '/idp/token', (req, res, b) => {
  if (!xaaClient(req, b)) return send(res, 401, { error: 'invalid_client', error_description: 'Invalid client_secret' });
  if (b.grant_type !== 'urn:ietf:params:oauth:grant-type:token-exchange' || b.requested_token_type !== 'urn:ietf:params:oauth:token-type:id-jag') return send(res, 400, { error: 'unsupported_grant_type' });
  if (b.subject_token_type !== 'urn:ietf:params:oauth:token-type:id_token' || !String(b.subject_token || '').startsWith('idtoken:')) return send(res, 400, { error: 'invalid_grant', error_description: 'subject_token' });
  if (b.audience !== 'https://rs.example') return send(res, 400, { error: 'invalid_target', error_description: 'Your organization has not linked this app to that resource' });
  const scope = b.scope || 'files:read';
  const assertion = signIdJag(req, { sub: String(b.subject_token).slice('idtoken:'.length), aud: b.audience, client_id: 'acme-at-rs', scope, ...(b.resource && { resource: b.resource }) });
  send(res, 200, { access_token: assertion, issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag', token_type: 'N_A', expires_in: 300, scope });
});
route('POST', '/__test/id-jag', (req, res, b) => send(res, 200, { assertion: signIdJag(req, { aud: 'https://rs.example', client_id: 'acme-at-rs', scope: 'files:read', ...b.claims }, b.typ) }));
route('POST', '/rs/token', (req, res, b) => {
  if (b.grant_type !== 'urn:ietf:params:oauth:grant-type:jwt-bearer' || !b.assertion) return send(res, 400, { error: 'unsupported_grant_type' });
  if (b.client_id !== 'acme-at-rs' && !/^Basic /i.test(String(req.headers.authorization || ''))) return send(res, 401, { error: 'invalid_client' });
  send(res, 200, { access_token: `rs_${crypto.randomBytes(8).toString('hex')}`, token_type: 'Bearer', expires_in: 3600, scope: 'files:read' });
});

// An A2A agent card (A2A 1.0 §8.4): JWS over the card in RFC 8785 canonical form without
// `signatures`, protected header { alg ES256, typ JOSE, kid, jku }, the key at /__test/a2a-jwks.
// ?tamper=1 changes the card after signing; ?jku=<url> points the header elsewhere.
const a2aKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jcs = (v) => (v === null || typeof v !== 'object' ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(jcs).join(',')}]`
    : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`);
route('GET', '/__test/a2a-jwks', (req, res) => send(res, 200, { keys: [{ ...a2aKey.publicKey.export({ format: 'jwk' }), kid: 'a2a-1', alg: 'ES256', use: 'sig' }] }));
route('GET', '/.well-known/agent-card.json', (req, res) => {
  const q = new URL(req.url, 'http://x').searchParams;
  const card = {
    protocolVersion: '1.0', name: 'Invoice agent', description: 'Pays approved invoices — “ödendi” ✓', url: `${baseOf(req)}/a2a`, version: '2.1.0',
    capabilities: { streaming: true }, defaultInputModes: ['text/plain'], defaultOutputModes: ['application/json'],
    skills: [{ id: 'pay', name: 'Pay an invoice', description: 'Pays one invoice', tags: ['finance', 'ä', '😀'] }], limits: { perDay: 25, ratio: 0.5 },
  };
  const protectedHeader = b64u(Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JOSE', kid: 'a2a-1', jku: q.get('jku') || `${baseOf(req)}/__test/a2a-jwks` })));
  const sig = crypto.sign('sha256', Buffer.from(`${protectedHeader}.${b64u(Buffer.from(jcs(card), 'utf8'))}`), { key: a2aKey.privateKey, dsaEncoding: 'ieee-p1363' });
  send(res, 200, { ...card, ...(q.get('tamper') && { name: 'Invoice agent (evil)' }), signatures: [{ protected: protectedHeader, signature: b64u(sig) }] });
});

route('GET', '/identity/.+', identityEcho);
route('POST', '/identity/.+', identityEcho);
route('PUT', '/identity/.+', identityEcho);
route('PATCH', '/identity/.+', identityEcho);
route('DELETE', '/identity/.+', identityEcho);

const server = http.createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => { raw += c; });
  req.on('end', () => {
    const [path] = req.url.split('?');
    const r = routes.find((x) => x.method === req.method && x.re.test(path)) || (path === '/agents/token' ? { fn: null } : null);
    if (!r) return send(res, 404, { error: 'no route' });
    let body = {};
    const form = String(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded');
    try { body = !raw ? {} : form ? Object.fromEntries(new URLSearchParams(raw)) : JSON.parse(raw); } catch { return send(res, 400, { error: 'bad json' }); }
    const ssoPath = path === '/sso/token' || path === '/sso/bc-authorize' || path.startsWith('/sso/agents/') || path.startsWith('/.well-known/oauth-authorization-server/')
      || path.startsWith('/idp/') || path === '/rs/token' || path === '/.well-known/agent-card.json';
    const agentCall = !path.startsWith('/__test/') && !ssoPath && (path === '/agents/token' || /^dpop /i.test(String(req.headers.authorization || '')));
    if (agentCall) {
      state.calls.push({ method: req.method, path, url: req.url, body, agent: true });
      if (path === '/agents/token') return req.method === 'POST' ? agentToken(req, res, body) : send(res, 404, { error: 'no route' });
      const scope = AGENT_SCOPES[`${req.method} ${path}`] || (req.method === 'GET' && path.startsWith('/agents/approvals/') ? 'approvals:read' : undefined);
      if (!agentAuth(req, res, path, scope)) return undefined;
    } else if (path === '/agents/jwks.json') {
      state.calls.push({ method: req.method, path, url: req.url, body });
    } else if (!path.startsWith('/__test/') && !ssoPath) {
      const bad = verifySignature(req, raw);
      if (bad) return send(res, 401, { code: bad, error: bad });
      state.calls.push({ method: req.method, path, url: req.url, body });
      // The feature gate (opts { featureRefused, feature }): every signed call answers it, as the API does.
      if (state.opts.featureRefused) {
        return send(res, 403, { error: state.opts.featureRefused, feature: state.opts.feature || 'device_risk', message: FEATURE_MESSAGES[state.opts.featureRefused] || 'Refused.' });
      }
    }
    try { r.fn(req, res, body, path.match(r.re)); } catch (e) { send(res, 500, { error: String(e) }); }
  });
});
server.listen(Number(process.env.PORT || 0), '127.0.0.1', () => {
  process.stdout.write(`${JSON.stringify({ port: server.address().port })}\n`);
});
process.on('SIGTERM', () => server.close(() => process.exit(0)));
