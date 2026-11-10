# frozen_string_literal: true

require "test_helper"

# Silent sign-ins, Never Locked Out, help desk, Mobile SDK, the Management API, an
# organization's agent and McpAuth against the fake API.
class ResourcesTest < FakeApiTest
  USER = "jane@acme.com"
  SILENT = %w[known_browser recent_approval same_phone familiar_network no_risk_signal].freeze
  APP = "tqapp_paymentsapi0000000000"
  RESOURCE = "https://mcp.acme.example/mcp"

  def setup
    super
    api.link(USER)
    vectors = TestSupport.fixture("silent-sign-in-vectors.json")["browserProof"]
    @proof = vectors["cases"].find { |c| c["name"] == "validHeaderEncoding" }["proof"]
    @thumbprint = vectors["thumbprint"]["expected"]
  end

  def login_requests
    api.calls.select { |c| c["path"] == "/login/request" }.map { |c| c["body"] }
  end

  def guard(proof, silent, action: "LOGIN", token: nil, client: tq)
    TouchQue::Guard.run(client, USER, action, ip: "203.0.113.7", user_agent: "UA", token: token, browser_proof: proof, silent_sign_in: silent)
  end

  def test_risk_check_and_known_browsers
    none = tq.risk.check(USER)
    assert_equal [true, "normal", "enforce", "CHK-2QX", ["no_browser_key"]], [none["prompt"], none["assurance"], none["silentMode"], none["caseCode"], none["reasons"].map { |r| r["code"] }]
    res = tq.risk.check(USER, type: "LOGIN", client_ip: "203.0.113.7", user_agent: "UA", browser_proof: @proof, max_age_seconds: 3600)
    assert_equal [{ "code" => "new_browser", "text" => "This browser has not been approved on the phone for this account" }], res["reasons"]
    assert_equal({ "externalUsername" => USER, "type" => "LOGIN", "clientIp" => "203.0.113.7", "userAgent" => "UA", "browserProof" => @proof, "maxAgeSeconds" => 3600 }, api.last_check)
    assert_raises(TouchQue::ConfigError) { tq.risk.check(USER, max_age_seconds: -1) }
    first = tq.login.request(USER, browser_proof: @proof)
    assert_equal({ "browsers" => [] }, tq.risk.browsers(USER))
    api.approve(first["requestId"])
    browser = tq.risk.browsers(USER)["browsers"].first
    assert_equal [@thumbprint, "push", nil], [browser["thumbprint"], browser["lastMfaMethod"], browser["lastSilentAt"]]
    assert_equal({ "forgotten" => 0 }, tq.risk.forget_browsers(USER, thumbprint: "other"))
    assert_equal({ "forgotten" => 1 }, tq.risk.forget_browsers(USER, thumbprint: @thumbprint))
  end

  def test_silent_sign_in_through_the_guard
    api.opts(silent: true)
    res = guard(@proof, true)
    a = res[:approved]
    assert_equal [200, "silent", "SILENT", "silent"], [res[:status], a["requestId"], a["confirmedVia"], a["assurance"]["method"]]
    assert_equal SILENT, a["reasons"].map { |r| r["code"] }
    assert_equal ["/risk/check"], paths
    critical = guard(@proof, true, action: "SEND_MONEY")
    assert_equal %w[waiting 47], [critical[:body]["touchque"]["state"], critical[:body]["touchque"]["number"]]

    api.reset
    api.link(USER)
    first = guard(@proof, true)
    assert_equal ["/risk/check", "/login/request"], paths
    api.opts(silent: true)
    assert_equal "waiting", guard(@proof, true, token: first[:body]["token"])[:body]["touchque"]["state"]
    assert_equal 1, paths.count("/risk/check")
    api.approve
    done = guard(@proof, true, token: first[:body]["token"])
    assert_equal %w[DEVICE push], [done[:approved]["confirmedVia"], done[:approved]["assurance"]["method"]]

    api.reset
    api.link(USER)
    api.opts(silent: true)
    assert_equal 202, guard(@proof, false)[:status]
    assert_equal @proof, login_requests[0]["browserProof"]
    assert_equal 202, guard("x" * 5000, true)[:status]
    assert_nil login_requests[1]["browserProof"]
    refute_includes paths, "/risk/check"
    guard(@proof, { max_age_seconds: 0 })
    assert_equal 0, api.last_check["maxAgeSeconds"]
    assert_raises(ArgumentError) { TouchQue::Guard.assert_silent_sign_in!({ max_age_seconds: -1 }, "x") }
    assert_raises(ArgumentError) { TouchQue::Guard.assert_silent_sign_in!("yes", "x") }
  end

  def test_never_locked_out
    %w[ada@acme.com bo@acme.com cy@acme.com].each { |u| api.link(u) }
    out = tq.recovery.set_vouchers("ada@acme.com", %w[bo@acme.com zed@acme.com])
    assert_equal [{ "externalUsername" => "bo@acme.com", "eligible" => true }, { "externalUsername" => "zed@acme.com", "eligible" => false, "reason" => "no_phone" }], out["vouchers"]
    e = assert_raises(TouchQue::APIError) { tq.recovery.start("cy@acme.com") }
    assert_equal [409, "not_enough_vouchers"], [e.status, e.code]
    tq.recovery.set_vouchers("ada@acme.com", %w[bo@acme.com cy@acme.com])
    r = tq.recovery.start("ada@acme.com", client_ip: "203.0.113.7", display_name: "Ada", cool_off_minutes: 90)
    assert_equal "AWAITING_DEVICE", r["status"]
    assert r["bindUri"].start_with?("touchque://recover?id=")
    assert_equal({ "externalUsername" => "ada@acme.com", "clientIp" => "203.0.113.7", "displayName" => "Ada", "coolOffMinutes" => 90 }, api.last_call["body"])
    api.recovery("VOUCHING")
    now = tq.recovery.status(r["recoveryId"])
    assert_equal %w[11 12], now["vouchers"].map { |v| v["code"] }
    assert TouchQue::Resources::Recovery.open?(now)
    assert_equal [r["recoveryId"]], tq.recovery.list(open: true).map { |x| x["recoveryId"] }
    vetoed = tq.recovery.veto(r["recoveryId"], by: "admin@acme.com")
    assert_equal %w[VETOED admin@acme.com], [vetoed["status"], vetoed["endedBy"]]
    assert_empty tq.recovery.list(open: true)
    api.reset
    assert_raises(TouchQue::ConfigError) { tq.recovery.start("") }
    assert_raises(TouchQue::ConfigError) { tq.recovery.start("a@b.com", required: "3") }
    assert_raises(TouchQue::ConfigError) { tq.recovery.list }
    assert_empty api.calls
  end

  def test_help_desk
    api.link("ayse@acme.com")
    s = tq.assist.open("ayse@acme.com", agent: { name: "Deniz Kaya", title: "IT help desk" }, reason: "Ticket 4411")
    assert_equal ["OPEN", true, true], [s["status"], s["notified"], s["phone"]]
    check = tq.assist.verify(s["id"], "reset_2fa", action_text: "reset your two-step verification")
    assert_match(/\A\d{2}\z/, check["challengeCode"])
    api.post("/__test/assist", { requestId: check["requestId"], action: "approve" })
    assert TouchQue::Resources::Assist.check_passed?(tq.assist.get(s["id"]), check["requestId"])
    assert_equal 428, assert_raises(TouchQue::APIError) { tq.assist.spend(s["id"], check["requestId"], "reset_password") }.status
    refute TouchQue::Resources::Assist.check_passed?(tq.assist.spend(s["id"], check["requestId"], "reset_2fa"), check["requestId"])
    assert_equal s["id"], tq.assist.list(external_username: "ayse@acme.com")[0]["id"]
    not_me = tq.assist.verify(s["id"], "activation_link")
    api.post("/__test/assist", { requestId: not_me["requestId"], action: "not_me" })
    assert tq.assist.get(s["id"])["frozen"]
    unlock = tq.assist.verify(s["id"], "unlock")
    api.post("/__test/assist", { requestId: unlock["requestId"], action: "approve" })
    out = tq.assist.unfreeze(s["id"], unlock["requestId"])
    assert_equal [true, false], [out["unfrozen"], out["session"]["frozen"]]
    assert_equal "ENDED", tq.assist.end(s["id"])["status"]
    assert_equal "assist_not_open", assert_raises(TouchQue::APIError) { tq.assist.verify(s["id"], "unlock") }.code
    tq.auth.generate_secret("can@acme.com")
    no_phone = tq.assist.open("can@acme.com", agent: { name: "Deniz Kaya" }, notify: false)
    e = assert_raises(TouchQue::APIError) { tq.assist.verify(no_phone["id"], "new_phone") }
    assert_equal %w[no_phone never_locked_out], [e.code, e.route]
    assert_raises(TouchQue::ConfigError) { tq.assist.open("a@b.com", agent: {}) }
    assert_raises(TouchQue::ConfigError) { tq.assist.list }
  end

  def test_mobile_sdk_server_side
    first = tq.mobile.create_enrollment("ada@shop.example")
    assert_match(/\Atqe_[A-Za-z0-9_-]{43}\z/, first["enrollmentToken"])
    device = api.post("/__test/mobile-enroll", { enrollmentToken: first["enrollmentToken"], platform: "android" })
    assert_equal "already_enrolled", assert_raises(TouchQue::APIError) { tq.mobile.create_enrollment("ada@shop.example") }.code
    second = tq.mobile.create_enrollment("ada@shop.example", replace: true, ttl_seconds: 300)
    assert_equal device["deviceId"], second["replacesDeviceId"]
    api.post("/__test/mobile-enroll", { enrollmentToken: second["enrollmentToken"] })
    active = tq.mobile.list_devices(external_username: "ada@shop.example")["devices"]
    assert_equal ["ios"], active.map { |d| d["platform"] }
    assert_equal "replaced", tq.mobile.get_device(device["deviceId"])["revokedReason"]
    assert_equal({ "via" => "webhook", "ok" => true }, tq.mobile.test_push(active[0]["deviceId"]))
    assert_equal({ "removed" => true, "wasLinked" => true }, tq.mobile.remove_device(active[0]["deviceId"]))
    assert_equal "optional", tq.mobile.settings["attestation"]
    s = tq.mobile.update_settings(ios_app_ids: ["ABCDE12345.com.shop.app"], attestation: "required")
    assert_equal [["ABCDE12345.com.shop.app"], 600], [s["iosAppIds"], s["enrollTtlSeconds"]]
    s = tq.mobile.update_settings(apns: { keyId: "ABC123DEFG", teamId: "TEAM123456", topic: "com.shop.app", key: "-----BEGIN PRIVATE KEY-----" },
                                  fcm: { serviceAccount: { project_id: "shop", client_email: "push@shop.iam.gserviceaccount.com", private_key: "x" } })
    assert_equal ["touchque", { "projectId" => "shop", "clientEmail" => "push@shop.iam.gserviceaccount.com" }], [s["push"]["ios"], s["push"]["fcm"]]
    assert_equal "webhook", tq.mobile.update_settings(apns: nil)["push"]["ios"]
    assert_raises(TouchQue::ConfigError) { tq.mobile.update_settings(nope: 1) }

    event = { "event" => "MOBILE_PUSH", "externalUsername" => "ada@shop.example", "deviceId" => "d1", "platform" => "ios", "pushToken" => "apns-token",
              "kind" => "approval", "requestId" => "r1", "expiresAt" => "2026-10-26T10:00:30.000Z",
              "alert" => { "title" => "Change delivery address", "body" => "Demo Shop is waiting for your approval." },
              "data" => { "touchque" => '{"v":1,"k":"approval","did":"d1","rid":"r1"}' } }
    push = TouchQue::Resources::Mobile.push_from_webhook(event)
    assert_equal({ "aps" => { "sound" => "default", "interruption-level" => "time-sensitive", "alert" => event["alert"] }, "touchque" => event["data"]["touchque"] }, push["apns"])
    assert_equal({ "touchque" => event["data"]["touchque"] }, push["fcmData"])
    assert_nil TouchQue::Resources::Mobile.push_from_webhook({ "event" => "DEVICE_LINKED" })
    assert TouchQue::Resources::Mobile.push_expired?(push, Time.utc(2026, 10, 26, 10, 1))
    refute TouchQue::Resources::Mobile.push_expired?(push, Time.utc(2026, 10, 26, 10, 0))
  end

  def test_management_api_calls
    api.reset
    i = tq.identity
    i.users.list(q: "ayse", limit: 10)
    i.users.create(email: "a@x.com", passwordHash: "$2b$10$abc")
    i.users.update("usr_1", appMetadata: { plan: nil })
    i.users.block("usr_1", reason: "fraud")
    i.users.delete("usr_1")
    i.users.reset_mfa("usr_1")
    i.users.password_reset("usr_1", send_email: false)
    i.users.add_roles("usr_1", ["rol_1"], organization_id: "org_1")
    i.users.remove_role("usr_1", "rol_1", organization_id: "org_1")
    i.imports.start(users: [{ email: "b@x.com" }], upsert: true)
    i.organizations.invite("org_1", email: "c@x.com", clientId: "cli", roleIds: ["rol_1"])
    assert_empty i.roles.list
    i.update_tenant(slug: "acme", displayName: "Acme")
    assert_equal "done", i.exports.wait("job_1", interval: 0.001)["status"]
    i.set_delivery("email", provider: "postmark", from: "login@acme.test", serverToken: "pm")
    i.test_delivery("sms", "+905321234567")
    i.set_attack_protection(bot: { provider: "turnstile", siteKey: "k", secret: "s", mode: "risky" })
    i.clients.rotate_secret("cli_1")
    i.users.end_session("usr_1", "ses_1")
    assert_includes i.exports.file("job_1"), "ok"
    i.set_approver_app_name("Acme Pay")
    i.set_custom_domain_only(true)
    i.check_domain_certificate("dom_1")
    calls = api.calls.select { |c| c["path"].start_with?("/identity") }
    assert_equal ["GET /identity/users?limit=10&q=ayse", "POST /identity/users", "PATCH /identity/users/usr_1", "POST /identity/users/usr_1/block",
                  "DELETE /identity/users/usr_1", "DELETE /identity/users/usr_1/mfa", "POST /identity/users/usr_1/password-reset", "POST /identity/users/usr_1/roles",
                  "DELETE /identity/users/usr_1/roles/rol_1?organizationId=org_1", "POST /identity/users-imports", "POST /identity/organizations/org_1/invitations",
                  "GET /identity/roles", "PUT /identity/tenant", "GET /identity/users-exports/job_1", "PUT /identity/delivery/email", "POST /identity/delivery/sms/test",
                  "PUT /identity/attack-protection", "POST /identity/clients/cli_1/rotate-secret", "DELETE /identity/users/usr_1/sessions/ses_1",
                  "GET /identity/users-exports/job_1/file", "PUT /identity/tenant", "PUT /identity/tenant",
                  "POST /identity/custom-domains/dom_1/check-certificate"], calls.map { |c| "#{c["method"]} #{c["url"]}" }
    assert_equal({ "branding" => { "approverAppName" => "Acme Pay" } }, calls[20]["body"])
    assert_equal({ "customDomainOnly" => true }, calls[21]["body"])
    assert_equal({ "email" => "a@x.com", "passwordHash" => "$2b$10$abc" }, calls[1]["body"])
    assert_equal({ "appMetadata" => { "plan" => nil } }, calls[2]["body"])
    assert_equal({ "roleIds" => ["rol_1"], "organizationId" => "org_1" }, calls[7]["body"])
  end

  def test_passkey_backend_and_outage_verifiers
    api.link("pk@acme.com")
    e = assert_raises(TouchQue::APIError) { tq.webauthn.register_options("pk@acme.com", discoverable: true) }
    assert_equal [403, "enrollment_approval_required"], [e.status, e.code]
    assert_equal({ "credentials" => [] }, tq.webauthn.list_credentials("pk@acme.com"))
    tq.webauthn.delete_credential("cred 1", external_username: "pk@acme.com")
    assert_equal "/webauthn/credentials/cred%201?externalUsername=pk%40acme.com", api.last_call["url"]
    assert_equal({ "enabled" => true, "userVerification" => "preferred" }, tq.webauthn.primary_availability)

    api.link("vpn@example.com")
    now = Time.now
    step = now.to_i / 30
    v = tq.offline.totp_verifiers(%w[vpn@example.com nobody@example.com], from_step: step - 1, steps: 4)
    assert_equal ["vpn@example.com"], v["users"].map { |u| u["externalUsername"] }
    user = v["users"][0]
    assert_equal step, TouchQue::Resources::Offline.match_totp_verifier(v, user, "k7p-2qxa", at: now)
    assert_nil TouchQue::Resources::Offline.match_totp_verifier(v, user, "K7P2QXB", at: now)
    assert_nil TouchQue::Resources::Offline.match_totp_verifier(v, user, "K7P2QXA", at: now + 3600)
    assert_nil TouchQue::Resources::Offline.match_totp_verifier(v, user, "K7P2QX1", at: now)
    api.opts(outageVerifiersDisabled: true)
    assert_raises(TouchQue::APIError) { tq.offline.totp_verifiers(["vpn@example.com"]) }
  end

  def resource(headers)
    status, text, = TouchQue::Transport.call("GET", "#{api.base_url}/__test/resource", headers: headers)
    [status, JSON.parse(text)]
  end

  def test_org_agent
    keys = TouchQue::AgentKeys.generate
    id = "oagt_abcdefghijkmnpqrstuv"
    api.post("/__test/org-agent", { agentId: id, publicKey: keys["publicJwk"], audiences: [APP], scopes: %w[invoices:read payments:create],
                                    delegation: %w[token_exchange ciba], sharedAccounts: ["k3JInstagramAcme01"] })
    agent = TouchQue::OrgAgent.new(agent_id: id, private_key: keys["privateJwk"], issuer: api.base_url)
    token = agent.get_token(scope: "invoices:read")
    assert_equal ["DPoP", 300, "invoices:read"], [token["tokenType"], token["expiresIn"], token["scope"]]
    assert_same token, agent.get_token(scope: "invoices:read")
    headers = agent.authorization("GET", "#{api.base_url}/__test/resource", scope: "invoices:read")
    assert_equal [200, { "ok" => true, "sub" => id, "aud" => APP, "via" => "key" }], resource(headers)
    assert_equal 401, resource(headers)[0]
    assert_equal "invalid_scope", assert_raises(TouchQue::APIError) { agent.get_token(scope: "payments:refund") }.code

    call = ->(t) { resource({ "Authorization" => "DPoP #{t}", "DPoP" => agent.dpop_proof("GET", "#{api.base_url}/__test/resource", t) })[1] }
    assert_equal "ada@acme.com", call.call(agent.exchange_token("member:ada@acme.com")["accessToken"])["sub"]
    assert_equal({ "accessToken" => "ya29.ada@acme.com", "tokenType" => "Bearer", "expiresIn" => 3599, "scope" => "email", "connection" => "google" },
                 agent.get_connection_token("member:ada@acme.com", "google", scope: "email"))
    assert_equal "invalid_grant", assert_raises(TouchQue::APIError) { agent.get_connection_token("member:ada@acme.com", "github") }.code
    payment = { "type" => "payment_initiation", "instructedAmount" => { "currency" => "TRY", "amount" => "500.00" } }
    ask = agent.ask_member("ada@acme.com", binding_message: "Pay invoice 42", authorization_details: [payment])
    assert_equal ["42", 1], [ask["bindingCode"], ask["interval"]]
    api.post("/__test/ciba-answer", { authReqId: ask["authReqId"], approve: true })
    approved = agent.wait_for_member(ask)
    assert_equal [payment], approved["authorizationDetails"]
    assert_equal id, call.call(approved["accessToken"])["act"]
    shared = agent.ask_to_open_shared_account("k3JInstagramAcme01", "ada@acme.com", "Post the launch photo")
    assert_equal "waiting_member", shared["status"]
    assert_includes shared["openUrl"], "/agent-ask?ask=#{shared["askId"]}"
    api.post("/__test/shared-ask-answer", { askId: shared["askId"], status: "declined" })
    assert_equal({ "status" => "declined", "reason" => nil, "caseCode" => nil }, agent.wait_for_shared_account(shared, interval: 0.05))
    no = agent.ask_member("ada@acme.com")
    api.post("/__test/ciba-answer", { authReqId: no["authReqId"], approve: false })
    assert_equal "access_denied", assert_raises(TouchQue::APIError) { agent.wait_for_member(no) }.code

    wid = "oagt_bbbbbbbbbbbbbbbbbbbb"
    api.post("/__test/org-agent", { agentId: wid, workload: { subject: "repo:acme/payments:ref:refs/heads/main", audience: "touchque" }, audiences: [APP], scopes: ["invoices:read"] })
    platform = ->(sub) { -> { api.post("/__test/workload-token", { sub: sub, aud: "touchque" })["token"] } }
    ci = TouchQue::OrgAgent.new(agent_id: wid, issuer: api.base_url, assertion: platform.call("repo:acme/payments:ref:refs/heads/main"))
    assert_equal "workload", resource(ci.authorization("GET", "#{api.base_url}/__test/resource"))[1]["via"]
    assert_raises(TouchQue::APIError) { TouchQue::OrgAgent.new(agent_id: wid, issuer: api.base_url, assertion: platform.call("repo:evil/x")).get_token }
    assert_raises(TouchQue::ConfigError) { TouchQue::OrgAgent.new(agent_id: id, issuer: "http://sso.example.com", assertion: -> { "x" }) }
  end

  def mcp_token(claims = {})
    api.post("/__test/mcp-token", { aud: RESOURCE, scope: "tickets:read" }.merge(claims))["token"]
  end

  def test_mcp_auth
    auth = TouchQue::McpAuth.new(issuer: "#{api.base_url}/mcp-as", resource: RESOURCE, tools: { "search_tickets" => "tickets:read", "delete_ticket" => "tickets:delete" })
    assert_equal ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], auth.metadata_paths
    assert_equal ["#{api.base_url}/mcp-as"], auth.protected_resource_metadata["authorization_servers"]
    claims = auth.verify("POST", RESOURCE, { "Authorization" => "Bearer #{mcp_token}" })
    assert_equal ["user-1", ["tickets:read"], false, "https://tool.example/client.json"], [claims["sub"], claims["scopes"], claims["dpopBound"], claims["clientId"]]
    auth.require_tool(claims, "search_tickets")
    e = assert_raises(TouchQue::McpAuthError) { auth.require_tool(claims, "delete_ticket") }
    assert_equal 403, e.status
    assert_includes e.www_authenticate, 'scope="tickets:delete"'
    e = assert_raises(TouchQue::McpAuthError) { auth.verify("POST", RESOURCE, {}) }
    assert_equal [401, 'Bearer resource_metadata="https://mcp.acme.example/.well-known/oauth-protected-resource/mcp"'], [e.status, e.www_authenticate]
    [{ aud: "https://other.example/mcp" }, { iss: "https://evil.example/mcp" }, { expiresIn: -120 }, { typ: "JWT" }].each do |bad|
      assert_equal "invalid_token", assert_raises(TouchQue::McpAuthError) { auth.verify("POST", RESOURCE, { "Authorization" => "Bearer #{mcp_token(bad)}" }) }.error
    end

    keys = TouchQue::AgentKeys.generate("EdDSA")
    jwk = keys["publicJwk"].slice("kty", "crv", "x")
    token = mcp_token(jkt: TouchQue::AgentKeys.thumbprint(jwk))
    signer = TouchQue::SigningKey.load(keys["privateJwk"], "test")
    proof = ->(htu = RESOURCE) { signer.jws({ "typ" => "dpop+jwt", "jwk" => jwk }, { "htm" => "POST", "htu" => htu, "iat" => TouchQue::Util.now, "jti" => SecureRandom.hex(12), "ath" => TouchQue::AgentKeys.access_token_hash(token) }) }
    assert_raises(TouchQue::McpAuthError) { auth.verify("POST", RESOURCE, { "Authorization" => "Bearer #{token}" }) }
    good = proof.call
    assert auth.verify("POST", RESOURCE, { "Authorization" => "DPoP #{token}", "DPoP" => good })["dpopBound"]
    assert_equal "invalid_dpop_proof", assert_raises(TouchQue::McpAuthError) { auth.verify("POST", RESOURCE, { "Authorization" => "DPoP #{token}", "DPoP" => good }) }.error
    assert_raises(TouchQue::McpAuthError) { auth.verify("POST", RESOURCE, { "Authorization" => "DPoP #{token}", "DPoP" => proof.call("https://other.example/mcp") }) }
  end
end
