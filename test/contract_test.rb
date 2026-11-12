# frozen_string_literal: true

require "test_helper"

# Against the shared fake Touchque API: a real HTTP round trip, so request signing is
# verified too. Same scenarios as the Node/Python/PHP/Go/.NET step-up tests.
class ContractTest < FakeApiTest
  def guard(user, token: nil, offline: false, code: nil, code_type: nil, action: "LOGIN")
    Touchque::Guard.run(tq, user, action, token: token, offline: offline, code: code, code_type: code_type)
  end

  def step(res) = res[:body]["touchque"]
  def token(res) = res[:body]["token"]

  def test_login_request_status_verify_and_report_fraud
    api.link("ada@acme.com")
    sent = tq.login.request("ada@acme.com", client_ip: "203.0.113.7", user_agent: "UA", details: [{ label: "Amount", value: "250 EUR" }],
                                            challenge_digits: 3, expires_in: 120, locale: "en")
    assert_equal "K7P-2QX", sent["caseCode"]
    assert_equal({ "externalUsername" => "ada@acme.com", "type" => "LOGIN", "clientIp" => "203.0.113.7", "userAgent" => "UA", "challengeDigits" => 3,
                   "expiresIn" => 120, "details" => [{ "label" => "Amount", "value" => "250 EUR" }], "locale" => "en" }, api.last_call["body"])
    assert_equal "PENDING", tq.login.status(sent["requestId"])["status"]
    api.approve(sent["requestId"])
    status = tq.login.status(sent["requestId"])
    assert_equal %w[CONFIRMED push], [status["status"], status.dig("assurance", "method")]
    report = tq.login.report_fraud(sent["requestId"], reason: "chargeback", note: "card holder disputed it")
    assert_equal [true, false], [report["reported"], report["alreadyReported"]]
    assert tq.login.report_fraud(sent["requestId"])["alreadyReported"]
    assert_raises(Touchque::ConfigError) { tq.login.report_fraud("") }
  end

  def test_verify_runs_on_challenge_before_the_wait
    api.link("bo@acme.com")
    api.opts(numberMatch: true)
    seen = nil
    result = tq.login.verify("bo@acme.com", timeout: 10) do |c|
      seen = c
      api.approve(c["requestId"])
    end
    assert result["approved"]
    assert_equal %w[47 K7P-2QX], [seen["challengeCode"], seen["caseCode"]]
    assert_includes seen["reasons"].map { |r| r["code"] }, "number_match_requested"
    assert_raises(Touchque::RejectedError) { tq.login.verify("bo@acme.com") { |c| api.reject(c["requestId"]) } }
    api.opts(passkeyOnly: true)
    assert_equal "policy", assert_raises(Touchque::PasskeyRequiredError) { tq.login.verify("bo@acme.com") }.reason
    api.opts(passkeyOnly: false)
    assert_equal "step_up", assert_raises(Touchque::PasskeyRequiredError) { tq.login.verify("bo@acme.com") { |c| api.escalate(c["requestId"]) } }.reason
    assert_raises(Touchque::TimeoutError) { tq.login.verify("bo@acme.com", timeout: 0.5) }
  end

  def test_verify_sends_expires_in_and_client_signals
    api.link("long@acme.com")
    tq.login.verify("long@acme.com", timeout: 10, expires_in: 120, client_signals: { "pasted" => true }) { |c| api.approve(c["requestId"]) }
    sent = api.calls.find { |c| c["path"] == "/login/request" }["body"]
    assert_equal [120, { "pasted" => true }], sent.values_at("expiresIn", "clientSignals")
  end

  def test_an_empty_reference_id_is_no_reference_id
    api.link("ref@acme.com")
    s = tq.start("SEND_MONEY", "ref@acme.com", reference_id: "")
    refute api.last_call["body"].key?("referenceId")
    api.approve(s["requestId"])
    assert_equal "SEND_MONEY", tq.complete(s["requestId"], "ref@acme.com", "SEND_MONEY", reference_id: "")["action"]
    first = Touchque::Guard.run(tq, "ref@acme.com", "SEND_MONEY", reference_id: "")
    api.approve
    assert_equal 200, Touchque::Guard.run(tq, "ref@acme.com", "SEND_MONEY", reference_id: "", token: token(first))[:status]
  end

  def test_guard_answers_503_for_any_failure_never_500
    api.link("down@acme.com")
    client = tq
    first = Touchque::Guard.run(client, "down@acme.com", "LOGIN")
    api.approve
    # The approval comes back for another person: never run the action, never a bare 500.
    client.login.define_singleton_method(:consume) { |_id| { "externalUsername" => "mallory@acme.com", "type" => "LOGIN" } }
    mismatch = Touchque::Guard.run(client, "down@acme.com", "LOGIN", token: token(first))
    assert_equal [503, "unavailable"], [mismatch[:status], step(mismatch)["reason"]]
    client.login.define_singleton_method(:request) { |*, **| raise Errno::ENETUNREACH }
    assert_equal 503, Touchque::Guard.run(client, "down@acme.com", "LOGIN")[:status]
  end

  def test_a_garbled_answer_is_a_network_error
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        conn = server.accept
        conn.readpartial(4096)
        conn.write("garbage\r\n\r\n")
        conn.close
      end
    end
    client = Touchque::Client.new(api_key: "tq_k", api_secret: "s", base_url: "http://127.0.0.1:#{server.addr[1]}")
    assert_raises(Touchque::NetworkError) { client.login.status("r1") }
  ensure
    thread&.kill
    server&.close
  end

  def test_unlinked_user_is_a_clear_api_error
    e = assert_raises(Touchque::APIError) { tq.login.request("nobody@acme.com") }
    assert_equal [404, "device_not_linked"], [e.status, e.code]
  end

  def test_waiting_step_carries_the_telemetry_token
    api.link("tel@acme.com")
    assert_nil tq.start("LOGIN", "tel@acme.com")["telemetryToken"]
    api.opts(telemetry: true)
    assert_equal "tt_test", tq.start("LOGIN", "tel@acme.com")["telemetryToken"]
  end

  def test_start_check_complete_full_flow
    api.link("jane@acme.com")
    s = tq.start("SEND_MONEY", "jane@acme.com", details: { " Amount " => "250 EUR" }, reference_id: "tx-9")
    assert_equal %w[waiting 47], [s["state"], s["number"]]
    assert_equal [{ "label" => "Amount", "value" => "250 EUR" }], s["details"]
    assert_equal "waiting", tq.check(s["requestId"])["state"]
    api.approve
    assert_equal "approved", tq.check(s["requestId"])["state"]
    approval = tq.complete(s["requestId"], "Jane@acme.com", "SEND_MONEY", details: { "Amount" => "250 EUR" }, reference_id: "tx-9")
    assert_equal({ "phishingResistant" => false, "method" => "push" }, approval["assurance"])
    assert_equal "already_used", assert_raises(Touchque::APIError) { tq.complete(s["requestId"], "jane@acme.com", "SEND_MONEY", details: { "Amount" => "250 EUR" }, reference_id: "tx-9") }.code
  end

  def test_complete_refuses_a_different_amount_and_unknown_actions
    api.link("jane2@acme.com")
    s = tq.start("SEND_MONEY", "jane2@acme.com", details: { "Amount" => "250 EUR" })
    api.approve(s["requestId"])
    assert_raises(Touchque::ApprovalMismatchError) { tq.complete(s["requestId"], "jane2@acme.com", "SEND_MONEY", details: { "Amount" => "9999 EUR" }) }
    assert_match(/NOT_DEFINED/, assert_raises(Touchque::ConfigError) { tq.start("NOT_DEFINED", "jane2@acme.com") }.message)
  end

  def test_guard_and_on_challenge_log_only_through_touchque_logger
    api.link("jane4@acme.com")
    api.opts(numberMatch: true)
    out, err = capture_io do
      assert_equal 500, guard("jane4@acme.com", action: "NOT_DEFINED")[:status]
      tq.login.verify("jane4@acme.com", timeout: 10) { |c| api.approve(c["requestId"]) && raise("screen gone") }
    end
    assert_equal ["", ""], [out, err], "silent by default"

    lines = []
    Touchque.logger = Object.new.tap do |l|
      l.define_singleton_method(:warn) { |m| lines << [:warn, m] }
      l.define_singleton_method(:error) { |m| lines << [:error, m] }
    end
    assert_equal 500, guard("jane4@acme.com", action: "NOT_DEFINED")[:status]
    tq.login.verify("jane4@acme.com", timeout: 10) { |c| api.approve(c["requestId"]) && raise("screen gone") }
    assert_equal :error, lines[0][0]
    assert_match(/NOT_DEFINED/, lines[0][1])
    assert_equal [:warn, "[Touchque] on_challenge failed: RuntimeError: screen gone"], lines[1]
  ensure
    Touchque.logger = nil
  end

  def test_action_types_define
    t = tq.action_types.define("EXPORT", name: "Export data", critical: true, second_thought: { questions: ["safe_account"], locale: "en" })
    assert t["critical"]
    assert_equal({ "type" => "EXPORT", "name" => "Export data", "critical" => true, "secondThought" => { "questions" => ["safe_account"], "locale" => "en" } },
                 api.last_call["body"])
    assert(tq.action_types.list.any? { |x| x["type"] == "EXPORT" })
  end

  def test_guard_full_flow
    api.link("guard@acme.com")
    api.opts(numberMatch: true)
    first = guard("guard@acme.com")
    assert_equal [202, "waiting", "47"], [first[:status], step(first)["state"], step(first)["number"]]
    assert_equal 202, guard("guard@acme.com", token: token(first))[:status]
    assert Touchque::Guard.status_poll?(tq, "guard@acme.com", "LOGIN", token: token(first))
    api.approve
    done = guard("guard@acme.com", token: token(first))
    assert_equal [200, "push"], [done[:status], done[:approved]["assurance"]["method"]]
    replay = guard("guard@acme.com", token: token(first))
    assert_nil replay[:approved]
    assert_includes [403, 408, 409], replay[:status]
    assert_equal "waiting", step(guard("guard@acme.com", token: token(first), action: "SEND_MONEY"))["state"]
    assert_equal 401, guard(nil)[:status]
  end

  def test_guard_enroll_then_offline_code
    first = guard("new-offline@acme.com")
    assert_equal "enroll", step(first)["state"]
    assert step(first)["enroll"]["qrCodeDataUrl"].start_with?("data:image/png;base64,")
    api.link("new-offline@acme.com")
    waiting = guard("new-offline@acme.com", token: token(first))
    assert_equal "waiting", step(waiting)["state"]
    off = guard("new-offline@acme.com", token: token(waiting), offline: true)
    assert_equal ["offline", "data:image/png;base64,OFFLINE"], [step(off)["state"], step(off)["offline"]["qrDataUrl"]]
    wrong = guard("new-offline@acme.com", token: token(off), code: "ZZZZ999")
    assert_equal 4, step(wrong)["offline"]["attemptsLeft"]
    ok = guard("new-offline@acme.com", token: token(wrong), code: "ABCD123")
    assert_equal [200, "offline_code", "OFFLINE_CODE"], [ok[:status], ok[:approved]["assurance"]["method"], ok[:approved]["confirmedVia"]]
  end

  def test_guard_phone_reject_kills_the_offline_qr
    api.link("reject-offline@acme.com")
    start = guard("reject-offline@acme.com")
    off = guard("reject-offline@acme.com", token: token(start), offline: true)
    assert_equal "offline", step(off)["state"]
    qr = api.calls.select { |c| c["path"] == "/offline/challenge" }.last
    assert_equal step(start)["requestId"], qr["body"]["requestId"]
    poll = guard("reject-offline@acme.com", token: token(off))
    assert_equal [202, "offline", step(off)["offline"]["challengeId"]], [poll[:status], step(poll)["state"], step(poll)["offline"]["challengeId"]]
    api.reject
    rejected = guard("reject-offline@acme.com", token: token(poll))
    assert_equal [403, "rejected"], [rejected[:status], step(rejected)["state"]]
    late = guard("reject-offline@acme.com", token: token(off), code: "ABCD123")
    assert_equal %w[rejected request_rejected], [step(late)["state"], step(late)["reason"]]
    assert_equal "rejected", step(guard("reject-offline@acme.com", token: token(off), code: "123456", code_type: "totp"))["state"]
    assert_equal "rejected", step(guard("reject-offline@acme.com", token: token(start), offline: true))["state"]
  end

  def test_guard_offline_qr_carries_the_number
    api.link("nm-offline@acme.com")
    api.opts(numberMatch: true)
    start = guard("nm-offline@acme.com")
    assert_equal "47", step(guard("nm-offline@acme.com", token: token(start), offline: true))["offline"]["challengeCode"]
  end

  def test_guard_frozen_rate_limited_blocked
    api.link("blocked@acme.com")
    api.opts(frozen: true)
    frozen = guard("blocked@acme.com")
    assert_equal [423, 900], [frozen[:status], step(frozen)["retryAfter"]]
    api.opts(frozen: false, rateLimited: true)
    assert_equal 429, guard("blocked@acme.com")[:status]
    api.opts(rateLimited: false, blocked: "geo_policy")
    blocked = guard("blocked@acme.com")
    assert_equal 403, blocked[:status]
    assert_equal({ "state" => "blocked", "reason" => "geo_policy", "caseCode" => "REF-USE" }, step(blocked))
  end

  def test_first_waiting_step_carries_the_mirror_canary_polls_do_not
    api.link("canary@acme.com")
    api.opts(canary: true)
    first = guard("canary@acme.com")
    assert step(first)["canary"]["url"].end_with?(".gif")
    poll = guard("canary@acme.com", token: token(first))
    assert_equal ["waiting", nil, "K7P-2QX"], [step(poll)["state"], step(poll)["canary"], step(poll)["caseCode"]]
  end

  def test_push_tapped_during_a_call_becomes_passkey_required_also_from_the_offline_qr
    api.link("oncall@acme.com")
    first = guard("oncall@acme.com")
    rid = step(first)["requestId"]
    off = guard("oncall@acme.com", token: token(first), offline: true)
    api.escalate(rid)
    poll = guard("oncall@acme.com", token: token(off))
    assert_equal [202, "passkey_required", rid], [poll[:status], step(poll)["state"], step(poll)["requestId"]]
    assert_equal "passkey_required", step(guard("oncall@acme.com", token: token(off), code: "ABCD123"))["state"]
  end

  def test_provisional_approval_and_the_critical_action_lock
    api.link("prov@acme.com")
    s = tq.start("LOGIN", "prov@acme.com")
    api.approve(s["requestId"], provisional: true)
    approval = tq.complete(s["requestId"], "prov@acme.com", "LOGIN")
    assert_equal [true, false], [approval["provisional"], approval["revoked"]]
    assert_equal({ "state" => "blocked", "reason" => "provisional", "caseCode" => "REF-USE" }, tq.start("SEND_MONEY", "prov@acme.com"))
    api.reconfirm(s["requestId"])
    assert_equal "waiting", tq.start("SEND_MONEY", "prov@acme.com")["state"]
  end

  def test_an_approval_taken_back_is_never_used
    api.link("revoke@acme.com")
    first = guard("revoke@acme.com")
    rid = step(first)["requestId"]
    api.approve(rid)
    api.revoke(rid)
    done = guard("revoke@acme.com", token: token(first))
    assert_equal 408, done[:status]
    assert_equal({ "state" => "expired", "reason" => "revoked" }, step(done))
  end

  def test_recovery_code_and_auth_user
    gen = tq.auth.generate_secret("eve@acme.com")
    assert gen["qrCodeDataUrl"].start_with?("data:image/png;base64,")
    assert_equal 409, assert_raises(Touchque::APIError) { tq.auth.generate_secret("eve@acme.com") }.status
    pending = tq.auth.get_user("eve@acme.com")
    assert_equal [false, nil], [pending["used"], pending["device"]]
    api.link("eve@acme.com")
    linked = tq.auth.get_user("eve@acme.com")
    assert_equal [true, "healthy", "ios"], [linked["used"], linked["device"]["state"], linked["device"]["platform"]]
    assert_equal 404, assert_raises(Touchque::APIError) { tq.auth.get_user("nobody@acme.com") }.status
    sent = tq.login.request("eve@acme.com")
    assert tq.login.approve_with_recovery_code(sent["requestId"], "r1")["success"]
  end

  def test_context_security_changes_and_destination
    vectors = TestSupport.fixture("actions-api-vectors.json")["context"]
    api.link("ctx@example.com")
    tq.login.request("ctx@example.com", context: { roles: ["admin"], amount: 2500 })
    assert_equal vectors["loginRequest"]["body"], api.last_call["body"]
    tq.risk.check("ctx@example.com", type: "LOGIN", context: { roles: ["admin"] })
    assert_equal vectors["riskCheck"]["body"], api.last_call["body"]
    res = tq.login.request("ctx@example.com", security_changes: { mfa: Time.utc(2026, 10, 25, 9, 30) },
                                              destination: { kind: "iban", value: "TR33 0006 1005 1978 6457 9413 26", known: ["TR330006100519786457841326"] })
    assert_equal "2026-10-25T09:30:00.000Z", api.last_call["body"]["securityChanges"]["mfa"]
    assert_equal [false, "same_start_and_end"], [res["destination"]["known"], res["destination"]["lookalike"][0]["reason"]]
  end

  # First-time QR: one per enrollment, not one per poll.

  def calls_since(from) = api.calls.drop(from).map { |c| "#{c["method"]} #{c["path"]}" }

  def test_an_enroll_poll_keeps_the_qr_without_a_new_secret
    user = "enroll-keep@acme.com"
    client = tq
    first = Touchque::Guard.run(client, user, "LOGIN")
    qr = step(first)["enroll"]
    assert_equal [202, "data:image/png;base64,QR-#{user}", ["r1"]], [first[:status], qr["qrCodeDataUrl"], qr["recoveryCodes"]]
    expires_at = Touchque::Steps.iso_ms(qr["expiresAt"])
    refute_nil expires_at, "the API's ISO 8601 expiresAt is kept"
    assert Touchque::Guard.status_poll?(client, user, "LOGIN", token: token(first))

    from = api.calls.length
    poll = Touchque::Guard.run(client, user, "LOGIN", token: token(first))
    assert_equal 202, poll[:status]
    # No "enroll": the page keeps the QR and the recovery codes it shows.
    assert_equal({ "state" => "enroll", "expiresAt" => Touchque::Steps.iso_of(expires_at) }, step(poll))
    # Only the link state is read: no new secret, no reset, no push.
    assert_equal ["GET /users/enroll-keep%40acme.com"], calls_since(from)

    again = Touchque::Guard.run(client, user, "LOGIN", token: token(poll))
    assert_equal step(poll), step(again)
    assert Touchque::Guard.status_poll?(client, user, "LOGIN", token: token(poll))
    refute Touchque::Guard.status_poll?(client, user, "SEND_MONEY", token: token(poll))
    refute Touchque::Guard.status_poll?(client, "other@acme.com", "LOGIN", token: token(poll))
  end

  def test_linking_during_the_enroll_poll_sends_the_push
    first = guard("enroll-link@acme.com")
    assert_equal "enroll", step(first)["state"]
    api.link("enroll-link@acme.com")
    poll = guard("enroll-link@acme.com", token: token(first))
    assert_equal [202, "waiting"], [poll[:status], step(poll)["state"]]
    refute_nil step(poll)["requestId"]
  end

  def test_an_enroll_qr_close_to_its_expiry_is_replaced
    api.opts(secretTtlMs: 10_000) # less than the 15 s the guard keeps in hand
    first = guard("enroll-short@acme.com")
    assert_equal "data:image/png;base64,QR-enroll-short@acme.com", step(first)["enroll"]["qrCodeDataUrl"]
    poll = guard("enroll-short@acme.com", token: token(first))
    assert_equal [202, "enroll"], [poll[:status], step(poll)["state"]]
    assert_equal ["data:image/png;base64,QR2-enroll-short@acme.com", ["r2"]], step(poll)["enroll"].values_at("qrCodeDataUrl", "recoveryCodes")
  end

  def test_an_enroll_token_is_a_status_poll_only_while_the_qr_is_up
    api.opts(secretTtlMs: 60_000) # 45 s before the 15 s margin
    up = guard("enroll-up@acme.com")
    assert Touchque::Guard.status_poll?(tq, "enroll-up@acme.com", "LOGIN", token: token(up))
    api.opts(secretTtlMs: 10_000) # inside the margin: the next poll renews the QR
    expiring = guard("enroll-expiring@acme.com")
    refute Touchque::Guard.status_poll?(tq, "enroll-expiring@acme.com", "LOGIN", token: token(expiring))
  end

  def test_before_start_runs_only_when_an_enroll_poll_starts_after_all
    client = tq
    calls = 0
    refused = { status: 429, body: { "error" => "RATE_LIMITED" } }
    refuse = lambda {
      calls += 1
      refused
    }
    go_on = lambda {
      calls += 1
      nil
    }
    run = ->(user, tok, hook) { Touchque::Guard.run(client, user, "LOGIN", token: tok, before_start: hook) }

    first = run.call("enroll-hook@acme.com", nil, refuse)
    keep = run.call("enroll-hook@acme.com", token(first), refuse)
    assert_equal ["enroll", nil], [step(keep)["state"], step(keep)["enroll"]]
    assert_equal 0, calls, "never for a first attempt or a poll that keeps the QR"

    # Linked: the poll would push. The hook answers instead, and nothing starts.
    api.link("enroll-hook@acme.com")
    from = api.calls.length
    assert_equal refused, run.call("enroll-hook@acme.com", token(first), refuse)
    assert_equal ["GET /users/enroll-hook%40acme.com"], calls_since(from)
    assert_equal "waiting", step(run.call("enroll-hook@acme.com", token(first), go_on))["state"]
    assert_equal 2, calls

    # A QR inside the margin would be renewed: the hook comes first there too.
    api.opts(secretTtlMs: 10_000)
    first = run.call("enroll-renew@acme.com", nil, refuse)
    from = api.calls.length
    assert_equal refused, run.call("enroll-renew@acme.com", token(first), refuse)
    assert_equal ["GET /users/enroll-renew%40acme.com"], calls_since(from), "no new secret"
    renewed = run.call("enroll-renew@acme.com", token(first), go_on)
    assert_equal "data:image/png;base64,QR2-enroll-renew@acme.com", step(renewed)["enroll"]["qrCodeDataUrl"]
    assert_equal 4, calls
  end

  def test_a_before_start_answer_that_is_no_result_fails_closed
    client = tq
    first = Touchque::Guard.run(client, "enroll-hook-bad@acme.com", "LOGIN")
    api.link("enroll-hook-bad@acme.com")
    [true, "refused", { "error" => "RATE_LIMITED" }, { status: 429 }].each do |bad|
      from = api.calls.length
      res = Touchque::Guard.run(client, "enroll-hook-bad@acme.com", "LOGIN", token: token(first), before_start: -> { bad })
      assert_equal [503, "unavailable"], [res[:status], step(res)["reason"]], bad.inspect
      assert_equal ["GET /users/enroll-hook-bad%40acme.com"], calls_since(from), "nothing started for #{bad.inspect}"
    end
    # false goes on, like nil.
    going = Touchque::Guard.run(client, "enroll-hook-bad@acme.com", "LOGIN", token: token(first), before_start: -> { false })
    assert_equal "waiting", step(going)["state"]
  end

  ErrorShape = Struct.new(:message, :code)

  def test_error_body_is_decided_by_what_it_encodes_to
    result = Touchque::Guard.unauthenticated
    step = result[:body]["touchque"]
    shape = ->(value) { JSON.parse(Touchque::Guard.error_body(result, ->(_) { value })) }
    hashy = Object.new.tap { |o| o.define_singleton_method(:to_hash) { { "message" => "to_hash" } } }
    as_json = Object.new.tap { |o| o.define_singleton_method(:as_json) { |*| { "message" => "as_json" } } }

    assert_equal({ "message" => "m", "code" => "c", "touchque" => step }, shape.call(ErrorShape.new("m", "c")))
    assert_equal({ "message" => "to_hash", "touchque" => step }, shape.call(hashy))
    assert_equal({ "message" => "as_json", "touchque" => step }, shape.call(as_json))
    if defined?(::Data)
      data = Data.define(:message).new(message: "data")
      assert_equal({ "message" => "data", "touchque" => step }, shape.call(data))
    end
    assert_equal ["Sign in first", nil, %w[a b]], ["Sign in first", nil, %w[a b]].map { |v| shape.call(v) }
  end

  def test_error_body_gets_a_copy_of_the_step_and_falls_back_on_failure
    lines = []
    Touchque.logger = Object.new.tap { |l| l.define_singleton_method(:error) { |m| lines << m } }
    result = Touchque::Guard.unauthenticated
    original = Touchque::Util.deep_copy(result[:body])
    edit = lambda { |r|
      r[:touchque]["state"] = "approved"
      r[:touchque].delete("reason")
      r[:code] << "!"
    }
    shaped = Touchque::Guard.error_body(result, ->(r) { edit.call(r) && { code: r[:code] } })
    assert_equal({ "code" => "unauthenticated!", "touchque" => original["touchque"] }, JSON.parse(shaped))
    assert_equal original, result[:body], "the answer is never changed"

    assert_equal original, JSON.parse(Touchque::Guard.error_body(result, ->(r) { edit.call(r) && raise("boom") }))
    assert_equal original, JSON.parse(Touchque::Guard.error_body(result, ->(_) { { "message" => "\xB1" } }))
    assert_equal "[Touchque] errorBody failed: boom", lines[0]
    assert_match(/\A\[Touchque\] errorBody failed: ./, lines[1], "a result that cannot be encoded")
  ensure
    Touchque.logger = nil
  end

  def test_enroll_false_says_why_and_is_no_status_poll
    client = tq
    # enroll: false (a pre-auth relay): "not linked", no QR, so no expiry in the token.
    res = Touchque::Guard.run(client, "enroll-none@acme.com", "LOGIN", enroll: false)
    assert_equal [202, { "state" => "enroll", "reason" => "enrollment_off" }], [res[:status], step(res)]
    refute Touchque::Guard.status_poll?(client, "enroll-none@acme.com", "LOGIN", token: token(res))
    # A 202 step, not a refusal: no state headers.
    assert_equal({ "content-type" => "application/json; charset=utf-8", "cache-control" => "no-store" }, Touchque::Guard.response(res)[1])
  end

  # Waiting polls repeat expiresAt.

  def claims(res) = Touchque::Steps.verify_guard_token("test_secret", token(res))

  def test_waiting_polls_carry_the_requests_expires_at
    user = "expiry-poll@acme.com"
    api.link(user)
    first = guard(user)
    rx = Touchque::Steps.iso_ms(step(first)["expiresAt"])
    refute_nil rx
    assert_equal rx, claims(first)["rx"], "the token carries the request's expiry"
    expires_at = Touchque::Steps.iso_of(rx)

    second = guard(user, token: token(first))
    third = guard(user, token: token(second))
    [second, third].each do |answer|
      assert_equal [202, "waiting", expires_at], [answer[:status], step(answer)["state"], step(answer)["expiresAt"]]
      assert_equal rx, claims(answer)["rx"]
    end

    # The offline QR next to the push carries it on.
    off = guard(user, token: token(third), offline: true)
    assert_equal ["offline", rx], [step(off)["state"], claims(off)["rx"]]
    kept = guard(user, token: token(off))
    assert_equal ["offline", rx], [step(kept)["state"], claims(kept)["rx"]]

    # A tap during a call moves the push to a passkey and Touchque extends it (180 s): the switch from the
    # offline QR answers the live expiry, not the first one, and the new token keeps it.
    api.escalate(step(first)["requestId"])
    passkey = guard(user, token: token(kept))
    live = Touchque::Steps.iso_ms(step(passkey)["expiresAt"])
    assert_equal "passkey_required", step(passkey)["state"]
    assert_operator live, :>, rx + 100_000, "the extended expiry, not the first one"
    assert_equal live, claims(passkey)["rx"]
    again = guard(user, token: token(passkey))
    assert_equal ["passkey_required", Touchque::Steps.iso_of(live)], step(again).values_at("state", "expiresAt")
  end

  def test_a_push_moved_to_a_passkey_answers_its_extended_expiry
    api.link("expiry-escalated@acme.com")
    first = guard("expiry-escalated@acme.com")
    rx = Touchque::Steps.iso_ms(step(first)["expiresAt"])
    api.escalate(step(first)["requestId"])
    poll = guard("expiry-escalated@acme.com", token: token(first))
    live = Touchque::Steps.iso_ms(step(poll)["expiresAt"])
    assert_equal "passkey_required", step(poll)["state"]
    assert_operator live, :>, rx + 100_000
    assert_equal live, claims(poll)["rx"]
  end

  def test_without_a_live_expiry_a_poll_falls_back_to_the_token
    # A status answer without expiresAt (an older API): the token's rx; without rx either, none (5.1).
    client = Touchque::Client.new(api_key: "tq_test_key", api_secret: "test_secret", base_url: "http://127.0.0.1:9")
    client.login.define_singleton_method(:status) { |_id| { "status" => "PENDING" } }
    rx = Touchque::Util.now_ms + 60_000
    claims = { "u" => "old@acme.com", "a" => "LOGIN", "d" => Touchque::Details.digest(nil), "r" => nil, "st" => "waiting",
               "rid" => "r1", "n" => nil, "oc" => nil, "exp" => Touchque::Util.now_ms + 600_000, "rx" => rx }
    poll = Touchque::Guard.run(client, "old@acme.com", "LOGIN", token: Touchque::Steps.sign_guard_token("test_secret", claims))
    assert_equal ["waiting", Touchque::Steps.iso_of(rx)], step(poll).values_at("state", "expiresAt")
    assert_equal rx, claims(poll)["rx"]

    old = Touchque::Guard.run(client, "old@acme.com", "LOGIN", token: Touchque::Steps.sign_guard_token("test_secret", claims.except("rx")))
    assert_equal "waiting", step(old)["state"]
    refute step(old).key?("expiresAt")
    refute claims(old).key?("rx")
  end

  def test_a_passkey_request_repeats_its_expires_at
    api.link("expiry-passkey@acme.com")
    api.opts(passkeyOnly: true)
    first = guard("expiry-passkey@acme.com")
    assert_equal "passkey_required", step(first)["state"]
    expires_at = Touchque::Steps.iso_of(Touchque::Steps.iso_ms(step(first)["expiresAt"]))
    poll = guard("expiry-passkey@acme.com", token: token(first))
    assert_equal ["passkey_required", expires_at], step(poll).values_at("state", "expiresAt")
  end

  def test_a_token_without_rx_takes_the_live_expiry
    api.link("expiry-old@acme.com")
    first = guard("expiry-old@acme.com")
    old = Touchque::Steps.sign_guard_token("test_secret", claims(first).except("rx"))
    poll = guard("expiry-old@acme.com", token: old)
    expiry = Touchque::Steps.iso_ms(step(first)["expiresAt"])
    assert_equal ["waiting", Touchque::Steps.iso_of(expiry)], step(poll).values_at("state", "expiresAt")
    assert_equal expiry, claims(poll)["rx"]
  end

  # Guard.response: the answer for a result in your own handler.

  def test_guard_response_gives_status_headers_and_json
    api.link("answer@acme.com")
    shape = ->(r) { { message: r[:message], code: r[:code], touchque: "mine" } }
    called = false
    waiting = guard("answer@acme.com")
    status, headers, body = Touchque::Guard.response(waiting, error_body: ->(_) { called = true })
    assert_equal [202, { "content-type" => "application/json; charset=utf-8", "cache-control" => "no-store" }], [status, headers]
    assert_equal waiting[:body], JSON.parse(body)
    refute called, "never for a 202 step"

    api.reject
    rejected = guard("answer@acme.com", token: token(waiting))
    status, headers, body = Touchque::Guard.response(rejected, error_body: shape)
    assert_equal [403, "rejected", nil], [status, headers["x-touchque-state"], headers["x-touchque-reason"]]
    assert_equal({ "message" => "The approval was rejected.", "code" => "rejected", "touchque" => step(rejected) }, JSON.parse(body))

    api.opts(rateLimited: true)
    limited = guard("answer@acme.com")
    api.opts(rateLimited: false)
    status, headers, body = Touchque::Guard.response(limited)
    assert_equal [429, "60", "rate_limited", "no-store"], [status, headers["retry-after"], headers["x-touchque-state"], headers["cache-control"]]
    assert_equal limited[:body], JSON.parse(body), "the default body keeps its token"

    misconfigured = guard("answer@acme.com", action: "NO_SUCH_ACTION")
    status, headers, body = Touchque::Guard.response(misconfigured, error_body: ->(r) { r[:code] })
    assert_equal [500, "blocked", "misconfigured", '"misconfigured"'], [status, headers["x-touchque-state"], headers["x-touchque-reason"], body]
  end

  def test_guard_response_logs_a_failing_error_body_and_sends_the_default_body
    lines = []
    Touchque.logger = Object.new.tap { |l| l.define_singleton_method(:error) { |m| lines << m } }
    result = Touchque::Guard.unauthenticated
    status, _, body = Touchque::Guard.response(result, error_body: ->(_) { raise "template missing" })
    assert_equal [401, result[:body]], [status, JSON.parse(body)]
    assert_equal ["[Touchque] errorBody failed: template missing"], lines
  ensure
    Touchque.logger = nil
  end

  def test_guard_response_refuses_an_approval_and_a_non_callable_error_body
    assert_raises(ArgumentError) { Touchque::Guard.response({ status: 200, approved: { "requestId" => "r1" } }) }
    assert_raises(ArgumentError) { Touchque::Guard.response(Touchque::Guard.unauthenticated, error_body: :shape) }
  end

  # Guard.run(nil, ...): the default client, Touchque.client.

  UNCONFIGURED = "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured."

  # Runs the block with Touchque.client built from +env+ only (no keys: none), the log captured.
  def with_default_client(env = {})
    saved = { env: ENV.to_h.slice("TQ_API_KEY", "TQ_API_SECRET", "TQ_API_URL"), logger: Touchque.logger,
              logged: Touchque::Guard.unconfigured_logged,
              options: Touchque.instance_variable_get(:@client_options), client: Touchque.instance_variable_get(:@client) }
    %w[TQ_API_KEY TQ_API_SECRET TQ_API_URL].each { |name| ENV.delete(name) }
    env.each { |name, value| ENV[name] = value }
    Touchque.configure
    Touchque::Guard.unconfigured_logged = false
    lines = []
    Touchque.logger = Object.new.tap { |l| l.define_singleton_method(:error) { |m| lines << m } }
    yield
    lines
  ensure
    %w[TQ_API_KEY TQ_API_SECRET TQ_API_URL].each { |name| ENV.delete(name) }
    saved[:env].each { |name, value| ENV[name] = value }
    Touchque.logger = saved[:logger]
    Touchque::Guard.unconfigured_logged = saved[:logged]
    Touchque.instance_variable_set(:@client_options, saved[:options])
    Touchque.instance_variable_set(:@client, saved[:client])
  end

  def keys = { "TQ_API_KEY" => "tq_test_key", "TQ_API_SECRET" => "test_secret", "TQ_API_URL" => api.base_url }

  def test_without_keys_a_nil_client_answers_500_or_401_and_logs_once
    lines = with_default_client do
      2.times { assert_equal Touchque::Guard.misconfigured, Touchque::Guard.run(nil, "jane@acme.com", "SEND_MONEY") }
      assert_equal Touchque::Guard.unauthenticated, Touchque::Guard.run(nil, nil, "SEND_MONEY")
    end
    assert_equal [UNCONFIGURED], lines
  end

  def test_status_poll_with_a_nil_client_is_false_until_the_keys_are_set
    # A valid waiting token for this user and action, signed with the secret the environment gives below.
    claims = { "u" => "jane@acme.com", "a" => "SEND_MONEY", "d" => Touchque::Details.digest(nil), "r" => nil,
               "st" => "waiting", "rid" => "r1", "exp" => Touchque::Util.now_ms + 60_000 }
    valid = Touchque::Steps.sign_guard_token("test_secret", claims)
    with_default_client do
      refute Touchque::Guard.status_poll?(nil, "jane@acme.com", "SEND_MONEY", token: valid), "no client while the keys are missing"
      keys.each { |name, value| ENV[name] = value }
      assert Touchque::Guard.status_poll?(nil, "jane@acme.com", "SEND_MONEY", token: valid)
    end
  end

  def test_default_client_setter_gives_the_nil_path_your_client_and_nil_forgets_it
    api.link("mine@acme.com")
    mine = Touchque::Client.new(api_key: "tq_test_key", api_secret: "test_secret", base_url: api.base_url)
    with_default_client do
      Touchque::Guard.default_client = mine # no keys in the environment: yours is used
      assert_same mine, Touchque::Guard.default_client
      first = Touchque::Guard.run(nil, "mine@acme.com", "LOGIN")
      assert_equal 202, first[:status]
      assert Touchque::Guard.status_poll?(nil, "mine@acme.com", "LOGIN", token: token(first))

      # nil forgets it: the next call builds from the environment again.
      Touchque::Guard.default_client = nil
      assert_equal 500, Touchque::Guard.run(nil, "mine@acme.com", "LOGIN")[:status]
      keys.each { |name, value| ENV[name] = value }
      assert_equal 202, Touchque::Guard.run(nil, "mine@acme.com", "LOGIN")[:status]
      refute_same mine, Touchque::Guard.default_client
    end
  end

  def test_touchque_client_fails_fast_at_boot
    with_default_client do
      error = assert_raises(Touchque::ConfigError) { Touchque.client }
      assert error.message.end_with?(Touchque::Client::MISSING_KEYS), error.message
      assert_nil Touchque::Guard.default_client, "the guard's lookup answers nil instead (and logs)"
    end
  end

  def test_with_keys_a_nil_client_runs_the_guard
    api.link("default@acme.com")
    lines = with_default_client(keys) do
      first = Touchque::Guard.run(nil, "default@acme.com", "LOGIN")
      assert_equal [202, "waiting"], [first[:status], step(first)["state"]]
      assert Touchque::Guard.status_poll?(nil, "default@acme.com", "LOGIN", token: token(first))
      api.approve
      done = Touchque::Guard.run(nil, "default@acme.com", "LOGIN", token: token(first))
      assert_equal [200, "default@acme.com"], [done[:status], done[:approved]["user"]]
    end
    assert_empty lines
  end

  def test_a_failed_default_client_build_is_retried_and_a_built_one_kept
    api.link("retry@acme.com")
    lines = with_default_client do
      assert_equal 500, Touchque::Guard.run(nil, "retry@acme.com", "LOGIN")[:status]
      # The keys arrive (a secret mounted late): the next request builds the client.
      keys.each { |name, value| ENV[name] = value }
      assert_equal 202, Touchque::Guard.run(nil, "retry@acme.com", "LOGIN")[:status]
      built = Touchque.client
      assert_equal 202, Touchque::Guard.run(nil, "retry@acme.com", "LOGIN")[:status]
      assert_same built, Touchque.client
    end
    assert_equal [UNCONFIGURED], lines
  end

  def test_the_enroll_expiry_comes_from_ttl_ms_when_the_api_sends_no_date
    client = Touchque::Client.new(api_key: "tq_k", api_secret: "s", base_url: "http://127.0.0.1:9")
    client.login.define_singleton_method(:request) { |*, **| raise Touchque::APIError.new(404, { "code" => "device_not_linked" }) }
    answers = [{ "qrCodeDataUrl" => "data:image/png;base64,QR", "expiresAt" => "soon", "ttlMs" => 60_000 },
               { "qrCodeDataUrl" => "data:image/png;base64,QR", "expiresAt" => "soon" }]
    client.auth.define_singleton_method(:generate_secret) { |_user| answers.shift }

    now = Touchque::Util.now_ms
    with_ttl = Touchque::Guard.run(client, "ttl@acme.com", "LOGIN")
    expires_at = Touchque::Steps.iso_ms(step(with_ttl)["enroll"]["expiresAt"])
    assert_includes (now + 60_000)...(now + 65_000), expires_at
    assert Touchque::Guard.status_poll?(client, "ttl@acme.com", "LOGIN", token: token(with_ttl))

    # Neither a date nor a lifetime: no expiry, and polls start again as before.
    none = Touchque::Guard.run(client, "ttl@acme.com", "LOGIN")
    refute step(none)["enroll"].key?("expiresAt")
    refute Touchque::Guard.status_poll?(client, "ttl@acme.com", "LOGIN", token: token(none))
  end
end
