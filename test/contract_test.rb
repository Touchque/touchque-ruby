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
end
