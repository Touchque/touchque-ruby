# frozen_string_literal: true

require "test_helper"
require "touchque/testing"

# Touchque::Testing::FakeTouchque: the real guard against an API answered in memory (no
# network, no keys, no Node.js).
class TestingTest < Minitest::Test
  FakeTouchque = Touchque::Testing::FakeTouchque

  def run_guard(tq, user, token: nil, action: "SEND_MONEY", **options)
    Touchque::Guard.run(tq, user, action, token: token, **options)
  end

  def step(res) = res[:body]["touchque"]
  def token(res) = res[:body]["token"]

  def test_a_push_runs_once_after_the_phone_approves
    tq = FakeTouchque.new
    assert_kind_of Touchque::Client, tq
    first = run_guard(tq, "jane@acme.com", details: { "Amount" => "5 EUR" })
    assert_equal [202, "waiting", "K7P-2QX"], [first[:status], step(first)["state"], step(first)["caseCode"]]
    poll = run_guard(tq, "jane@acme.com", token: token(first), details: { "Amount" => "5 EUR" })
    assert_equal 202, poll[:status]
    # The request keeps its expiry and answers it on each status check: polls carry it.
    assert_equal tq.requests.last["expiresAt"], step(first)["expiresAt"]
    assert_equal tq.requests.last["expiresAt"], tq.login.status(step(first)["requestId"])["expiresAt"]
    assert_equal step(first)["expiresAt"], step(poll)["expiresAt"]

    assert_equal step(first)["requestId"], tq.approve
    done = run_guard(tq, "jane@acme.com", token: token(first), details: { "Amount" => "5 EUR" })
    assert_equal [200, "jane@acme.com", "push"], [done[:status], done[:approved]["user"], done[:approved]["assurance"]["method"]]
    replay = run_guard(tq, "jane@acme.com", token: token(first), details: { "Amount" => "5 EUR" })
    assert_equal [408, "already_used"], [replay[:status], step(replay)["reason"]]

    request = tq.requests.last
    assert_equal ["jane@acme.com", "SEND_MONEY", [{ "label" => "Amount", "value" => "5 EUR" }], "CONFIRMED"],
                 request.values_at("user", "type", "details", "status")
    assert_equal ["POST /login/request", "GET /login/status/#{request["id"]}"], tq.calls.first(2).map { |c| "#{c["method"]} #{c["path"]}" }
  end

  def test_reject_expire_number_match_and_passkey
    tq = FakeTouchque.new(number_match: true)
    first = run_guard(tq, "bo@acme.com")
    assert_equal "47", step(first)["number"]
    tq.reject
    assert_equal [403, "rejected"], run_guard(tq, "bo@acme.com", token: token(first)).then { |r| [r[:status], step(r)["state"]] }

    second = run_guard(tq, "bo@acme.com")
    tq.expire(step(second)["requestId"])
    assert_equal 408, run_guard(tq, "bo@acme.com", token: token(second))[:status]

    third = run_guard(tq, "bo@acme.com")
    tq.approve(via: "WEBAUTHN")
    passkey = run_guard(tq, "bo@acme.com", token: token(third))
    assert_equal ["passkey", true], passkey[:approved]["assurance"].values_at("method", "phishingResistant")
    assert_raises(ArgumentError) { tq.approve("no-such-request") }
    assert_raises(ArgumentError) { FakeTouchque.new.approve }
  end

  def test_auto_approve
    tq = FakeTouchque.new(auto_approve: true)
    first = run_guard(tq, "auto@acme.com")
    assert_equal 202, first[:status], "the first request still answers the step"
    assert_equal 200, run_guard(tq, "auto@acme.com", token: token(first))[:status]
  end

  def test_the_first_time_qr_until_the_phone_links
    tq = FakeTouchque.new.unlink("new@acme.com")
    refute tq.linked?("new@acme.com")
    first = run_guard(tq, "new@acme.com")
    assert_equal ["data:image/png;base64,QR1-new@acme.com", ["r1"]], step(first)["enroll"].values_at("qrCodeDataUrl", "recoveryCodes")
    from = tq.calls.size
    keep = run_guard(tq, "new@acme.com", token: token(first))
    assert_equal ["enroll", nil], [step(keep)["state"], step(keep)["enroll"]]
    assert_equal ["GET /users/new%40acme.com"], tq.calls.drop(from).map { |c| "#{c["method"]} #{c["path"]}" }

    tq.link("new@acme.com") # the phone scanned the QR
    assert_equal "waiting", step(run_guard(tq, "new@acme.com", token: token(keep)))["state"]

    # Nobody has a phone; a QR about to expire is renewed with new recovery codes.
    nobody = FakeTouchque.new(linked: false)
    nobody.secret_ttl_ms = 10_000
    qr = run_guard(nobody, "late@acme.com")
    renewed = run_guard(nobody, "late@acme.com", token: token(qr))
    assert_equal ["data:image/png;base64,QR2-late@acme.com", ["r2"]], step(renewed)["enroll"].values_at("qrCodeDataUrl", "recoveryCodes")
    off = run_guard(nobody, "late@acme.com", enroll: false)
    assert_equal({ "state" => "enroll", "reason" => "enrollment_off" }, step(off))
  end

  def test_offline_and_time_based_codes
    tq = FakeTouchque.new
    first = run_guard(tq, "off@acme.com")
    off = run_guard(tq, "off@acme.com", token: token(first), offline: true)
    assert_equal ["offline", "data:image/png;base64,OFFLINE"], [step(off)["state"], step(off)["offline"]["qrDataUrl"]]
    wrong = run_guard(tq, "off@acme.com", token: token(off), code: "ZZZZ999")
    assert_equal 4, step(wrong)["offline"]["attemptsLeft"]
    ok = run_guard(tq, "off@acme.com", token: token(wrong), code: FakeTouchque::OFFLINE_CODE)
    assert_equal [200, "OFFLINE_CODE"], [ok[:status], ok[:approved]["confirmedVia"]]

    again = run_guard(tq, "off@acme.com")
    totp = run_guard(tq, "off@acme.com", token: token(again), code: tq.totp_code, code_type: "totp")
    assert_equal [200, "OFFLINE_TOTP"], [totp[:status], totp[:approved]["confirmedVia"]]
  end

  def test_the_api_calls_it_answers_and_the_rest
    tq = FakeTouchque.new
    defined = tq.action_types.define("EXPORT", name: "Export data", critical: true)
    assert_equal ["EXPORT", true], defined.values_at("type", "critical")
    assert_equal ["EXPORT"], tq.action_types.list.map { |t| t["type"] }
    assert_equal true, tq.risk.check("risk@acme.com")["prompt"]
    error = assert_raises(Touchque::APIError) { tq.agents.list }
    assert_equal 404, error.status
    assert_same FakeTouchque, Touchque::Testing::FakeClient
  end

  # The client Touchque.client holds now, without building one.
  def current_client = Touchque.instance_variable_get(:@client)

  def assert_client_is(expected)
    expected.nil? ? assert_nil(current_client) : assert_same(expected, current_client)
  end

  def test_install_makes_it_the_default_client
    previous = current_client
    tq = FakeTouchque.new
    tq.install do
      assert_same tq, Touchque.client
      assert_same tq, Touchque::Guard.default_client # install is Touchque::Guard.default_client = tq
      first = Touchque::Guard.run(nil, "default@acme.com", "LOGIN")
      assert_equal "waiting", step(first)["state"]
      assert Touchque::Guard.status_poll?(nil, "default@acme.com", "LOGIN", token: token(first))
    end
    assert_client_is previous

    assert_same tq, tq.install
    assert_same tq, Touchque.client
    tq.uninstall
    tq.uninstall # twice is harmless
    assert_client_is previous
  end
end
