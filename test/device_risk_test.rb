# frozen_string_literal: true

require "test_helper"

# Device risk against the shared fake API: the report goes through untouched and the
# answer fails toward asking. Same scenarios as the Node SDK's DeviceRisk tests.
class DeviceRiskTest < FakeApiTest
  def test_the_form_field_as_it_came_is_answered_never_raised
    [nil, "", ["x"]].each do |value|
      r = tq.device_risk.check(value, event: "sign_in", external_username: "ayse@acme.com")
      assert_equal "missing", r["report"]
      assert_nil r["visitorId"]
      assert_equal ["device_identification_missing"], r["signals"].map { |x| x["code"] }
      refute r["stepUp"]
      assert r["wouldStepUp"]
    end
    assert_equal "unknown", tq.device_risk.check("nope")["report"]
    assert_equal "expired", Touchque::Resources::DeviceRisk.parse_check({ "report" => "expired" })["report"]
  end

  def test_check_sends_the_report_and_reads_the_answer
    r = tq.device_risk.check("dre_flaggedaaaaaaaaaaaaaaa", event: "sign_up", external_username: "ayse@acme.com", client_ip: "203.0.113.7")
    assert_equal "ok", r["report"]
    assert_equal ["tqv_fakeVisitor00000001", "DRK-2QX", false], [r["visitorId"], r["caseCode"], r["signals"][0]["enforced"]]
    assert_equal "tqv_fakeVisitor00000001", tq.device_risk.get_event("dre_aaaaaaaaaaaaaaaaaaaaaa")["visitorId"]
    assert_equal [], tq.device_risk.check(device_risk: "REPORT")["signals"]
    assert_equal ["device_many_accounts"], r["signals"].map { |s| s["code"] }
    assert_equal [false, true, "shadow"], [r["stepUp"], r["wouldStepUp"], r["mode"]]
  end

  def test_bad_input_fails_before_any_request
    assert_raises(Touchque::ConfigError) { tq.device_risk.check(device_risk: "r", event: "tracking") }
    assert_raises(Touchque::ConfigError) { tq.device_risk.get_event("../users") }
  end

  def test_the_answer_fails_toward_asking
    assert Touchque::Resources::DeviceRisk.parse_check({})["stepUp"]
    refute Touchque::Resources::DeviceRisk.parse_check({ "stepUp" => false })["stepUp"]
    r = Touchque::Resources::DeviceRisk.parse_check({ "signals" => [{ "code" => "device_tampered", "text" => "t" }, nil, { "text" => "x" }], "requires" => "passkey" })
    assert_equal [{ "code" => "device_tampered", "text" => "t", "strength" => "number_match" }], r["signals"]
    assert_equal %w[passkey invalid], [r["requires"], r["report"]]
  end

  def test_engine_unavailable_comes_through_and_a_normal_answer_has_nil
    down = Touchque::Resources::DeviceRisk.parse_check({ "report" => "ok", "signals" => [], "stepUp" => true, "wouldStepUp" => true,
                                                         "requires" => "number_match", "mode" => "enforce", "engine" => "unavailable" })
    assert_equal ["unavailable", true, "number_match"], [down["engine"], down["stepUp"], down["requires"]]
    normal = Touchque::Resources::DeviceRisk.parse_check({ "report" => "ok", "signals" => [], "stepUp" => false, "requires" => "none", "mode" => "shadow" })
    assert_nil normal["engine"]
    refute normal["stepUp"]
    assert_nil Touchque::Resources::DeviceRisk.parse_check({ "engine" => 42 })["engine"]
  end

  def test_risk_check_carries_device_risk
    api.link("ayse@acme.com")
    assert tq.risk.check("ayse@acme.com", device_risk_request_id: "dre_aaaaaaaaaaaaaaaaaaaaaa")["prompt"]
  end

  def test_the_address_the_counts_and_a_bot_answer_come_through
    r = Touchque::Resources::DeviceRisk.parse_check({ "report" => "ok", "network" => { "type" => "hosting" }, "velocity" => { "identifications1h" => 2 }, "bot" => { "result" => "suspected" } })
    assert_equal "hosting", r["network"]["type"]
    assert_equal 2, r["velocity"]["identifications1h"]
    assert_equal "suspected", r["bot"]["result"]
    assert_nil Touchque::Resources::DeviceRisk.parse_check({ "network" => "x" })["network"]
  end

  def test_search_events_pages_with_the_opaque_cursor_and_sends_the_filters
    first = tq.device_risk.search_events(account: "ada@example.com", step_up: false, ip: "203.0.113.0/24", limit: 1)
    assert_equal({ "account" => "ada@example.com", "stepUp" => "false", "ip" => "203.0.113.0/24", "limit" => "1" }, api.last_device_risk_search)
    assert_equal ["dre_fakeEvent00000000002"], first["events"].map { |e| e["requestId"] }
    assert_nil first["nextCursor"]
    seen = []
    cursor = nil
    loop do
      page = tq.device_risk.search_events(limit: 1, cursor: cursor)
      seen.concat(page["events"].map { |e| e["requestId"] })
      cursor = page["nextCursor"]
      break unless cursor
    end
    assert_equal %w[dre_fakeEvent00000000003 dre_fakeEvent00000000002 dre_fakeEvent00000000001], seen
    assert_raises(Touchque::ConfigError) { tq.device_risk.search_events(limit: 101) }
    assert_raises(Touchque::ConfigError) { tq.device_risk.search_events(page: 2) }
  end
end
