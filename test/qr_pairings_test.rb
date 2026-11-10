# frozen_string_literal: true

require "test_helper"

# QR pairing against the shared fake API: register, the QR's text and hash, the phone's
# scan, a request for the phone that scanned, and refusals. Same scenarios as the Node
# SDK's QrPairings tests.
class QrPairingsTest < FakeApiTest
  THUMB = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

  def setup
    super
    api.link("ayse@acme.com")
  end

  def test_create_scan_then_ask_the_phone_that_scanned
    p = tq.qr_pairings.create(THUMB, client_ip: "203.0.113.7", user_agent: "Mozilla/5.0", browser: "Chrome 155", os: "macOS 15")
    assert_equal TouchQue::Resources::QrPairings.uri(p["pairingId"], p["nonce"], THUMB), p["uri"]
    assert_match %r{\Atouchque://pair-browser\?v=1&p=[\w-]{22}&n=[\w-]{43}&k=[\w-]{43}\z}, p["uri"]
    assert_equal TouchQue::Util.b64url(TouchQue::Util.sha256(p["nonce"])), api.get("/__test/qr-pairings").last["nonceHash"]
    assert_equal "waiting", tq.qr_pairings.get(p["pairingId"])["state"]
    err = assert_raises(TouchQue::APIError) { tq.login.request("ayse@acme.com", qr_pairing: p["pairingId"]) }
    assert_equal "pairing_not_confirmed", err.code

    api.post("/__test/qr-scan", { id: p["pairingId"], user: "ayse@acme.com" })
    seen = tq.qr_pairings.get(p["pairingId"])
    assert_equal ["confirmed", "ayse@acme.com", []], [seen["state"], seen["externalUsername"], seen["proximity"]["warnings"]]
    req = tq.login.request("ayse@acme.com", qr_pairing: p["pairingId"])
    after = tq.qr_pairings.get(p["pairingId"])
    assert_equal ["requested", req["requestId"]], [after["state"], after["requestId"]]
  end

  def test_refuse_after_the_scan_and_checks_before_the_call
    p = tq.qr_pairings.create(THUMB, ttl_seconds: 60)
    err = assert_raises(TouchQue::APIError) { tq.qr_pairings.refuse(p["pairingId"], reason: "policy", message: "Not yet") }
    assert_equal [409, "not_open"], [err.status, err.code]
    api.post("/__test/qr-scan", { id: p["pairingId"], user: "ayse@acme.com", confirm: false })
    refused = tq.qr_pairings.refuse(p["pairingId"], reason: "device_not_approved", message: "Ask IT to approve this computer.", device_code: "ABC-123")
    assert_equal %w[refused device_not_approved ABC-123], [refused["state"], refused["outcome"]["reason"], refused["outcome"]["deviceCode"]]
    assert_raises(TouchQue::ConfigError) { tq.qr_pairings.create("short") }
    assert_raises(TouchQue::ConfigError) { tq.qr_pairings.create(THUMB, ttl_seconds: 10) }
    assert_raises(TouchQue::ConfigError) { tq.qr_pairings.refuse(p["pairingId"], reason: "nope", message: "x") }
    assert_raises(TouchQue::ConfigError) { tq.qr_pairings.refuse(p["pairingId"], reason: "other", message: " ") }
  end
end
