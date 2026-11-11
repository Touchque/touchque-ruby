# frozen_string_literal: true

require "test_helper"
require "pp"

# The cross-language fixtures (fixtures/): every SDK signs, canonicalizes, verifies
# and matches exactly like the server and the other SDKs.
class VectorsTest < Minitest::Test
  # A stand-in for Touchque::HTTP answering one fixed body.
  class StubHTTP
    def initialize(answer)
      @answer = answer
    end

    def post(_path, _body = {})
      @answer.is_a?(Exception) ? raise(@answer) : @answer
    end
  end

  def test_signature_vectors
    fx = TestSupport.fixture("signature-vectors.json")
    refute_empty fx["vectors"]
    fx["vectors"].each do |v|
      assert_equal v["expected_signature"], Touchque::HTTP.sign(fx["secret"], v["method"], v["signed_path"], v["body"], v["timestamp"], v["nonce"]), v["description"]
    end
  end

  def test_webhook_vectors
    fx = TestSupport.fixture("webhook-vectors.json")
    webhook = Touchque::Client.new(api_key: "tq_x", api_secret: fx["secret"]).webhook
    fx["vectors"].each do |v|
      assert_equal v["expected_canonical"], Touchque::Resources::Webhook.canonicalize(v["delivered_body"]), v["description"]
      # The fixtures carry a fixed past timestamp: no freshness check.
      assert_equal v["payload"]["requestId"], webhook.verify(v["delivered_body"], tolerance_seconds: 0)["requestId"]
    end
  end

  def test_webhook_signature_timestamp_and_replay
    secret = "whsec_test"
    webhook = Touchque::Client.new(api_key: "tq_x", api_secret: secret).webhook
    sign = lambda do |payload|
      sig = Touchque::Util.hmac_hex(secret, Touchque::Resources::Webhook.canonicalize(JSON.generate(payload)))
      JSON.generate(payload.merge("signature" => sig))
    end
    fresh = sign.call({ "status" => "SUCCESS", "requestId" => "r1", "timestamp" => Time.now.utc.iso8601(3), "jti" => "j1", "note" => "Zoë Ångström / € 😀" })
    cache = Touchque::MemoryReplayCache.new
    assert_equal "r1", webhook.verify(fresh, replay_cache: cache)["requestId"]
    error = assert_raises(Touchque::WebhookReplayError) { webhook.verify(fresh, replay_cache: cache) }
    assert_equal "j1", error.jti
    assert_raises(Touchque::WebhookSignatureError) { webhook.verify(sign.call({ "status" => "SUCCESS", "timestamp" => "2020-01-01T00:00:00.000Z" })) }
    tampered = assert_raises(Touchque::WebhookSignatureError) { webhook.verify(fresh.sub('"r1"', '"r2"')) }
    refute_match(/expected/i, tampered.message)
    assert_raises(Touchque::WebhookSignatureError) { webhook.verify("not json") }
    assert_raises(Touchque::WebhookSignatureError) { webhook.verify(sign.call({ "status" => "SUCCESS" })) }
    # A pretty-printed body canonicalizes to the same bytes.
    pretty = JSON.pretty_generate(JSON.parse(fresh))
    assert_equal Touchque::Resources::Webhook.canonicalize(fresh), Touchque::Resources::Webhook.canonicalize(pretty)
  end

  # The event names the API sends (its recovery and help desk webhooks, the Mobile SDK's push).
  def test_webhook_event_names
    w = Touchque::Resources::Webhook
    sent = %w[RECOVERY_STARTED RECOVERY_DEVICE_BOUND RECOVERY_COOLING RECOVERY_COMPLETED RECOVERY_VETOED RECOVERY_EXPIRED RECOVERY_FAILED
              ASSIST_OPENED ASSIST_ENDED ASSIST_CHECK_PASSED ASSIST_CHECK_FAILED ASSIST_UNFROZEN ASSIST_CLAIM_CONFIRMED ASSIST_CLAIM_UNVERIFIED MOBILE_PUSH]
    sent.each { |name| assert_equal name, w.const_get("EVENT_#{name}") }
    known = w.constants.grep(/\AEVENT_(RECOVERY|ASSIST)_/).map { |c| w.const_get(c) }
    assert_equal sent.grep(/\A(RECOVERY|ASSIST)_/).sort, known.sort
  end

  def test_silent_sign_in_risk_check_vectors
    TestSupport.fixture("silent-sign-in-vectors.json")["riskCheck"]["cases"].each do |c|
      [Touchque::Resources::Risk.parse_check(c["response"]), Touchque::Resources::Risk.new(StubHTTP.new(c["response"])).check("jane@acme.com")].each do |res|
        assert_equal c["expected"]["prompt"], res["prompt"], c["name"]
        assert_equal c["expected"]["reasonCodes"], res["reasons"].map { |r| r["code"] }, c["name"]
        assert_equal c["expected"]["assurance"], res["assurance"], c["name"]
      end
    end
  end

  def test_approval_proof_vectors
    fx = TestSupport.fixture("approval-proof-vectors.json")
    fx["digest_cases"].each do |c|
      assert_equal c["digest"], Touchque::Details.digest(c["details"] || c["details_object"])
    end
    fx["cases"].each do |c|
      o = c["options"]
      got = Touchque::ApprovalProof.verify(c["proof"], request_id: o["requestId"], type: o["type"], details: o["details"], challenge_code: o["challengeCode"],
                                                       expected_public_key: o["expectedPublicKey"], allow_unpinned_key: o["allowUnpinnedKey"] == true)
      assert_equal c["expected"], got, c["name"]
    end
    refute Touchque::ApprovalProof.verify({ "version" => "v2", "algorithm" => "ECDSA-P256-SHA256", "publicKey" => "!!", "message" => "x", "signature" => "%%" },
                                          request_id: "r", type: "LOGIN", allow_unpinned_key: true)
  end

  def test_details_trim_like_the_api
    # JavaScript's trim, as the API: Unicode spaces too (no-break, narrow no-break, ideographic, BOM).
    spaced = { "\u3000Amount\t" => "\u00a0250 EUR\u202f\ufeff" }
    assert_equal [{ "label" => "Amount", "value" => "250 EUR" }], Touchque::Details.normalize(spaced)
    assert_equal Touchque::Details.digest({ "Amount" => "250 EUR" }), Touchque::Details.digest(spaced)
    # Spaces inside a value stay.
    assert_equal [{ "label" => "Total", "value" => "1 250,00\u00a0TL" }], Touchque::Details.normalize([{ label: " Total", value: "1 250,00\u00a0TL " }])
  end

  def test_agent_vectors
    fx = TestSupport.fixture("agent-vectors.json")
    fx["thumbprints"].each { |v| assert_equal v["thumbprint"], Touchque::AgentKeys.thumbprint(v["jwk"]) }
    fx["ath"].each { |v| assert_equal v["ath"], Touchque::AgentKeys.access_token_hash(v["accessToken"]) }
    at = fx["approvalToken"]
    claims = Touchque::ApprovalToken.verify_with(at["token"], at["jwks"], audience: at["audience"], user: "ayse@example.com", type: "PAY_INVOICE",
                                                                          authorization_details: { instructedAmount: { currency: "TRY", amount: "500" },
                                                                                                   creditorAccount: { iban: "TR33 0006 1005 1978 6457 8413 26" } },
                                                                          now: at["verifyAt"])
    assert_equal at["claims"], claims
    own = at["audience"]
    [[at["tampered"], own, at["verifyAt"]], [at["wrongType"], own, at["verifyAt"]], [at["token"], "touchque:workspace:other", at["verifyAt"]],
     [at["token"], own, at["claims"]["exp"] + 60]].each do |token, aud, now|
      assert_raises(Touchque::ApprovalMismatchError) { Touchque::ApprovalToken.verify_with(token, at["jwks"], audience: aud, now: now) }
    end
    assert_raises(Touchque::ApprovalMismatchError) { Touchque::ApprovalToken.verify_with(at["token"], at["jwks"], audience: own, user: "mallory@example.com", now: at["verifyAt"]) }
    # The audience is required, and a token without aud is refused.
    [[at["token"], at["jwks"], "touchque:workspace:other", /another workspace/], [at["token"], at["jwks"], nil, /audience is required/],
     [at["token"], at["jwks"], "", /audience is required/], [at["noAudience"]["token"], at["noAudience"]["jwks"], own, /names no workspace/]].each do |token, jwks, aud, want|
      err = assert_raises(Touchque::ApprovalMismatchError) { Touchque::ApprovalToken.verify_with(token, jwks, audience: aud, now: at["verifyAt"]) }
      assert_match want, err.message
    end
    fx["matching"].each do |m|
      assert_equal m["matches"], Touchque::ApprovalToken.matches?(at["claims"]["authorization_details"], m["expect"]), m["name"]
    end
  end

  def test_guard_tokens_are_bound_and_expire
    claims = { "u" => "a", "a" => "LOGIN", "d" => "", "r" => nil, "exp" => Touchque::Util.now_ms + 60_000 }
    token = Touchque::Steps.sign_guard_token("secret", claims)
    assert_equal "a", Touchque::Steps.verify_guard_token("secret", token)["u"]
    assert_nil Touchque::Steps.verify_guard_token("other", token)
    assert_nil Touchque::Steps.verify_guard_token("secret", "#{token[0..-3]}xx")
    assert_nil Touchque::Steps.verify_guard_token("secret", Touchque::Steps.sign_guard_token("secret", claims.merge("exp" => Touchque::Util.now_ms - 1)))
  end

  def test_config_refuses_swapped_keys_and_plain_http
    assert_raises(Touchque::ConfigError) { Touchque::Client.new(api_key: "secret", api_secret: "tq_key") }
    assert_raises(Touchque::ConfigError) { Touchque::Client.new(api_key: "tq_k", api_secret: "s", base_url: "http://api.example.com") }
    assert Touchque::Client.new(api_key: "tq_k", api_secret: "s", base_url: "http://127.0.0.1:9")
  end

  def test_inspect_never_shows_the_api_secret
    client = Touchque::Client.new(api_key: "tq_key123", api_secret: "SECRET123", base_url: "http://127.0.0.1:9")
    relay = Touchque::RelayHandler.new(client, get_user_id: ->(_) {}, get_login_user: ->(_) {})
    [client, client.webhook, client.login, relay].each do |o|
      refute_match(/SECRET123|tq_key123/, o.inspect, o.class.name)
      refute_match(/SECRET123|tq_key123/, o.pretty_inspect, o.class.name)
    end
    assert_includes client.inspect, "http://127.0.0.1:9"
  end

  def test_login_cookies_seal_unseal_and_split
    secret = "s" * 40
    sealed = Touchque::LoginSession.seal({ "a" => 1 }, secret, "session", 60)
    assert_equal({ "a" => 1 }, Touchque::LoginSession.unseal(sealed, secret, "session"))
    assert_nil Touchque::LoginSession.unseal(sealed, secret, "tx")
    assert_nil Touchque::LoginSession.unseal("#{sealed[0..-3]}AA", secret, "session")
    assert_nil Touchque::LoginSession.unseal(Touchque::LoginSession.seal({ "a" => 1 }, secret, "session", -1), secret, "session")
    big = "x" * 9000
    parts = Touchque::LoginSession.cookie_values("tq_session", big, ["tq_session"])
    assert_equal({ "tq_session.0" => big[0, 3800], "tq_session.1" => big[3800, 3800], "tq_session.2" => big[7600..], "tq_session" => nil }, parts)
    assert_equal big, Touchque::LoginSession.read("tq_session", parts.compact)
    assert_equal "/", Touchque::LoginSession.safe_return_to("//evil.example")
  end
end
