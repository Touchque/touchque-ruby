# frozen_string_literal: true

require "test_helper"
require "socket"

# Touchque Login's passkey domain, user store and custom-domain list against the API's own
# answers: refusals keep their status, error, field and count, a 204 is an
# empty answer, and nothing the API answers is dropped. The shared fake API answers every
# /identity call with { ok: true }, so these answers come from a stub on 127.0.0.1.
class IdentitySettingsTest < Minitest::Test
  STORE = { "url" => "https://api.acme.test/touchque/user-store", "enabled" => true, "active" => false, "movedIn" => 12,
            "lastCall" => { "at" => "2026-11-17T08:00:00.000Z", "event" => "user_store.get_user", "ok" => false, "status" => 500, "ms" => 41, "error" => "answered 500" },
            "paused" => true, "updatedAt" => "2026-11-17T07:00:00.000Z",
            "signing" => "Signed like Touchque webhooks: HMAC-SHA256 with your API secret (x-signature); check it with your SDK's webhook verify." }.freeze

  # Answers each request with the next [status, body] (body nil: none) and records what it was sent.
  def with_api(*answers)
    server = TCPServer.new("127.0.0.1", 0)
    seen = []
    thread = Thread.new do
      loop do
        conn = server.accept
        method, path = conn.gets.to_s.split
        headers = {}
        while (line = conn.gets) && line != "\r\n"
          name, value = line.split(":", 2)
          headers[name.strip.downcase] = value.to_s.strip
        end
        body = conn.read(headers["content-length"].to_i).to_s
        seen << [method, path, body.empty? ? nil : JSON.parse(body)]
        status, out = answers.shift || [200, {}]
        text = out.nil? ? "" : JSON.generate(out)
        conn.write("HTTP/1.1 #{status} X\r\nContent-Type: application/json\r\nContent-Length: #{text.bytesize}\r\nConnection: close\r\n\r\n#{text}")
        conn.close
      end
    end
    yield Touchque::Client.new(api_key: "tq_k", api_secret: "s", base_url: "http://127.0.0.1:#{server.addr[1]}").identity, seen
  ensure
    thread&.kill
    server&.close
  end

  def test_passkey_domain_refusals_keep_error_field_and_count
    exist = { "error" => "passkeys_exist", "field" => "passkeyDomain", "count" => 3, "message" => "3 customer passkeys belong to the current setting and would stop working" }
    with_api([409, exist],
             [409, { "error" => "not_your_domain", "field" => "passkeyDomain", "message" => "example.org must be one of your verified custom domains, or a domain above one that your organization verified (Organization → Domains)" }],
             [409, { "error" => "organization_unavailable", "field" => "passkeyDomain", "message" => "Your organization’s verified domains could not be read; try again" }],
             [400, { "error" => "invalid_request", "field" => "passkeyDomain", "message" => "passkeyDomain must be a domain like example.com, or null" }],
             # Before Touchque Login is set up, the PUT would make the tenant: slug comes first.
             [400, { "error" => "invalid_request", "field" => "slug", "message" => "slug must be 3–63 lowercase letters, digits or hyphens" }],
             [200, { "slug" => "acme", "passkeyDomain" => nil }]) do |identity, seen|
      e = assert_raises(Touchque::APIError) { identity.set_passkey_domain("acme.com") }
      refute_kind_of Touchque::FeatureError, e
      assert_equal [409, "passkeys_exist", "passkeyDomain", 3, exist["message"]], [e.status, e.error, e.data["field"], e.data["count"], e.message]
      assert_equal [409, "not_your_domain"], assert_raises(Touchque::APIError) { identity.set_passkey_domain("example.org") }.then { |x| [x.status, x.error] }
      assert_equal [409, "organization_unavailable"], assert_raises(Touchque::APIError) { identity.set_passkey_domain("acme.com") }.then { |x| [x.status, x.error] }
      e = assert_raises(Touchque::APIError) { identity.set_passkey_domain("not a domain") }
      assert_equal [400, "invalid_request", "passkeyDomain"], [e.status, e.error, e.data["field"]]
      e = assert_raises(Touchque::APIError) { identity.set_passkey_domain("acme.com") }
      assert_equal [400, "invalid_request", "slug"], [e.status, e.error, e.data["field"]]
      assert_equal({ "slug" => "acme", "passkeyDomain" => nil }, identity.set_passkey_domain(nil))
      assert_equal [["PUT", "/identity/tenant", { "passkeyDomain" => "acme.com" }], ["PUT", "/identity/tenant", { "passkeyDomain" => "example.org" }],
                    ["PUT", "/identity/tenant", { "passkeyDomain" => "acme.com" }], ["PUT", "/identity/tenant", { "passkeyDomain" => "not a domain" }],
                    ["PUT", "/identity/tenant", { "passkeyDomain" => "acme.com" }], ["PUT", "/identity/tenant", { "passkeyDomain" => nil }]], seen
    end
  end

  def test_user_store_answers_come_back_whole
    with_api([200, STORE], [201, STORE], [200, { "ok" => false, "error" => "no answer in 5 seconds", "ms" => 5003 }], [204, nil]) do |identity, seen|
      assert_equal STORE, identity.get_user_store
      assert_equal STORE, identity.set_user_store(url: STORE["url"])
      # A failing endpoint is an answer, not an exception.
      assert_equal({ "ok" => false, "error" => "no answer in 5 seconds", "ms" => 5003 }, identity.test_user_store)
      assert_equal({}, identity.remove_user_store)
      assert_equal [["GET", "/identity/user-store", nil], ["PUT", "/identity/user-store", { "url" => STORE["url"] }],
                    ["POST", "/identity/user-store/test", {}], ["DELETE", "/identity/user-store", nil]], seen
    end
  end

  def test_user_store_refusals
    with_api([409, { "error" => "passwords_off", "field" => "enabled", "message" => "Moving users in checks their passwords: turn passwords on first" }],
             [400, { "error" => "invalid_request", "field" => "url", "message" => "url must use https" }],
             [400, { "error" => "invalid_request", "field" => "url", "message" => "url is required" }],
             [404, { "error" => "not_enabled", "message" => "PUT /identity/tenant first" }],
             [403, { "error" => "feature_not_in_plan", "feature" => "ciam", "message" => "This feature is not part of your organization’s plan." }]) do |identity, _seen|
      e = assert_raises(Touchque::APIError) { identity.set_user_store(enabled: true) }
      assert_equal [409, "passwords_off", "enabled"], [e.status, e.error, e.data["field"]]
      e = assert_raises(Touchque::APIError) { identity.test_user_store(url: "http://api.acme.test/user-store") }
      assert_equal [400, "invalid_request", "url", "url must use https"], [e.status, e.error, e.data["field"], e.message]
      assert_equal "url is required", assert_raises(Touchque::APIError) { identity.test_user_store }.message
      # DELETE answers 204 with or without a user store: a 404 is Touchque Login not set up, never swallowed.
      e = assert_raises(Touchque::APIError) { identity.remove_user_store }
      assert_equal [404, "not_enabled"], [e.status, e.error]
      e = assert_raises(Touchque::FeatureNotInPlanError) { identity.get_user_store }
      assert_equal [403, "ciam"], [e.status, e.feature]
    end
  end

  def test_custom_domain_list_keeps_verified_domains_and_slug_passkeys
    domain = { "id" => "dom_1", "domain" => "login.acme.com", "status" => "verified", "primary" => true, "proof" => "organization_domain",
               "organizationDomain" => "acme.com", "dns" => { "points" => "here", "cloudflareProxy" => false, "caaBlocks" => false, "problems" => [] },
               "autoCheckUntil" => "2026-11-20T08:00:00.000Z" }
    answer = { "domains" => [domain], "verifiedDomains" => ["acme.com"], "slugPasskeys" => 2 }
    with_api([200, answer], [200, answer], [200, { "domains" => [], "verifiedDomains" => nil, "slugPasskeys" => 0 }]) do |identity, seen|
      assert_equal [domain], identity.custom_domains.list
      assert_equal answer, identity.custom_domains.overview
      assert_nil identity.custom_domains.overview["verifiedDomains"]
      assert_equal [["GET", "/identity/custom-domains", nil]] * 3, seen
    end
  end

  # overview always has its three keys; get finds the domain in the list (the API has no read by
  # id) and raises for an id it does not have as the API answers one (404 not_found); verify posts
  # {} to the domain's path-encoded verify route and returns the domain.
  def test_custom_domain_overview_get_and_verify
    domain = { "id" => "dom 1/a", "domain" => "login.acme.com", "status" => "pending", "primary" => false, "dns" => nil, "autoCheckUntil" => "2026-11-20T08:00:00.000Z" }
    verified = domain.merge("status" => "verified", "dns" => { "points" => "here", "cloudflareProxy" => false, "caaBlocks" => false, "problems" => [] })
    with_api([200, { "domains" => [domain], "verifiedDomains" => [], "slugPasskeys" => 0 }], [200, { "ok" => true }],
             [200, { "domains" => [domain] }], [200, { "domains" => [domain] }],
             [200, verified], [404, { "error" => "not_found" }]) do |identity, seen|
      assert_equal({ "domains" => [domain], "verifiedDomains" => [], "slugPasskeys" => 0 }, identity.custom_domains.overview)
      # An answer without them still has the three keys (nothing else is dropped).
      assert_equal({ "ok" => true, "domains" => [], "verifiedDomains" => nil, "slugPasskeys" => nil }, identity.custom_domains.overview)
      assert_equal domain, identity.custom_domains.get("dom 1/a")
      missing = assert_raises(Touchque::APIError) { identity.custom_domains.get("dom_2") }
      assert_equal verified, identity.custom_domains.verify("dom 1/a")
      # The API's own 404 for an id it does not have: the same error.
      real = assert_raises(Touchque::APIError) { identity.custom_domains.verify("dom_2") }
      [missing, real].each do |e|
        refute_kind_of Touchque::FeatureError, e
        assert_equal [404, "not_found"], [e.status, e.error]
      end
      assert_equal ["not_found", "No custom domain with this id"], [missing.data["error"], missing.data["message"]]
      assert_equal "No custom domain with this id", missing.message
      assert_equal [["GET", "/identity/custom-domains", nil], ["GET", "/identity/custom-domains", nil], ["GET", "/identity/custom-domains", nil],
                    ["GET", "/identity/custom-domains", nil], ["POST", "/identity/custom-domains/dom%201%2Fa/verify", {}],
                    ["POST", "/identity/custom-domains/dom_2/verify", {}]], seen
    end
  end

  # A request to your user store, signed as Touchque signs it (HMAC-SHA256 with your API secret over
  # the payload with its top-level keys sorted; the signature in x-signature and in the body): the
  # webhook helper checks it, and a replay of it is refused.
  def test_a_user_store_request_verifies_with_the_webhook_helper
    secret = "api_secret_test"
    payload = { "event" => "user_store.verify_password", "tenant" => "acme", "email" => "ada@acme.com", "password" => "pässwörd 🔑 \"1\" \\ 😀 </script>",
                "timestamp" => Time.now.utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ"), "jti" => SecureRandom.uuid }
    signature = OpenSSL::HMAC.hexdigest("SHA256", secret, JSON.generate(payload.sort.to_h))
    raw = JSON.generate(payload.merge("signature" => signature))
    webhook = Touchque::Client.new(api_key: "tq_x", api_secret: secret).webhook
    cache = Touchque::MemoryReplayCache.new
    assert_equal payload.merge("signature" => signature), webhook.verify(raw, signature, replay_cache: cache)
    assert_raises(Touchque::WebhookReplayError) { webhook.verify(raw, signature, replay_cache: cache) }
    assert_raises(Touchque::WebhookSignatureError) { webhook.verify(raw.sub("ada@", "eve@"), signature) }
    ping = { "event" => "user_store.ping", "tenant" => "acme", "timestamp" => payload["timestamp"], "jti" => SecureRandom.uuid }
    ping_signature = OpenSSL::HMAC.hexdigest("SHA256", secret, JSON.generate(ping.sort.to_h))
    assert_equal "user_store.ping", webhook.verify(JSON.generate(ping.merge("signature" => ping_signature)))["event"]
  end
end
