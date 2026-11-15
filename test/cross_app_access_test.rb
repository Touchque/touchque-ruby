# frozen_string_literal: true

require "test_helper"

# Cross App Access (ID-JAG) and A2A agent card signatures against the fake API: an app
# trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
# authorization server checks one (issuer, audience, client, expiry, typ, once); a card
# signed in RFC 8785 form by the fake (JavaScript) verifies here with keys from its own
# host and fails when changed or pointed elsewhere.
class CrossAppAccessTest < FakeApiTest
  def verifier
    Touchque::IdJagVerifier.new(issuer: "#{api.base_url}/idp", audience: "https://rs.example")
  end

  def reason
    yield
    "accepted"
  rescue Touchque::IdJagError => e
    e.message
  end

  def test_request_redeem_and_verify
    idp = "#{api.base_url}/idp"
    jag = Touchque::CrossAppAccess.request_id_jag(issuer: idp, client_id: "tqapp_test", client_secret: "tqs_test", id_token: "idtoken:ada",
                                                  audience: "https://rs.example", resource: "https://rs.example/files")
    assert_equal "files:read", jag["scope"]
    err = assert_raises(Touchque::IdJagError) do
      Touchque::CrossAppAccess.request_id_jag(issuer: idp, client_id: "tqapp_test", client_secret: "wrong", id_token: "idtoken:ada", audience: "https://rs.example")
    end
    assert_equal ["invalid_client", 401], [err.error, err.status]
    v = verifier
    claims = v.verify(jag["assertion"], client_id: "acme-at-rs")
    assert_equal ["ada", "acme-at-rs", ["files:read"], "https://rs.example/files"], claims.values_at("sub", "client_id", "scopes", "resource")
    assert_equal "already used", reason { v.verify(jag["assertion"], client_id: "acme-at-rs") }
    tokens = Touchque::CrossAppAccess.redeem_id_jag(token_endpoint: "#{api.base_url}/rs/token", client_id: "acme-at-rs", assertion: jag["assertion"])
    assert_equal "Bearer", tokens["token_type"]
  end

  def test_refusals
    v = verifier
    mint = ->(claims = {}, typ = nil) { api.post("/__test/id-jag", { claims: claims }.merge(typ ? { typ: typ } : {}))["assertion"] }
    assert_equal "issued to another client", reason { v.verify(mint.call, client_id: "someone-else") }
    assert_equal "not for this authorization server", reason { v.verify(mint.call({ aud: "https://evil.example" }), client_id: "acme-at-rs") }
    assert_equal "not for this authorization server", reason { v.verify(mint.call({ aud: ["https://rs.example", "https://b.example"] }), client_id: "acme-at-rs") }
    assert_equal "another issuer", reason { v.verify(mint.call({ iss: "https://evil.example" }), client_id: "acme-at-rs") }
    assert_equal "not an ID-JAG (typ oauth-id-jag+jwt)", reason { v.verify(mint.call({}, "at+jwt"), client_id: "acme-at-rs") }
    assert_equal "expired", reason { v.verify(mint.call({ exp: Time.now.to_i - 600 }), client_id: "acme-at-rs") }
    h, b, s = mint.call.split(".")
    forged = Touchque::Util.b64url(JSON.generate(JSON.parse(Touchque::Util.b64url_decode(b)).merge("sub" => "mallory")))
    assert_equal "signature does not verify", reason { v.verify("#{h}.#{forged}.#{s}", client_id: "acme-at-rs") }
  end

  def test_dpop_bound_request_redeem_and_verify
    # An identity provider and an authorization server that check the proof and bind to its key.
    server = TCPServer.new("127.0.0.1", 0)
    local = "http://127.0.0.1:#{server.addr[1]}"
    seen = []
    thread = Thread.new do
      loop do
        conn = server.accept
        path = conn.gets.to_s.split[1]
        headers = {}
        while (line = conn.gets) && line != "\r\n"
          name, value = line.split(":", 2)
          headers[name.strip.downcase] = value.to_s.strip
        end
        conn.read(headers["content-length"].to_i)
        header, payload, input, sig = Touchque::JWS.split(headers["dpop"])
        ok = header.is_a?(Hash) && Touchque::JWS.verify("ES256", header["jwk"], input, sig)
        jkt = ok ? Touchque::AgentKeys.thumbprint(header["jwk"]) : nil
        seen << { "path" => path, "header" => header, "payload" => payload, "jkt" => jkt }
        status, out = if !ok
                        ["400 Bad Request", { "error" => "invalid_dpop_proof" }]
                      elsif path == "/idp/token?x=1"
                        jag = "#{Touchque::Util.b64url('{"typ":"oauth-id-jag+jwt","alg":"RS256"}')}.#{Touchque::Util.b64url(JSON.generate("cnf" => { "jkt" => jkt }))}.sig"
                        ["200 OK", { "access_token" => jag, "issued_token_type" => Touchque::CrossAppAccess::ID_JAG_TOKEN_TYPE, "token_type" => "N_A" }]
                      else
                        ["200 OK", { "access_token" => "at", "token_type" => "DPoP" }]
                      end
        text = JSON.generate(out)
        conn.write("HTTP/1.1 #{status}\r\nContent-Type: application/json\r\nContent-Length: #{text.bytesize}\r\nConnection: close\r\n\r\n#{text}")
        conn.close
      end
    end
    key = Touchque::CrossAppAccess.create_id_jag_dpop_key
    got = Touchque::CrossAppAccess.request_id_jag(token_endpoint: "#{local}/idp/token?x=1", client_id: "tqapp_test", client_secret: "tqs_test",
                                                  id_token: "idtoken:ada", audience: "https://rs.example", dpop_key: key)
    assert_equal true, got["dpop_bound"]
    tokens = Touchque::CrossAppAccess.redeem_id_jag(token_endpoint: "#{local}/rs/token", client_id: "acme-at-rs", assertion: got["assertion"], dpop_key: key)
    assert_equal "DPoP", tokens["token_type"]
    assert_equal 2, seen.length
    assert_equal ["dpop+jwt", "ES256", key.thumbprint], [seen[0]["header"]["typ"], seen[0]["header"]["alg"], seen[0]["jkt"]]
    refute seen[0]["header"]["jwk"].key?("d")
    assert_equal ["POST", "#{local}/idp/token"], seen[0]["payload"].values_at("htm", "htu")
    assert_equal ["#{local}/rs/token", key.thumbprint], [seen[1]["payload"]["htu"], seen[1]["jkt"]]
    refute_equal seen[0]["payload"]["jti"], seen[1]["payload"]["jti"]

    # An identity provider that ignores DPoP answers with a bearer ID-JAG: dpop_bound false.
    plain_jag = Touchque::CrossAppAccess.request_id_jag(issuer: "#{api.base_url}/idp", client_id: "tqapp_test", client_secret: "tqs_test",
                                                        id_token: "idtoken:ada", audience: "https://rs.example",
                                                        dpop_key: Touchque::CrossAppAccess.create_id_jag_dpop_key)
    assert_equal false, plain_jag["dpop_bound"]

    # The verifier: a bound ID-JAG needs the proof key's thumbprint, refused before it is used up.
    v = verifier
    mint = ->(claims) { api.post("/__test/id-jag", { claims: claims })["assertion"] }
    bound = mint.call({ cnf: { jkt: "right-key-thumbprint" } })
    assert_equal "bound to a DPoP key: a DPoP proof with that key is required", reason { v.verify(bound, client_id: "acme-at-rs") }
    assert_equal "the DPoP proof was made with another key", reason { v.verify(bound, client_id: "acme-at-rs", dpop_jkt: "other-key") }
    assert_equal "right-key-thumbprint", v.verify(bound, client_id: "acme-at-rs", dpop_jkt: "right-key-thumbprint")["cnf_jkt"]
    odd = mint.call({ cnf: { x5t: "abc" } })
    assert_equal "unsupported confirmation method (only DPoP cnf.jkt)", reason { v.verify(odd, client_id: "acme-at-rs", dpop_jkt: "x") }
    # Unbound: as before, with or without a proof key.
    assert_nil v.verify(mint.call({}), client_id: "acme-at-rs", dpop_jkt: "any")["cnf_jkt"]
  ensure
    thread&.kill
    server&.close
  end

  def code
    yield
    "verified"
  rescue Touchque::AgentCardError => e
    e.error
  end

  def test_agent_cards
    url = "#{api.base_url}/.well-known/agent-card.json"
    card = Net::HTTP.get(URI(url)).force_encoding("UTF-8")
    assert_equal({ "kid" => "a2a-1", "alg" => "ES256", "key_source" => "jku" }, Touchque::AgentCard.verify(card, card_url: url))
    tampered = Net::HTTP.get(URI("#{url}?tamper=1")).force_encoding("UTF-8")
    assert_equal "invalid_signature", code { Touchque::AgentCard.verify(tampered, card_url: url) }
    assert_equal "untrusted_key", code { Touchque::AgentCard.verify(card, card_url: "https://agent.example/.well-known/agent-card.json") }
    assert_equal "unsigned", code { Touchque::AgentCard.verify('{"name":"x"}') }

    keys = Touchque::AgentKeys.generate("EdDSA")
    signed = Touchque::AgentCard.sign('{"name":"Mine","url":"https://mine.example/a2a","skills":[]}', keys["privateJwk"], kid: "k1")
    jwk = keys["publicJwk"].merge("kid" => "k1")
    assert_equal({ "kid" => "k1", "alg" => "EdDSA", "key_source" => "keys" }, Touchque::AgentCard.verify(signed, keys: [jwk]))
    assert_equal "invalid_signature", code { Touchque::AgentCard.verify(signed.sub("mine.example", "evil.example"), keys: [jwk]) }

    value = JSON.parse('{"€":"Euro","\r":"CR","😀":"smile","1":"one","a":[1e21,1e-7,0.5,-0,"tab\there",1e-5,100.0]}')
    assert_equal '{"\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\there",0.00001,100],"€":"Euro","😀":"smile"}', Touchque::AgentCard.canonical_json(value)
  end
end

# The ID-JAG DPoP proof (RFC 9449: htm, htu, jwk, ath, nonce) and the token endpoints' one retry
# with a server nonce (section 8), against token endpoints on this machine.
class IdJagDpopTest < Minitest::Test
  NONCE = "eyJ7S_zG.eyJH0-Z.HX4w-7v" # RFC 9449 section 8
  URL = "https://resource.example.org/protectedresource"

  def key
    @key ||= Touchque::CrossAppAccess.create_id_jag_dpop_key
  end

  def proof(url = URL, **options)
    Touchque::CrossAppAccess.id_jag_dpop_proof(key, url, **options)
  end

  def payload_of(proof)
    Touchque::JWS.split(proof)[1]
  end

  def ath_of(token)
    [OpenSSL::Digest::SHA256.digest(token)].pack("m0").tr("+/", "-_").delete("=")
  end

  # Each recorded request's DPoP proof: [header, claims, signing input, signature].
  def proofs(requests)
    requests.map { |r| Touchque::JWS.split(r["headers"]["dpop"]) }
  end

  def redeem(url, **options)
    Touchque::CrossAppAccess.redeem_id_jag(token_endpoint: url, client_id: "acme", assertion: "the.id.jag", **options)
  end

  # An answer as Net::HTTP gives it, with these header lines ([name, value] pairs).
  def http_answer(status, *lines)
    res = Net::HTTPResponse::CODE_TO_OBJ[status.to_s].new("1.1", status.to_s, "Answer")
    lines.each { |name, value| res.add_field(name, value) }
    res
  end

  # The block's result; fails when the block took a second or more.
  def within_a_second
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = yield
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
    assert_operator elapsed, :<, 1.0, "took #{elapsed.round(3)} s"
    result
  end

  # A token endpoint on 127.0.0.1 that records every request ({"path", "headers", "body"}) and
  # answers the n-th one with reply.call(n): [status, header lines (a Hash or [name, value] pairs,
  # any bytes), JSON body].
  def with_token_endpoint(reply)
    server = TCPServer.new("127.0.0.1", 0)
    requests = []
    thread = Thread.new do
      loop do
        conn = server.accept
        path = conn.gets.to_s.split[1]
        headers = {}
        while (line = conn.gets) && line != "\r\n"
          name, value = line.split(":", 2)
          headers[name.strip.downcase] = value.to_s.strip
        end
        requests << { "path" => path, "headers" => headers, "body" => conn.read(headers["content-length"].to_i) }
        status, extra, out = reply.call(requests.length)
        text = JSON.generate(out)
        conn.write("HTTP/1.1 #{status} Answer\r\n", *extra.map { |k, v| "#{k}: ".b + v.to_s.b + "\r\n".b },
                   "Content-Type: application/json\r\nContent-Length: #{text.bytesize}\r\nConnection: close\r\n\r\n", text)
        conn.close
      end
    end
    yield "http://127.0.0.1:#{server.addr[1]}/token", requests
  ensure
    thread&.kill
    server&.close
  end

  def test_proof_shape_with_the_old_call_form
    url = "https://sso.touchque.com/sso/token?x=1#f"
    header, payload, input, sig = Touchque::JWS.split(Touchque::CrossAppAccess.id_jag_dpop_proof(key, url))
    assert_equal ["dpop+jwt", "ES256", key.public_jwk], header.values_at("typ", "alg", "jwk")
    assert_equal %w[kty crv x y], header["jwk"].keys
    assert_equal [32, 32], header["jwk"].values_at("x", "y").map { |v| Touchque::Util.b64url_decode(v).bytesize }
    assert_equal 64, sig.bytesize
    assert Touchque::JWS.verify("ES256", header["jwk"], input, sig)
    assert_equal key.thumbprint, Touchque::AgentKeys.thumbprint(header["jwk"])
    assert_equal %w[htm htu iat jti], payload.keys.sort
    assert_equal ["POST", "https://sso.touchque.com/sso/token"], payload.values_at("htm", "htu")
    assert_kind_of Integer, payload["iat"]
    assert_in_delta Time.now.to_i, payload["iat"], 5
    refute_equal payload["jti"], payload_of(Touchque::CrossAppAccess.id_jag_dpop_proof(key, url))["jti"]
  end

  def test_proof_method_access_token_and_nonce
    # RFC 9449 section 7.1: the example access token and its ath.
    get = payload_of(proof(method: "get", access_token: "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"))
    assert_equal ["GET", URL, "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"], get.values_at("htm", "htu", "ath")
    refute get.key?("nonce")
    token = "at.#{SecureRandom.hex(24)}"
    delete = payload_of(proof(method: :delete, access_token: token))
    assert_equal ["DELETE", ath_of(token)], delete.values_at("htm", "ath")
    with_nonce = payload_of(proof(nonce: NONCE))
    assert_equal ["POST", NONCE], with_nonce.values_at("htm", "nonce")
    refute with_nonce.key?("ath")
    all = payload_of(proof("#{URL}?page=2", method: "Put", access_token: token, nonce: "n-1"))
    assert_equal ["PUT", URL, ath_of(token), "n-1"], all.values_at("htm", "htu", "ath", "nonce")
    # nil or empty: as if left out.
    plain = payload_of(proof(method: nil, access_token: "", nonce: ""))
    assert_equal [%w[htm htu iat jti], "POST"], [plain.keys.sort, plain["htm"]]
  end

  def test_proof_method_is_trimmed_upper_cased_and_a_token
    { " get " => "GET", "\tdelete\r\n" => "DELETE", "   " => "POST", "\n" => "POST", "m-search" => "M-SEARCH", :propfind => "PROPFIND" }.each do |method, htm|
      assert_equal htm, payload_of(proof(method: method))["htm"], method.inspect
    end
    ["GET /x", "GE T", "GÉT", "GET\r\nX-Evil: 1", "(GET)", "GET,POST", "get ", "\xff".b, "{}"].each do |method|
      assert_raises(Touchque::ConfigError, method.inspect) { proof(method: method) }
    end
  end

  def test_proof_nonce_is_dpop_nonce_syntax
    every = [0x21, *0x23..0x5B, *0x5D..0x7E].pack("C*") # each NQCHAR once
    assert_equal every, payload_of(proof(nonce: every))["nonce"]
    ["a b", %(a"b), "a\\b", "nönce", "\xff".b, "a\tb", "\x7f"].each do |nonce|
      assert_raises(Touchque::ConfigError, nonce.inspect) { proof(nonce: nonce) }
    end
  end

  def test_the_proof_jwk_is_rebuilt_from_the_public_key
    full = Touchque::AgentKeys.generate("ES256")["privateJwk"] # d, kid and alg too
    signer = Touchque::SigningKey.load(full, "test")
    leaky = Object.new
    leaky.define_singleton_method(:public_jwk) { full.transform_keys(&:to_sym).merge(use: "sig", key_ops: ["sign"]) }
    leaky.define_singleton_method(:jws) { |header, payload| signer.jws(header, payload) }
    header, _, input, sig = Touchque::JWS.split(Touchque::CrossAppAccess.id_jag_dpop_proof(leaky, URL))
    assert_equal({ "kty" => "EC", "crv" => "P-256", "x" => full["x"], "y" => full["y"] }, header["jwk"])
    assert_equal %w[kty crv x y], header["jwk"].keys
    assert Touchque::JWS.verify("ES256", header["jwk"], input, sig)
    ed25519 = Touchque::IdJagDpopKey.new(Touchque::SigningKey.load(Touchque::AgentKeys.generate("EdDSA")["privateJwk"], "test"))
    [nil, "a key", ed25519].each do |not_p256|
      assert_raises(Touchque::ConfigError, not_p256.inspect) { Touchque::CrossAppAccess.id_jag_dpop_proof(not_p256, URL) }
    end
  end

  def test_htu_from_the_url
    {
      "HTTPS://API.Example.com:443/v1/files?x=1" => "https://api.example.com/v1/files",
      "https://sso.touchque.com/sso/token?x=1#f" => "https://sso.touchque.com/sso/token",
      "https://token.example" => "https://token.example/",
      "https://Token.Example?x=1#f" => "https://token.example/",
      "http://LOCALHOST:80/Token" => "http://localhost/Token",
      "https://auth.example:0443/x" => "https://auth.example/x",
      "https://auth.example:8443/a%2fb/%7Euser/" => "https://auth.example:8443/a%2fb/%7Euser/",
      # The path as given: no dot-segment removal.
      "https://auth.example/a/./b/../token?x=1" => "https://auth.example/a/./b/../token",
      "http://127.0.0.1:8080" => "http://127.0.0.1:8080/",
      "http://[::1]:443/x" => "http://[::1]:443/x",
      "https://user:pass@host.example/x" => "https://host.example/x"
    }.each do |url, htu|
      assert_equal htu, payload_of(Touchque::CrossAppAccess.id_jag_dpop_proof(key, url))["htu"], url
    end
    ["/token", "token.example/token", "ftp://host.example/x", "https://exa mple.com/", "http:///x", "https://host.example/ü", nil].each do |url|
      assert_raises(Touchque::ConfigError, url.inspect) { Touchque::CrossAppAccess.id_jag_dpop_proof(key, url) }
    end
  end

  def test_the_proof_and_token_endpoint_helpers_are_private
    %i[dpop_htu dpop_nonce_of use_dpop_nonce? dpop_jwk dpop_htm nonce_value token_request header_values dpop_nonce_challenge?].each do |name|
      refute_respond_to Touchque::CrossAppAccess, name
      assert_includes Touchque::CrossAppAccess.private_methods, name
    end
    %i[create_id_jag_dpop_key id_jag_dpop_proof request_id_jag redeem_id_jag].each { |name| assert_respond_to Touchque::CrossAppAccess, name }
  end

  def test_redeem_retries_once_with_the_servers_nonce
    reply = lambda do |n|
      if n == 1
        [400, { "DPoP-Nonce" => NONCE }, { "error" => "use_dpop_nonce", "error_description" => "Authorization server requires nonce in DPoP proof" }]
      else
        [200, {}, { "access_token" => "at", "token_type" => "DPoP", "expires_in" => 300 }]
      end
    end
    with_token_endpoint(reply) do |url, requests|
      tokens = redeem(url, client_secret: "s3cret", scope: %w[files:read], dpop_key: key)
      assert_equal ["at", "DPoP"], tokens.values_at("access_token", "token_type")
      assert_equal 2, requests.length
      first, second = requests
      assert_equal [first["body"], first["headers"]["authorization"]], [second["body"], second["headers"]["authorization"]]
      assert_equal "Basic #{["acme:s3cret"].pack("m0")}", second["headers"]["authorization"]
      assert_equal({ "grant_type" => Touchque::CrossAppAccess::JWT_BEARER_GRANT, "assertion" => "the.id.jag", "scope" => "files:read" },
                   URI.decode_www_form(second["body"]).to_h)
      (h1, p1, i1, s1), (h2, p2, i2, s2) = proofs(requests)
      assert_nil p1["nonce"]
      assert_equal NONCE, p2["nonce"]
      refute_equal p1["jti"], p2["jti"]
      assert_kind_of Integer, p2["iat"]
      assert_equal [["POST", url], ["POST", url]], [p1, p2].map { |p| p.values_at("htm", "htu") }
      assert Touchque::JWS.verify("ES256", h1["jwk"], i1, s1)
      assert Touchque::JWS.verify("ES256", h2["jwk"], i2, s2)
      assert_equal [key.thumbprint] * 2, [h1, h2].map { |h| Touchque::AgentKeys.thumbprint(h["jwk"]) }
    end
  end

  def test_request_id_jag_retries_once_on_a_dpop_challenge
    reply = lambda do |n|
      if n == 1
        [401, { "WWW-Authenticate" => %(DPoP algs="ES256", error="use_dpop_nonce", error_description="nonce required"), "DPoP-Nonce" => NONCE }, {}]
      else
        jag = "#{Touchque::Util.b64url('{"typ":"oauth-id-jag+jwt","alg":"ES256"}')}.#{Touchque::Util.b64url(JSON.generate("cnf" => { "jkt" => key.thumbprint }))}.sig"
        [200, {}, { "access_token" => jag, "issued_token_type" => Touchque::CrossAppAccess::ID_JAG_TOKEN_TYPE, "token_type" => "N_A" }]
      end
    end
    with_token_endpoint(reply) do |url, requests|
      got = Touchque::CrossAppAccess.request_id_jag(token_endpoint: url, client_id: "tqapp_test", client_secret: "tqs_test", id_token: "idtoken:ada",
                                                    audience: "https://rs.example", dpop_key: key)
      assert_equal true, got["dpop_bound"]
      assert_equal 2, requests.length
      first, second = requests
      assert_equal [first["body"], first["headers"]["authorization"]], [second["body"], second["headers"]["authorization"]]
      assert_equal ["idtoken:ada", "https://rs.example"], URI.decode_www_form(second["body"]).to_h.values_at("subject_token", "audience")
      assert_equal "Basic #{["tqapp_test:tqs_test"].pack("m0")}", second["headers"]["authorization"]
      assert_equal [nil, NONCE], proofs(requests).map { |p| p[1]["nonce"] }
      refute_equal(*proofs(requests).map { |p| p[1]["jti"] })
    end
  end

  def test_no_retry_without_a_key_and_the_nonce_is_on_the_error
    with_token_endpoint(->(_) { [400, { "DPoP-Nonce" => NONCE }, { "error" => "use_dpop_nonce" }] }) do |url, requests|
      err = assert_raises(Touchque::IdJagError) { redeem(url) }
      assert_equal ["use_dpop_nonce", 400, NONCE], [err.error, err.status, err.dpop_nonce]
      assert_equal 1, requests.length
      refute requests[0]["headers"].key?("dpop")
    end
  end

  def test_a_second_nonce_request_is_not_retried
    reply = ->(n) { [400, { "DPoP-Nonce" => "nonce-#{n}" }, { "error" => "use_dpop_nonce", "error_description" => "use the new nonce" }] }
    with_token_endpoint(reply) do |url, requests|
      err = assert_raises(Touchque::IdJagError) { redeem(url, dpop_key: key) }
      assert_equal ["use_dpop_nonce", 400, "nonce-2", "use the new nonce"], [err.error, err.status, err.dpop_nonce, err.message]
      assert_equal 2, requests.length
      assert_equal [nil, "nonce-1"], proofs(requests).map { |p| p[1]["nonce"] }
      # A public client: client_id in the form, sent again as it was.
      assert_equal requests[0]["body"], requests[1]["body"]
      assert_equal "acme", URI.decode_www_form(requests[1]["body"]).to_h["client_id"]
      refute requests[1]["headers"].key?("authorization")
    end
  end

  def test_the_error_keeps_the_latest_valid_nonce
    first = [400, { "DPoP-Nonce" => NONCE }, { "error" => "use_dpop_nonce" }]
    {
      # The retry's answer names none, an invalid one or two different ones: the first answer's.
      [400, {}, { "error" => "invalid_grant" }] => NONCE,
      [400, { "DPoP-Nonce" => "not valid" }, { "error" => "invalid_grant" }] => NONCE,
      [400, [["DPoP-Nonce", "n-2"], ["DPoP-Nonce", "n-3"]], { "error" => "invalid_grant" }] => NONCE,
      # It names a valid one: that one.
      [401, { "DPoP-Nonce" => "n-2" }, { "error" => "invalid_client" }] => "n-2"
    }.each do |second, nonce|
      with_token_endpoint(->(n) { n == 1 ? first : second }) do |url, requests|
        err = assert_raises(Touchque::IdJagError) { redeem(url, dpop_key: key) }
        assert_equal [2, second[0], second[2]["error"], nonce], [requests.length, err.status, err.error, err.dpop_nonce], second.inspect
      end
    end
    # An identity provider that answers the retry with no ID-JAG: the error still names the nonce.
    with_token_endpoint(->(n) { n == 1 ? first : [200, {}, { "access_token" => "opaque" }] }) do |url, requests|
      err = assert_raises(Touchque::IdJagError) do
        Touchque::CrossAppAccess.request_id_jag(token_endpoint: url, client_id: "tqapp_test", client_secret: "tqs_test", id_token: "idtoken:ada",
                                                audience: "https://rs.example", dpop_key: key)
      end
      assert_equal ["invalid_response", nil, NONCE, 2], [err.error, err.status, err.dpop_nonce, requests.length]
    end
  end

  def test_only_one_valid_nonce_is_retried
    # Missing, empty, not 1*NQCHAR, or repeated with different values: no retry, no nonce on the error.
    [
      {},
      { "DPoP-Nonce" => "" },
      { "DPoP-Nonce" => "two words" },
      { "DPoP-Nonce" => %(say"hi") },
      { "DPoP-Nonce" => "back\\slash" },
      { "DPoP-Nonce" => "nönce" },
      { "DPoP-Nonce" => "\xff\xfe".b },
      { "DPoP-Nonce" => "tab\there" },
      { "DPoP-Nonce" => "del\x7f" },
      [["DPoP-Nonce", "n-1"], ["DPoP-Nonce", "n-2"]]
    ].each do |lines|
      with_token_endpoint(->(_) { [400, lines, { "error" => "use_dpop_nonce" }] }) do |url, requests|
        err = assert_raises(Touchque::IdJagError, lines.inspect) { redeem(url, dpop_key: key) }
        assert_equal [1, "use_dpop_nonce", 400, nil], [requests.length, err.error, err.status, err.dpop_nonce], lines.inspect
      end
    end
    # One value, even sent twice, of NQCHARs only: retried with it as it is.
    every = [0x21, *0x23..0x5B, *0x5D..0x7E].pack("C*")
    [[["DPoP-Nonce", every]], [["DPoP-Nonce", NONCE], ["DPoP-Nonce", NONCE]]].each do |lines|
      reply = ->(n) { n == 1 ? [400, lines, { "error" => "use_dpop_nonce" }] : [200, {}, { "access_token" => "at" }] }
      with_token_endpoint(reply) do |url, requests|
        assert_equal "at", redeem(url, dpop_key: key)["access_token"]
        assert_equal [nil, lines[0][1]], proofs(requests).map { |p| p[1]["nonce"] }
      end
    end
  end

  def test_only_a_nonce_request_that_names_a_nonce_is_retried
    [
      [400, { "DPoP-Nonce" => NONCE }, { "error" => "invalid_grant" }, NONCE],
      [400, {}, { "error" => "use_dpop_nonce" }, nil],
      [403, { "DPoP-Nonce" => NONCE }, { "error" => "use_dpop_nonce" }, NONCE],
      [500, { "DPoP-Nonce" => NONCE }, {}, NONCE],
      [400, { "WWW-Authenticate" => %(DPoP error="use_dpop_nonce"), "DPoP-Nonce" => NONCE }, {}, NONCE],
      [401, { "WWW-Authenticate" => %(Bearer error="use_dpop_nonce"), "DPoP-Nonce" => NONCE }, {}, NONCE],
      [401, { "WWW-Authenticate" => %(Bearer error="use_dpop_nonce", DPoP algs="ES256"), "DPoP-Nonce" => NONCE }, {}, NONCE],
      [401, { "WWW-Authenticate" => %(DPoP error="invalid_dpop_proof"), "DPoP-Nonce" => NONCE }, {}, NONCE]
    ].each do |status, headers, body, nonce|
      with_token_endpoint(->(_) { [status, headers, body] }) do |url, requests|
        err = assert_raises(Touchque::IdJagError) { redeem(url, dpop_key: key) }
        assert_equal [1, status, nonce], [requests.length, err.status, err.dpop_nonce], [status, headers, body].inspect
      end
    end
  end

  def test_which_answers_ask_for_a_nonce
    asks = ->(status, data, *lines) { Touchque::CrossAppAccess.send(:use_dpop_nonce?, status, data, http_answer(status, *lines)) }
    challenge = ->(text) { ["WWW-Authenticate", text] }
    assert asks.call(400, { "error" => "use_dpop_nonce" })
    assert asks.call(401, { "error" => "use_dpop_nonce" })
    refute asks.call(403, { "error" => "use_dpop_nonce" })
    refute asks.call(400, {}, challenge.call(%(DPoP error="use_dpop_nonce")))
    {
      %(DPoP error="use_dpop_nonce") => true,
      %(Bearer realm="files", DPoP algs="ES256", error="use_dpop_nonce") => true,
      "dpop error=use_dpop_nonce" => true,
      %(DPoP error = "use_dpop_nonce") => true,
      %(DPoP realm="say \\"hi\\", please", error="use_dpop_nonce") => true,
      %(Basic dGVzdA==, Negotiate abc, DPoP error="use_dpop_nonce") => true,
      %(Bearer error="use_dpop_nonce", DPoP algs="ES256") => false, # Bearer's error
      %(Bearer realm="a, DPoP error=use_dpop_nonce") => false, # inside a quoted string
      %(DPoP error="use_dpop_nonce_later") => false,
      %(DPoP error_description="use_dpop_nonce") => false,
      %(DPoP error="use_dpop_nonce) => false, # no closing quote
      %(DPoPX error="use_dpop_nonce") => false,
      "" => false,
      "\xff\xfe DPoP".b => false
    }.each do |text, want|
      assert_equal want, asks.call(401, {}, challenge.call(text)), text.inspect
    end
    # Each WWW-Authenticate line on its own.
    assert asks.call(401, {}, challenge.call(%(Bearer realm="files")), challenge.call(%(DPoP error="use_dpop_nonce")))
  end

  def test_which_nonces_are_valid
    nonce = ->(*values) { Touchque::CrossAppAccess.send(:dpop_nonce_of, http_answer(400, *values.map { |v| ["DPoP-Nonce", v] })) }
    assert_equal [NONCE, Encoding::UTF_8], [nonce.call(NONCE), nonce.call(NONCE).encoding]
    assert_equal NONCE, nonce.call(NONCE, NONCE)
    assert_nil nonce.call
    assert_nil nonce.call(NONCE, "n-2")
    ["", " ", "a b", %(a"b), "a\\b", "é", "\xff".b, "\x00", "\x7f"].each { |v| assert_nil nonce.call(v), v.inspect }
    assert_nil Touchque::IdJagError.new("invalid_grant", "expired", 400).dpop_nonce
  end

  def test_a_64_kb_challenge_is_read_in_linear_time
    asking = %(DPoP realm="#{"a" * 65_536}", error="use_dpop_nonce")
    [[%(DPoP realm="#{"a" * 65_536}"), 1], ["DPoP #{"a," * 30_000}", 1], [asking, 2]].each do |challenge, tries|
      # A 200 without a key: the answer as it is.
      with_token_endpoint(->(_) { [200, { "WWW-Authenticate" => challenge }, { "access_token" => "at" }] }) do |url, _|
        assert_equal "at", within_a_second { redeem(url) }["access_token"]
      end
      # A 401 with a key and a nonce: the refusal, after the one retry when the challenge asks for the nonce.
      refused = ->(_) { [401, { "WWW-Authenticate" => challenge, "DPoP-Nonce" => NONCE }, { "error" => "invalid_token" }] }
      with_token_endpoint(refused) do |url, requests|
        err = within_a_second { assert_raises(Touchque::IdJagError) { redeem(url, dpop_key: key) } }
        assert_equal [401, "invalid_token", NONCE, tries], [err.status, err.error, err.dpop_nonce, requests.length]
      end
    end
    # The challenge parser alone, on half a megabyte of shapes that make backtracking parsers slow.
    n = 524_288
    realms = 'realm="x", ' * (n / 12)
    {
      "DPoP #{"a," * (n / 2)}" => false,
      "DPoP #{"a=b, " * (n / 5)}" => false,
      "DPoP realm=\"#{"\\a" * (n / 2)}" => false,
      "DPoP realm=\"#{" " * n}\" x" => false,
      "," * n => false,
      "DPoP #{"error " * (n / 6)}" => false,
      "Bearer #{realms}DPoP error=\"use_dpop_nonce\"" => true
    }.each do |text, want|
      assert_equal want, within_a_second { Touchque::CrossAppAccess.send(:use_dpop_nonce?, 401, {}, http_answer(401, ["WWW-Authenticate", text])) }
    end
  end
end
