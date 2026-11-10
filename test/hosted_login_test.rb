# frozen_string_literal: true

require "test_helper"

# An in-process fake TouchQue Login tenant: JWKS, /oauth/token with PKCE, /bc-authorize, My Account.
class FakeTenant
  ISSUER = "https://acme.login.touchque.com"
  CLIENT = "client-123"

  attr_accessor :sign_with, :nonce_override, :polls
  attr_reader :posts, :key

  def initialize
    @key = OpenSSL::PKey::RSA.new(2048)
    @codes = {}
    @posts = []
    @polls = 0
  end

  def jwt(payload, typ = "JWT", key = nil)
    input = "#{TouchQue::Util.b64url(JSON.generate({ alg: "RS256", typ: typ, kid: "k1" }))}.#{TouchQue::Util.b64url(JSON.generate(payload))}"
    "#{input}.#{TouchQue::Util.b64url((key || @key).sign(OpenSSL::Digest.new("SHA256"), input))}"
  end

  def authorize(url)
    q = TouchQue::HostedLogin.params_of(url)
    code = "code-#{@codes.size}"
    @codes[code] = [q["code_challenge"], q["nonce"]]
    [code, q["state"]]
  end

  def transport
    lambda do |method, url, headers, body|
      path = URI.parse(url).path
      if path == "/.well-known/jwks.json"
        n = TouchQue::Util.b64url(@key.n.to_s(2))
        e = TouchQue::Util.b64url(@key.e.to_s(2))
        next [200, JSON.generate({ keys: [{ kty: "RSA", kid: "k1", use: "sig", n: n, e: e }] })]
      end
      f = body ? URI.decode_www_form(body).to_h : {}
      @posts << { path: path, fields: f, headers: headers } if method == "POST"
      next [200, JSON.generate({ auth_req_id: "req-1", expires_in: 300, interval: 0, binding_code: "42" })] if path == "/bc-authorize"
      next [200, JSON.generate({ profile: JSON.parse(body) })] if path == "/me/v1/profile"
      next [401, JSON.generate({ error: "insufficient_user_authentication", error_description: "Sign in again", max_age: 0 })] if path == "/me/v1/password"
      next [204, ""] if path == "/me/v1/sessions/s1"
      next [404, "{}"] unless path == "/oauth/token"

      now = Time.now.to_i
      case f["grant_type"]
      when "authorization_code"
        challenge, nonce = @codes[f["code"]]
        next [400, JSON.generate({ error: "invalid_grant" })] unless challenge == TouchQue::Util.b64url(TouchQue::Util.sha256(f["code_verifier"]))

        at = jwt({ iss: ISSUER, sub: "usr_1", aud: ["https://api.acme.test"], exp: now + 300, iat: now, client_id: CLIENT, scope: "openid read:orders" }, "at+jwt")
        id = jwt({ iss: ISSUER, sub: "usr_1", aud: CLIENT, exp: now + 300, iat: now, nonce: @nonce_override || nonce, email: "a@acme.test",
                   at_hash: TouchQue::Util.b64url(TouchQue::Util.sha256(at)[0, 16]) }, "JWT", @sign_with)
        [200, JSON.generate({ access_token: at, token_type: "Bearer", expires_in: 300, scope: "openid", id_token: id, refresh_token: "tqr_1" })]
      when "refresh_token"
        [200, JSON.generate({ access_token: "x", token_type: "Bearer", expires_in: 300, refresh_token: "tqr_2" })]
      when "urn:ietf:params:oauth:grant-type:token-exchange"
        if f["requested_token_type"] == TouchQue::HostedLogin::CONNECTION_TOKEN_TYPE
          [200, JSON.generate({ access_token: "ya29.g", token_type: "Bearer", expires_in: 3500, scope: "openid email", connection: f["connection"] })]
        else
          [200, JSON.generate({ access_token: "at-x", token_type: "Bearer", expires_in: 120, issued_token_type: "urn:ietf:params:oauth:token-type:access_token" })]
        end
      when "urn:openid:params:grant-type:ciba"
        @polls += 1
        next [400, JSON.generate({ error: "authorization_pending" })] if @polls == 1
        next [400, JSON.generate({ error: "access_denied" })] if f["auth_req_id"] == "denied"

        [200, JSON.generate({ access_token: "at-c", token_type: "Bearer", expires_in: 300, authorization_details: [{ type: "payment_initiation" }] })]
      else
        [400, JSON.generate({ error: "unsupported_grant_type" })]
      end
    end
  end
end

class HostedLoginTest < Minitest::Test
  def setup
    @tenant = FakeTenant.new
  end

  def login(secret = nil)
    TouchQue::HostedLogin.new(domain: FakeTenant::ISSUER, client_id: FakeTenant::CLIENT, client_secret: secret, redirect_uri: "https://app/cb", transport: @tenant.transport)
  end

  def test_authorization_url
    req = TouchQue::HostedLogin.new(domain: "acme.login.touchque.com", client_id: FakeTenant::CLIENT, redirect_uri: "https://app/cb", audience: "https://api.acme.test")
                               .authorization_url(screen_hint: "signup")
    q = TouchQue::HostedLogin.params_of(req["url"])
    assert req["url"].start_with?("#{FakeTenant::ISSUER}/authorize?")
    assert_equal TouchQue::Util.b64url(TouchQue::Util.sha256(req["codeVerifier"])), q["code_challenge"]
    assert_equal ["S256", req["state"], "signup", "https://api.acme.test"], q.values_at("code_challenge_method", "state", "screen_hint", "audience")
  end

  def test_callback_refresh_and_access_token
    l = login("s3cret")
    req = l.authorization_url
    code, state = @tenant.authorize(req["url"])
    tokens = l.handle_callback("https://app/cb?code=#{code}&state=#{TouchQue::Util.seg(state)}&iss=#{TouchQue::Util.seg(FakeTenant::ISSUER)}",
                               state: req["state"], nonce: req["nonce"], code_verifier: req["codeVerifier"])
    assert_equal %w[usr_1 tqr_1], [tokens["claims"]["sub"], tokens["refreshToken"]]
    assert_equal "Basic #{["#{FakeTenant::CLIENT}:s3cret"].pack("m0")}", @tenant.posts[0][:headers]["Authorization"]
    assert_equal "tqr_2", l.refresh("tqr_1")["refreshToken"]
    assert_equal "usr_1", l.verify_access_token(tokens["accessToken"], audience: "https://api.acme.test", required_scopes: ["read:orders"])["sub"]
    assert_equal "insufficient_scope", assert_raises(TouchQue::HostedLoginError) { l.verify_access_token(tokens["accessToken"], audience: "https://api.acme.test", required_scopes: ["write:orders"]) }.error_code
    assert_raises(TouchQue::HostedLoginError) { l.verify_access_token(tokens["idToken"], audience: FakeTenant::CLIENT) }
  end

  def test_refusals
    l = login
    req = l.authorization_url
    code, state = @tenant.authorize(req["url"])
    checks = { state: req["state"], nonce: req["nonce"], code_verifier: req["codeVerifier"] }
    [[{ "code" => code, "state" => "x" }, "state_mismatch"], [{ "error" => "access_denied", "state" => state }, "access_denied"],
     [{ "code" => code, "state" => state, "iss" => "https://evil" }, "issuer_mismatch"]].each do |params, want|
      assert_equal want, assert_raises(TouchQue::HostedLoginError) { l.handle_callback(params, **checks) }.error_code
    end
    @tenant.nonce_override = "replayed"
    req2 = l.authorization_url
    code2, state2 = @tenant.authorize(req2["url"])
    assert_equal "nonce_mismatch", assert_raises(TouchQue::HostedLoginError) {
      l.handle_callback({ "code" => code2, "state" => state2 }, state: req2["state"], nonce: req2["nonce"], code_verifier: req2["codeVerifier"])
    }.error_code
    @tenant.nonce_override = nil
    @tenant.sign_with = OpenSSL::PKey::RSA.new(2048)
    req3 = l.authorization_url
    code3, state3 = @tenant.authorize(req3["url"])
    assert_match(/Bad signature/, assert_raises(TouchQue::HostedLoginError) {
      l.handle_callback({ "code" => code3, "state" => state3 }, state: req3["state"], nonce: req3["nonce"], code_verifier: req3["codeVerifier"])
    }.message)
  end

  def test_iss_this_issuer_or_none_is_accepted_a_foreign_or_empty_one_is_refused_before_the_exchange
    l = login
    req = l.authorization_url
    code, state = @tenant.authorize(req["url"])
    checks = { state: req["state"], nonce: req["nonce"], code_verifier: req["codeVerifier"] }
    ["https://evil", "#{FakeTenant::ISSUER}.evil", "#{FakeTenant::ISSUER}/", ""].each do |iss|
      assert_equal "issuer_mismatch", assert_raises(TouchQue::HostedLoginError) { l.handle_callback({ "code" => code, "state" => state, "iss" => iss }, **checks) }.error_code, iss
    end
    assert_equal "issuer_mismatch", assert_raises(TouchQue::HostedLoginError) {
      l.handle_callback("https://app/cb?code=#{code}&state=#{TouchQue::Util.seg(state)}&iss=", **checks)
    }.error_code
    # A foreign error answer is reported as the issuer mismatch, not as its own error.
    assert_equal "issuer_mismatch", assert_raises(TouchQue::HostedLoginError) {
      l.handle_callback({ "error" => "access_denied", "state" => state, "iss" => "https://evil" }, **checks)
    }.error_code
    assert_empty @tenant.posts
    assert_equal "usr_1", l.handle_callback({ code: code, state: state, iss: FakeTenant::ISSUER }, **checks)["claims"]["sub"]

    # No iss (an older server): no field in the URL, or a nil value for a missing field.
    req2 = l.authorization_url
    code2, state2 = @tenant.authorize(req2["url"])
    tokens = l.handle_callback({ "code" => code2, "state" => state2, "iss" => nil }, state: req2["state"], nonce: req2["nonce"], code_verifier: req2["codeVerifier"])
    assert_equal "usr_1", tokens["claims"]["sub"]
    req3 = l.authorization_url
    code3, state3 = @tenant.authorize(req3["url"])
    tokens = l.handle_callback("https://app/cb?code=#{code3}&state=#{TouchQue::Util.seg(state3)}", state: req3["state"], nonce: req3["nonce"], code_verifier: req3["codeVerifier"])
    assert_equal "usr_1", tokens["claims"]["sub"]
  end

  def test_exchange_token_ciba_and_token_vault
    l = login("s3cret")
    ex = l.exchange_token("user-at", "https://api.acme.test", scope: "payments:create")
    assert_equal ["at-x", "urn:ietf:params:oauth:token-type:access_token"], [ex["accessToken"], ex["issuedTokenType"]]
    assert_equal "user-at", @tenant.posts[0][:fields]["subject_token"]
    ask = l.ask_user("ada@acme.test", "openid payments:create", binding_message: "Pay invoice 42", authorization_details: [{ type: "payment_initiation" }])
    assert_equal %w[req-1 42], [ask["authReqId"], ask["bindingCode"]]
    assert_equal [{ "type" => "payment_initiation" }], JSON.parse(@tenant.posts[1][:fields]["authorization_details"])
    assert_equal [{ "type" => "payment_initiation" }], l.wait_for_user(ask)["authorizationDetails"]
    @tenant.polls = 0
    assert_equal "access_denied", assert_raises(TouchQue::HostedLoginError) { l.wait_for_user(ask.merge("authReqId" => "denied")) }.error_code
    vaulted = l.get_connection_token("user-at", "google", scope: "email")
    assert_equal %w[ya29.g google], [vaulted["accessToken"], vaulted["connection"]]
    last = @tenant.posts.last[:fields]
    assert_equal "email", last["scope"]
    refute last.key?("audience")
  end

  def test_my_account
    account = login.my_account("at-me")
    assert_equal({ "name" => "Ada", "userMetadata" => { "theme" => nil } }, account.update_profile({ name: "Ada", userMetadata: { theme: nil } })["profile"])
    assert_nil account.end_session("s1")
    e = assert_raises(TouchQue::MyAccountError) { account.set_password("n3w-passw0rd") }
    assert_equal [true, 401, 0], [e.step_up?, e.status, e.max_age]
    assert_equal "#{FakeTenant::ISSUER}/account/security", account.account_page_url("security")
  end

  def test_plaintext_http_only_on_localhost
    ["http://acme.login.touchque.com", "http://10.0.0.5:8080", "http://localhost.evil.example"].each do |domain|
      assert_equal "config", assert_raises(TouchQue::HostedLoginError) { TouchQue::HostedLogin.new(domain: domain, client_id: "c") }.error_code, domain
      assert_equal "config", assert_raises(TouchQue::MyAccountError) { TouchQue::MyAccount.new(domain, "at") }.error_code, domain
    end
    ["http://localhost:3000", "http://127.0.0.1:4000", "http://[::1]:4000", "http://acme.login.localhost:3000/", "acme.login.touchque.com"].each do |domain|
      assert TouchQue::HostedLogin.new(domain: domain, client_id: "c").issuer.start_with?("http"), domain
    end
  end

  def test_inspect_never_shows_secrets_or_tokens
    l = login("CS999")
    [l, l.my_account("AT-SECRET")].each { |o| refute_match(/CS999|AT-SECRET/, o.inspect, o.class.name) }
    assert_includes l.inspect, FakeTenant::ISSUER
  end
end
