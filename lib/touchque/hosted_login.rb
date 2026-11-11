# frozen_string_literal: true

module Touchque
  # Touchque Login (hosted sign-in) for your app: an OpenID Connect client for your
  # tenant (acme.login.touchque.com or your own domain). PKCE (S256) is always used.
  # ID tokens are checked against the tenant's JWKS (RS256, issuer, audience, expiry,
  # nonce, at_hash); your API checks access tokens with verify_access_token. In Rails,
  # Touchque::Rails::HostedLogin wires the routes for you.
  #
  #   login = Touchque::HostedLogin.new(domain: "acme.login.touchque.com", client_id: "...", client_secret: "...",
  #                                     redirect_uri: "https://app/callback")
  #   req = login.authorization_url              # keep state, nonce, code_verifier; redirect to req["url"]
  #   tokens = login.handle_callback(request.url, state: req["state"], nonce: req["nonce"], code_verifier: req["codeVerifier"])
  #   tokens["claims"]["sub"]
  class HostedLogin
    # requested_token_type for the token vault (get_connection_token).
    CONNECTION_TOKEN_TYPE = "urn:touchque:params:oauth:token-type:connection-access-token"

    attr_reader :issuer, :client_id, :redirect_uri

    # +transport+: ->(method, url, headers, body) { [status, text] } (tests).
    def initialize(domain:, client_id:, client_secret: nil, redirect_uri: nil, scope: "openid profile email", audience: nil,
                   clock_tolerance: 60, transport: nil)
      raise HostedLoginError.new("config", "domain is required") if domain.to_s.empty?
      raise HostedLoginError.new("config", "client_id is required") if client_id.to_s.empty?

      raw = domain.chomp("/")
      @issuer = raw.match?(%r{\Ahttps?://}) ? raw : "https://#{raw}"
      unless Util.https_or_loopback?(@issuer)
        raise HostedLoginError.new("config", "Refusing a plaintext http:// domain: codes, the client secret and tokens would be sent in the clear. Use https:// (http:// only on localhost).")
      end
      @client_id = client_id
      @client_secret = client_secret
      @redirect_uri = redirect_uri
      @scope = scope
      @audience = audience
      @clock_tolerance = clock_tolerance
      @transport = transport || lambda { |method, url, headers, body|
        status, text, = Transport.call(method, url, headers: headers, body: body)
        [status, text]
      }
      @keys = {}
      @keys_at = 0
      @lock = Mutex.new
    end

    # Never shows the client secret (logs, consoles, error reporters).
    def inspect
      "#<#{self.class.name} issuer=#{@issuer.inspect} client_id=#{@client_id.inspect}>"
    end

    # The URL to send the browser to, and the values to keep until the callback:
    # {"url", "state", "nonce", "codeVerifier"}.
    def authorization_url(state: nil, nonce: nil, code_verifier: nil, redirect_uri: nil, scope: nil, audience: nil, prompt: nil,
                          login_hint: nil, screen_hint: nil, ui_locales: nil, max_age: nil, connection: nil, organization: nil,
                          invitation: nil, acr_values: nil, response_mode: nil, extra_params: {})
      redirect = redirect_uri || @redirect_uri
      raise HostedLoginError.new("config", "redirect_uri is required") if redirect.to_s.empty?

      state ||= random(32)
      nonce ||= random(32)
      code_verifier ||= random(48)
      params = [
        ["response_type", "code"], ["client_id", @client_id], ["redirect_uri", redirect], ["scope", scope || @scope],
        ["state", state], ["nonce", nonce], ["code_challenge", Util.b64url(Util.sha256(code_verifier))], ["code_challenge_method", "S256"]
      ]
      { "audience" => audience || @audience, "prompt" => prompt, "login_hint" => login_hint, "screen_hint" => screen_hint,
        "ui_locales" => ui_locales, "max_age" => max_age&.to_s, "connection" => connection, "organization" => organization,
        "invitation" => invitation, "acr_values" => acr_values, "response_mode" => response_mode }.each do |k, v|
        params << [k, v.to_s] unless v.nil? || v.to_s.empty?
      end
      (extra_params || {}).each { |k, v| params << [k.to_s, v.to_s] }
      query = params.map { |k, v| "#{Util.seg(k)}=#{Util.seg(v)}" }.join("&")
      { "url" => "#{@issuer}/authorize?#{query}", "state" => state, "nonce" => nonce, "codeVerifier" => code_verifier }
    end

    # Checks state (and iss), exchanges the code with the PKCE verifier, verifies the ID
    # token. +callback+: the callback URL, its query string, or its params (a Hash).
    def handle_callback(callback, state:, nonce:, code_verifier:, redirect_uri: nil, max_age: nil)
      p = self.class.params_of(callback)
      if p["state"].to_s.empty? || state.to_s.empty? || !Util.secure_compare(state, p["state"])
        raise HostedLoginError.new("state_mismatch", "The state does not match this sign-in")
      end
      # RFC 9207: a response that carries iss (even an empty one) must name this issuer, the one the
      # ID token is checked against. Servers that do not send iss yet are accepted.
      if p.key?("iss") && p["iss"] != @issuer
        raise HostedLoginError.new("issuer_mismatch", p["iss"].empty? ? "The response has an empty iss" : "The response came from #{p["iss"]}")
      end
      raise HostedLoginError.new(p["error"], p["error_description"]) unless p["error"].to_s.empty?
      raise HostedLoginError.new("invalid_request", "The callback has no code") if p["code"].to_s.empty?

      redirect = redirect_uri || @redirect_uri
      raise HostedLoginError.new("config", "redirect_uri is required") if redirect.to_s.empty?

      tokens = token("grant_type" => "authorization_code", "code" => p["code"], "redirect_uri" => redirect, "code_verifier" => code_verifier)
      raise HostedLoginError.new("invalid_token", "No ID token: ask for the openid scope") if tokens["idToken"].to_s.empty?

      tokens.merge("claims" => verify_id_token(tokens["idToken"], nonce: nonce, access_token: tokens["accessToken"], max_age: max_age))
    end

    # A new access token and a rotated refresh token: keep the new one.
    def refresh(refresh_token, scope: nil)
      tokens = token("grant_type" => "refresh_token", "refresh_token" => refresh_token, "scope" => scope)
      return tokens if tokens["idToken"].to_s.empty?

      tokens.merge("claims" => verify_id_token(tokens["idToken"], access_token: tokens["accessToken"]))
    end

    # A token for the My Account API (audience https://<domain>/me/) from the refresh token
    # a first-party app holds. The refresh token rotates: keep the returned one. Scopes:
    # read:me, update:me, manage:me:security, delete:me.
    def my_account_token(refresh_token, scope: "read:me update:me")
      token("grant_type" => "refresh_token", "refresh_token" => refresh_token, "audience" => "#{@issuer}/me/", "scope" => scope)
    end

    # The My Account API for the person holding +access_token+.
    def my_account(access_token)
      MyAccount.new(@issuer, access_token, transport: @transport)
    end

    # The hosted account page (profile; security, devices or privacy).
    def account_url(section = nil)
      "#{@issuer}/account#{section ? "/#{section}" : ""}"
    end

    # Machine to machine: an access token for your API with the app's own credentials.
    def client_credentials(audience, scope: nil)
      token("grant_type" => "client_credentials", "audience" => audience, "scope" => scope)
    end

    # RFC 8693: a signed-in user's access token, traded for one to call +audience+ on
    # their behalf (sub = the user, act.sub = this app).
    def exchange_token(subject_token, audience, scope: nil)
      token("grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token" => subject_token,
            "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token", "audience" => audience, "scope" => scope)
    end

    # Token vault: the provider's own access token (Google, Microsoft, GitHub...) for the
    # signed-in user, from a connection that stores tokens. Touchque refreshes it; the
    # refresh token never leaves. HostedLoginError invalid_grant when nothing is stored.
    def get_connection_token(user_access_token, connection, scope: nil)
      token("grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token" => user_access_token,
            "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token", "requested_token_type" => CONNECTION_TOKEN_TYPE,
            "connection" => connection, "scope" => scope)
    end

    # CIBA: asks the user (email or usr_ id) to approve on their phone:
    # {"authReqId", "expiresAt", "interval", "bindingCode"}.
    def ask_user(login_hint, scope, audience: nil, binding_message: nil, authorization_details: nil, requested_expiry: nil)
      status, body = post("/bc-authorize", {
                            "login_hint" => login_hint, "scope" => scope, "audience" => audience, "binding_message" => binding_message,
                            "authorization_details" => authorization_details && Util.json(Util.stringify(authorization_details)),
                            "requested_expiry" => requested_expiry&.to_s
                          })
      raise error(status, body) if status >= 400

      d = Util.parse_json(body) || {}
      { "authReqId" => d["auth_req_id"].to_s, "expiresAt" => Util.now + d["expires_in"].to_i, "interval" => (d["interval"] || 5).to_i,
        "bindingCode" => d["binding_code"] }
    end

    # Polls until the user answers: the tokens, or HostedLoginError access_denied / expired_token.
    def wait_for_user(request)
      interval = request["interval"].to_i
      loop do
        raise HostedLoginError.new("expired_token", "The user did not answer in time") if Util.now > request["expiresAt"]

        sleep interval
        begin
          return token("grant_type" => "urn:openid:params:grant-type:ciba", "auth_req_id" => request["authReqId"])
        rescue HostedLoginError => e
          if e.error_code == "slow_down"
            interval += 5
          elsif e.error_code != "authorization_pending"
            raise
          end
        end
      end
    end

    def revoke(token_value)
      status, body = post("/oauth/revoke", { "token" => token_value })
      raise error(status, body) if status >= 400

      nil
    end

    def userinfo(access_token)
      status, body = @transport.call("GET", "#{@issuer}/userinfo", { "Authorization" => "Bearer #{access_token}", "Accept" => "application/json" }, nil)
      raise error(status, body) if status >= 400

      Util.parse_json(body) || {}
    end

    def logout_url(id_token_hint: nil, post_logout_redirect_uri: nil, state: nil)
      p = { "client_id" => @client_id, "id_token_hint" => id_token_hint, "post_logout_redirect_uri" => post_logout_redirect_uri, "state" => state }
      "#{@issuer}/oidc/logout?" + p.reject { |_, v| v.nil? || v.empty? }.map { |k, v| "#{k}=#{Util.seg(v)}" }.join("&")
    end

    # For your API: signature, issuer, audience, expiry, typ at+jwt, scopes.
    def verify_access_token(token_value, audience:, required_scopes: [])
      payload = verify_jwt(token_value, "at+jwt")
      raise HostedLoginError.new("invalid_token", "The token is for another audience") unless Array(payload["aud"]).include?(audience)

      missing = required_scopes - payload["scope"].to_s.split(" ")
      raise HostedLoginError.new("insufficient_scope", "Missing scope: #{missing.join(" ")}", 403) unless missing.empty?

      payload
    end

    def verify_id_token(id_token, nonce: nil, access_token: nil, max_age: nil)
      payload = verify_jwt(id_token, nil)
      auds = Array(payload["aud"])
      raise HostedLoginError.new("invalid_token", "The ID token is for another app") unless auds.include?(@client_id)
      raise HostedLoginError.new("invalid_token", "azp does not name this app") if auds.length > 1 && payload["azp"] != @client_id
      if nonce && !(payload["nonce"].is_a?(String) && Util.secure_compare(nonce, payload["nonce"]))
        raise HostedLoginError.new("nonce_mismatch", "The nonce does not match this sign-in")
      end
      if access_token && payload["at_hash"].is_a?(String)
        expected = Util.b64url(Util.sha256(access_token)[0, 16])
        raise HostedLoginError.new("invalid_token", "at_hash does not match the access token") unless Util.secure_compare(expected, payload["at_hash"])
      end
      if max_age && payload["auth_time"].is_a?(Integer) && Util.now - payload["auth_time"] > max_age + @clock_tolerance
        raise HostedLoginError.new("login_required", "The sign-in is older than max_age")
      end

      payload
    end

    # The query or form params of a callback URL, a query string or a Hash.
    def self.params_of(callback)
      # A nil value (a framework's missing field) counts as no field.
      return Util.stringify(callback).compact.transform_values(&:to_s) if callback.is_a?(Hash)

      text = callback.to_s
      text = text.split("?", 2)[1].to_s if text.include?("?")
      URI.decode_www_form(text.split("#", 2)[0].to_s).to_h
    end

    private

    def random(bytes)
      Util.b64url(SecureRandom.random_bytes(bytes))
    end

    def post(path, fields)
      headers = { "Content-Type" => "application/x-www-form-urlencoded", "Accept" => "application/json" }
      fields = fields.reject { |_, v| v.nil? || v.to_s.empty? }
      if @client_secret
        basic = "#{Util.seg(@client_id)}:#{Util.seg(@client_secret)}"
        headers["Authorization"] = "Basic #{[basic].pack("m0")}"
      else
        fields = fields.merge("client_id" => @client_id)
      end
      @transport.call("POST", "#{@issuer}#{path}", headers, URI.encode_www_form(fields))
    end

    def error(status, body)
      d = Util.parse_json(body.to_s) || {}
      HostedLoginError.new(d["error"] || "http_#{status}", d["error_description"], status)
    end

    def token(fields)
      status, body = post("/oauth/token", fields)
      raise error(status, body) if status >= 400

      d = Util.parse_json(body) || {}
      {
        "accessToken" => d["access_token"].to_s, "tokenType" => d["token_type"] || "Bearer", "expiresAt" => Util.now + d["expires_in"].to_i,
        "scope" => d["scope"].to_s, "idToken" => d["id_token"], "refreshToken" => d["refresh_token"], "claims" => {},
        "authorizationDetails" => d["authorization_details"].is_a?(Array) ? d["authorization_details"] : nil,
        "issuedTokenType" => d["issued_token_type"], "connection" => d["connection"].is_a?(String) ? d["connection"] : nil
      }
    end

    def load_keys(force)
      @lock.synchronize do
        age = Util.now - @keys_at
        return if !force && !@keys.empty? && age < 3600
        return if force && age < 30

        status, body = @transport.call("GET", "#{@issuer}/.well-known/jwks.json", { "Accept" => "application/json" }, nil)
        raise HostedLoginError.new("jwks_unavailable", "JWKS answered #{status}") if status >= 400

        @keys = ((Util.parse_json(body) || {})["keys"] || []).each_with_object({}) do |k, h|
          h[k["kid"]] = k if k["kty"] == "RSA" && k["kid"] && k["n"] && k["e"] && (k["use"] || "sig") == "sig"
        end
        @keys_at = Util.now
      end
    end

    def verify_jwt(token_value, typ)
      parts = JWS.split(token_value)
      raise HostedLoginError.new("invalid_token", "not a JWT") unless parts

      header, payload, input, sig = parts
      raise HostedLoginError.new("invalid_token", "Unexpected alg") unless header["alg"] == "RS256"
      raise HostedLoginError.new("invalid_token", "Wrong token type") if typ && header["typ"].to_s.downcase != typ

      kid = header["kid"].to_s
      load_keys(false)
      load_keys(true) unless @keys.key?(kid)
      raise HostedLoginError.new("invalid_token", "Unknown signing key") unless @keys.key?(kid)
      raise HostedLoginError.new("invalid_token", "Bad signature") unless JWS.verify("RS256", @keys[kid], input, sig)

      now = Util.now
      raise HostedLoginError.new("invalid_token", "Wrong issuer") unless payload["iss"] == @issuer
      raise HostedLoginError.new("invalid_token", "The token expired") unless payload["exp"].is_a?(Numeric) && now <= payload["exp"] + @clock_tolerance
      raise HostedLoginError.new("invalid_token", "The token is from the future") if payload["iat"].is_a?(Numeric) && payload["iat"] > now + @clock_tolerance

      payload
    end
  end

  # The Touchque Login My Account API (/me/v1) from your server: the signed-in customer's
  # own profile, sign-in methods, devices, apps and data, called with their access token
  # for audience https://<domain>/me/. Security changes, the data export and deletion need
  # a recent sign-in; when it is too old a MyAccountError with step_up? is raised.
  class MyAccount
    def initialize(domain, access_token, transport: nil)
      raise MyAccountError.new("config", 0, "domain and access_token are required") if domain.to_s.empty? || access_token.to_s.empty?

      raw = domain.chomp("/")
      @issuer = raw.match?(%r{\Ahttps?://}) ? raw : "https://#{raw}"
      unless Util.https_or_loopback?(@issuer)
        raise MyAccountError.new("config", 0, "Refusing a plaintext http:// domain: the access token would be sent in the clear. Use https:// (http:// only on localhost).")
      end
      @access_token = access_token
      @transport = transport || lambda { |method, url, headers, body|
        status, text, = Transport.call(method, url, headers: headers, body: body)
        [status, text]
      }
    end

    # Never shows the access token (logs, consoles, error reporters).
    def inspect
      "#<#{self.class.name} issuer=#{@issuer.inspect}>"
    end

    # The hosted account page, optionally at security, devices or privacy.
    def account_page_url(section = nil)
      "#{@issuer}/account#{section ? "/#{section}" : ""}"
    end

    def get = call("GET", "")
    def get_profile = call("GET", "/profile")

    # name, givenName, familyName, nickname, locale, userMetadata (merged; nil removes a key).
    def update_profile(changes) = call("PATCH", "/profile", changes)
    def authentication_methods = call("GET", "/authentication-methods")
    def rename_passkey(id, label) = call("PATCH", "/authentication-methods/passkeys/#{Util.seg(id)}", { "label" => label }) && nil
    # Needs a recent sign-in.
    def remove_passkey(id) = call("DELETE", "/authentication-methods/passkeys/#{Util.seg(id)}") && nil
    # Needs a recent sign-in.
    def unlink_touchque_app = call("DELETE", "/authentication-methods/touchque") && nil
    # Email codes as a second step. Needs a recent sign-in.
    def set_email_codes(enabled) = call("PUT", "/authentication-methods/email", { "enabled" => enabled })
    # Texts a code to a new number for text-message codes. Needs a recent sign-in.
    def start_sms_enrollment(phone) = call("POST", "/authentication-methods/sms", { "phone" => phone })
    # The code from that text: text-message codes are on. Needs a recent sign-in.
    def verify_sms_enrollment(code) = call("POST", "/authentication-methods/sms/verify", { "code" => code })
    # Needs a recent sign-in.
    def remove_sms_codes = call("DELETE", "/authentication-methods/sms") && nil
    # Needs a recent sign-in.
    def unlink_identity(id) = call("DELETE", "/identities/#{Util.seg(id)}") && nil
    # Apps stop using a linked account for the person (token vault: the identity's appAccess id); signing in with it stays.
    def stop_app_access(id) = call("DELETE", "/app-access/#{Util.seg(id)}") && nil
    # Sets or changes the password; other sessions end. Needs a recent sign-in.
    def set_password(password) = call("PUT", "/password", { "password" => password })
    # Needs a recent sign-in and another way to sign in.
    def remove_password = call("DELETE", "/password") && nil
    # A confirmation link goes to the new address. Needs a recent sign-in.
    def change_email(email) = call("POST", "/email", { "email" => email })
    def send_verification_email = call("POST", "/email/verification")
    def sessions = call("GET", "/sessions")
    def end_session(id) = call("DELETE", "/sessions/#{Util.seg(id)}") && nil
    def end_other_sessions = call("DELETE", "/sessions")
    def apps = call("GET", "/apps")
    def revoke_app(client_id) = call("DELETE", "/apps/#{Util.seg(client_id)}")
    def consents = call("GET", "/consents")
    def set_marketing(granted) = call("PUT", "/consents/marketing", { "granted" => granted })
    # Everything about the person (KVKK/GDPR). Needs a recent sign-in.
    def export_data = call("GET", "/export")
    # Erases the account at once. Needs delete:me and a recent sign-in.
    def delete_account = call("DELETE", "")

    private

    def call(method, path, body = nil)
      headers = { "Authorization" => "Bearer #{@access_token}", "Accept" => "application/json" }
      headers["Content-Type"] = "application/json" unless body.nil?
      status, text = @transport.call(method, "#{@issuer}/me/v1#{path}", headers, body.nil? ? nil : Util.json(Util.stringify(body)))
      return {} if status == 204

      d = Util.parse_json(text.to_s) || {}
      raise MyAccountError.new(d["error"] || "http_#{status}", status, d["error_description"], d["max_age"]&.to_i) if status >= 400

      d
    end
  end
end
