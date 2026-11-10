# frozen_string_literal: true

module TouchQue
  # A refused ID-JAG or exchange (Cross App Access). +error+ is the OAuth error:
  # invalid_grant for a bad ID-JAG, else what the server answered.
  class IdJagError < Error
    attr_reader :error, :status

    def initialize(error, message, status = nil)
      @error = error
      @status = status
      super(message)
    end
  end

  # Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
  # draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
  # organization's identity provider (TouchQue SSO) decides which of its apps may reach
  # which other service for its members; the app trades a member's ID token for an
  # ID-JAG there, then the ID-JAG for an access token at the other service's
  # authorization server, with no consent screen per member. Your own authorization
  # server takes them with IdJagVerifier.
  #
  #   jag = TouchQue::CrossAppAccess.request_id_jag(issuer: "https://sso.touchque.com", client_id: id, client_secret: secret,
  #                                                 id_token: id_token, audience: "https://auth.files.example")
  #   tokens = TouchQue::CrossAppAccess.redeem_id_jag(token_endpoint: "https://auth.files.example/token", client_id: "acme",
  #                                                   client_secret: files_secret, assertion: jag["assertion"])
  module CrossAppAccess
    ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag"
    ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
    TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
    JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

    module_function

    # https, or http on this machine (tests).
    def safe_url?(url)
      u = URI.parse(url.to_s)
      u.scheme == "https" || (u.scheme == "http" && %w[localhost 127.0.0.1 ::1 [::1]].include?(u.host))
    rescue URI::InvalidURIError
      false
    end

    def get_json(url)
      status, text, = Transport.call("GET", url, timeout: 5)
      raise "#{url} answered #{status}" if status >= 400

      Util.parse_json(text) || {}
    end

    # The identity provider's OpenID configuration, checked against its issuer.
    def discover(issuer, fetch = method(:get_json))
      meta = fetch.call("#{issuer.chomp("/")}/.well-known/openid-configuration")
      raise ConfigError, "the identity provider's metadata does not match its issuer" unless meta["issuer"] == issuer

      meta
    end

    def post_form(url, fields, basic = nil)
      raise ConfigError, "#{url} must be an https URL" unless safe_url?(url)

      headers = { "Content-Type" => "application/x-www-form-urlencoded" }
      if basic
        raw = "#{URI.encode_www_form_component(basic[0]).gsub("+", "%20")}:#{URI.encode_www_form_component(basic[1]).gsub("+", "%20")}"
        headers["Authorization"] = "Basic #{[raw].pack("m0")}"
      end
      status, text, = Transport.call("POST", url, headers: headers, body: Transport.form(fields), timeout: 10)
      data = Util.parse_json(text)
      data = {} unless data.is_a?(Hash)
      raise IdJagError.new((data["error"] || "server_error").to_s, (data["error_description"] || "#{url} answered #{status}").to_s, status) if status >= 400

      data
    end

    def scope_text(scope)
      scope.is_a?(Array) ? scope.join(" ") : scope
    end

    # Trades a member's ID token for an ID-JAG at the identity provider (token exchange,
    # client_secret_basic): { "assertion", "expires_in", "scope" }.
    def request_id_jag(client_id:, client_secret:, id_token:, audience:, issuer: nil, token_endpoint: nil, resource: nil, scope: nil)
      unless token_endpoint
        raise ConfigError, "request_id_jag needs issuer or token_endpoint" if issuer.to_s.empty?

        token_endpoint = discover(issuer)["token_endpoint"]
        raise ConfigError, "the identity provider names no token_endpoint" unless token_endpoint.is_a?(String)
      end
      data = post_form(token_endpoint, {
                         "grant_type" => TOKEN_EXCHANGE_GRANT, "requested_token_type" => ID_JAG_TOKEN_TYPE,
                         "subject_token" => id_token, "subject_token_type" => ID_TOKEN_TYPE,
                         "audience" => audience, "resource" => resource, "scope" => scope_text(scope)
                       }, [client_id, client_secret])
      unless data["issued_token_type"] == ID_JAG_TOKEN_TYPE && data["access_token"].is_a?(String)
        raise IdJagError.new("invalid_response", "the identity provider did not answer with an ID-JAG")
      end

      { "assertion" => data["access_token"], "expires_in" => data["expires_in"], "scope" => data["scope"] }
    end

    # Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer).
    def redeem_id_jag(token_endpoint:, client_id:, assertion:, client_secret: nil, resource: nil, scope: nil)
      fields = { "grant_type" => JWT_BEARER_GRANT, "assertion" => assertion, "resource" => resource, "scope" => scope_text(scope) }
      fields["client_id"] = client_id if client_secret.to_s.empty?
      post_form(token_endpoint, fields, client_secret.to_s.empty? ? nil : [client_id, client_secret])
    end
  end

  # Your authorization server, taking ID-JAGs from an organization's identity provider:
  # checks the one an authenticated client presents (jwt-bearer grant) and uses it once.
  #
  #   verifier = TouchQue::IdJagVerifier.new(issuer: "https://sso.touchque.com", audience: "https://auth.files.example")
  #   claims = verifier.verify(params[:assertion], client_id: authenticated_client_id)
  #
  # +first_use+ (a callable jti, exp → true when new) lets several processes share a
  # store such as Redis SET NX; memory in this process by default.
  class IdJagVerifier
    def initialize(issuer:, audience:, jwks_uri: nil, clock_skew: 60, first_use: nil, fetch: nil)
      if issuer.to_s.empty? || audience.to_s.empty?
        raise ConfigError, "IdJagVerifier needs issuer (the identity provider) and audience (your authorization server's issuer)"
      end

      @issuer = issuer
      @audience = audience
      @jwks_uri = jwks_uri
      @skew = clock_skew
      @first_use = first_use || method(:remember_once)
      @fetch = fetch || CrossAppAccess.method(:get_json)
      @keys = {}
      @keys_at = 0
      @tried_at = 0
      @seen = {}
      @lock = Mutex.new
    end

    # The ID-JAG, checked and used once: its claims, or IdJagError (error invalid_grant).
    def verify(assertion, client_id:)
      bad = ->(message) { IdJagError.new("invalid_grant", message) }
      parts = JWS.split(assertion)
      raise bad.call("assertion is not a JWT") unless parts

      head, c, input, sig = parts
      raise bad.call("not an ID-JAG (typ oauth-id-jag+jwt)") unless head["typ"] == "oauth-id-jag+jwt"
      raise bad.call("unsupported signature") unless %w[RS256 ES256 EdDSA].include?(head["alg"]) && head["kid"].is_a?(String)

      key = begin
        key_for(head["kid"])
      rescue StandardError => e
        raise IdJagError.new("temporarily_unavailable", "the identity provider's keys could not be read: #{e.message}")
      end
      raise bad.call("signature does not verify") unless key && JWS.verify(head["alg"], key, input, sig)

      now = Util.now
      auds = c["aud"].is_a?(Array) ? c["aud"] : [c["aud"]]
      raise bad.call("another issuer") unless c["iss"] == @issuer
      raise bad.call("not for this authorization server") unless auds.length == 1 && auds[0] == @audience
      raise bad.call("issued to another client") unless c["client_id"].is_a?(String) && c["client_id"] == client_id
      raise bad.call("expired") unless c["exp"].is_a?(Numeric) && c["exp"] + @skew >= now
      raise bad.call("issued in the future") unless c["iat"].is_a?(Numeric) && c["iat"] - @skew <= now
      raise bad.call("sub and jti are required") unless c["sub"].is_a?(String) && c["jti"].is_a?(String)
      raise bad.call("already used") unless @first_use.call(c["jti"], c["exp"].to_i)

      {
        "iss" => c["iss"], "sub" => c["sub"], "aud" => auds[0], "client_id" => c["client_id"], "jti" => c["jti"],
        "issued_at" => c["iat"].to_i, "expires_at" => c["exp"].to_i,
        "scopes" => c["scope"].is_a?(String) && !c["scope"].empty? ? c["scope"].split(" ") : [],
        "resource" => c["resource"], "tenant" => c["tenant"], "email" => c["email"], "auth_time" => c["auth_time"], "amr" => c["amr"],
        "claims" => c
      }
    end

    private

    def remember_once(jti, exp)
      @lock.synchronize do
        now = Util.now
        @seen.delete_if { |_, until_at| until_at < now }
        return false if @seen.key?(jti)

        @seen[jti] = exp + @skew
        true
      end
    end

    def load_keys
      unless @jwks_uri
        @jwks_uri = CrossAppAccess.discover(@issuer, @fetch)["jwks_uri"]
        raise "the identity provider names no jwks_uri" unless @jwks_uri.is_a?(String)
      end
      @keys = (@fetch.call(@jwks_uri)["keys"] || []).each_with_object({}) { |k, h| h[k["kid"]] = k if k["kid"] }
      @keys_at = Util.now
    end

    def key_for(kid)
      @lock.synchronize do
        load_keys if @keys_at.zero? || Util.now - @keys_at > 600
        if !@keys.key?(kid) && Util.now - @tried_at > 60
          @tried_at = Util.now
          load_keys
        end
        @keys[kid]
      end
    end
  end
end
