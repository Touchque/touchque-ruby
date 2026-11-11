# frozen_string_literal: true

module Touchque
  # An organization's AI agent on Touchque SSO (Organization → AI agents in the
  # dashboard): it gets 5-minute tokens for one of the organization's apps, proving who
  # it is with its own key (private_key_jwt) or with the token its platform already
  # gives it (GitHub Actions, GitLab, Google Cloud, Azure, Kubernetes), and binds each
  # token to a DPoP key made when it starts.
  #
  #   agent = Touchque::OrgAgent.new(agent_id: "oagt_...", private_key: ENV["TQ_ORG_AGENT_KEY"])
  #   headers = agent.authorization("GET", "https://payments.acme.com/invoices", resource: "tqapp_...")
  #   # A GitHub Actions job (permissions: id-token: write), with no key to store:
  #   agent = Touchque::OrgAgent.new(agent_id: "oagt_...", assertion: Touchque::OrgAgent.github_actions_token("touchque"))
  class OrgAgent
    attr_reader :agent_id

    # The token a GitHub Actions job may ask for (the job needs permissions: id-token: write).
    def self.github_actions_token(audience = "touchque")
      lambda do
        url = ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_URL", nil)
        bearer = ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_TOKEN", nil)
        raise ConfigError, "Not in a GitHub Actions job with `permissions: id-token: write`" if url.to_s.empty? || bearer.to_s.empty?

        _, text, = Transport.call("GET", "#{url}#{url.include?("?") ? "&" : "?"}audience=#{Util.seg(audience)}", headers: { "Authorization" => "Bearer #{bearer}" })
        value = Util.parse_json(text)&.dig("value")
        raise ConfigError, "GitHub gave no token" if value.to_s.empty?

        value
      end
    end

    # A token the platform writes to a file and renews (a Kubernetes projected service account token...).
    def self.file_token(path)
      -> { File.read(path).strip }
    end

    # agent_id: TQ_ORG_AGENT_ID. issuer: TQ_SSO_URL (https://sso.touchque.com). private_key:
    # a JWK (Hash or JSON) or an EC PEM (TQ_ORG_AGENT_KEY), or assertion: a callable
    # returning the platform's token.
    def initialize(agent_id: nil, issuer: nil, private_key: nil, kid: nil, assertion: nil, resource: nil, scope: nil, timeout: 10)
      agent_id ||= ENV.fetch("TQ_ORG_AGENT_ID", "")
      raise ConfigError, "Set TQ_ORG_AGENT_ID (or agent_id:): the oagt_... id from Organization → AI agents" unless agent_id.match?(/\Aoagt_[a-z2-9]{20}\z/)

      @agent_id = agent_id
      @issuer = (issuer || ENV["TQ_SSO_URL"].then { |v| v.to_s.empty? ? nil : v } || "https://sso.touchque.com").chomp("/")
      Util.assert_safe_url!(@issuer, "issuer")
      if assertion
        raise ConfigError, "assertion must be callable (it returns the platform's token)" unless assertion.respond_to?(:call)

        @assertion = assertion
      else
        private_key ||= ENV.fetch("TQ_ORG_AGENT_KEY", nil)
        raise ConfigError, "Pass private_key: (or set TQ_ORG_AGENT_KEY), or assertion: with the platform's token" if private_key.to_s.empty?

        @key = SigningKey.load(private_key, "Touchque::OrgAgent")
        jwk = private_key.is_a?(Hash) ? Util.stringify(private_key) : (private_key.to_s.lstrip.start_with?("{") ? Util.parse_json(private_key) : nil)
        @kid = kid || (jwk.is_a?(Hash) && jwk["kid"]) || AgentKeys.thumbprint(@key.public_jwk)
      end
      # The DPoP key: made here, never leaves this process.
      @dpop_key = SigningKey.new_es256
      @resource = resource
      @scope = scope
      @timeout = timeout
      @tokens = {}
      @lock = Mutex.new
    end

    # A DPoP proof (RFC 9449) for one request: with the token, for a call to the app.
    def dpop_proof(method, url, access_token = nil)
      uri = URI.parse(url)
      htu = "#{uri.scheme}://#{uri.host}#{uri.port == uri.default_port ? "" : ":#{uri.port}"}#{uri.path}"
      claims = { "htm" => method.to_s.upcase, "htu" => htu, "iat" => Util.now, "jti" => Util.random_hex(16) }
      claims["ath"] = AgentKeys.access_token_hash(access_token) if access_token
      @dpop_key.jws({ "typ" => "dpop+jwt", "jwk" => @dpop_key.public_jwk }, claims)
    end

    # A token for one app (renewed 30 seconds before it expires):
    # {"accessToken", "tokenType" => "DPoP", "expiresIn", "scope"}.
    def get_token(resource: nil, scope: nil)
      resource ||= @resource
      scope ||= @scope
      key = "#{resource} #{scope}"
      @lock.synchronize do
        cached = @tokens[key]
        return cached[:token] if cached && cached[:expires_at] - Util.now > 30

        token = token_of(post("/sso/token", { "grant_type" => "client_credentials", "resource" => resource, "scope" => scope }, dpop: true))
        @tokens[key] = { token: token, expires_at: Util.now + token["expiresIn"] }
        token
      end
    end

    # A token for a member, with their own access token for one of the agent's apps
    # (RFC 8693): sub is the member, act the agent.
    def exchange_token(subject_token, resource: nil, scope: nil)
      token_of(post("/sso/token", {
                      "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token" => subject_token,
                      "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token",
                      "resource" => resource || @resource, "scope" => scope || @scope
                    }, dpop: true))
    end

    # The token vault: a member's own access token at another service (Google, Microsoft
    # 365, GitHub...) they connected on Touchque, for a connection that names this agent.
    # APIError invalid_grant: the member has not connected it (or disconnected, or left).
    def get_connection_token(subject_token, connection, scope: nil)
      data = post("/sso/token", {
                    "grant_type" => "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token" => subject_token,
                    "subject_token_type" => "urn:ietf:params:oauth:token-type:access_token",
                    "requested_token_type" => "urn:touchque:params:oauth:token-type:connection-access-token",
                    "connection" => connection, "scope" => scope
                  }, dpop: true)
      { "accessToken" => data["access_token"].to_s, "tokenType" => "Bearer", "expiresIn" => data["expires_in"]&.to_i,
        "scope" => data["scope"].to_s, "connection" => data["connection"] || connection }
    end

    # Asks to open a shared account (its key, from Organization → AI agents → Access) for
    # a member: {"askId", "openUrl", "status", "expiresIn"}. The member opens openUrl in
    # the browser where their Touchque extension is paired; the agent never sees the
    # password. +message+ (at most 64 characters) is shown marked unverified.
    def ask_to_open_shared_account(account, login_hint, message = nil)
      data = post("/sso/agents/shared-accounts/asks", { "account" => account, "login_hint" => login_hint, "binding_message" => message }, dpop: false)
      { "askId" => data["ask_id"].to_s, "openUrl" => data["open_url"].to_s, "status" => data["status"].to_s, "expiresIn" => (data["expires_in"] || 600).to_i }
    end

    # Where an ask stands: {"status", "reason", "caseCode"}; never anything of the account.
    def shared_account_ask_status(ask_id)
      data = post("/sso/agents/shared-accounts/asks/#{Util.seg(ask_id)}", {}, dpop: false)
      { "status" => data["status"].to_s, "reason" => data["reason"], "caseCode" => data["case_code"] }
    end

    # Polls an ask until it ends: opened, refused, declined or expired.
    def wait_for_shared_account(ask, interval: 3.0)
      deadline = Util.now + ask["expiresIn"].to_i + 5
      loop do
        s = shared_account_ask_status(ask["askId"])
        return s if !%w[waiting_member asked_phone].include?(s["status"]) || Util.now > deadline

        sleep interval
      end
    end

    # Asks a member to approve on their phone (CIBA): {"authReqId", "expiresIn", "interval",
    # "bindingCode"}. Show bindingCode in the conversation.
    def ask_member(login_hint, binding_message: nil, authorization_details: nil, resource: nil, scope: nil, requested_expiry: nil)
      data = post("/sso/bc-authorize", {
                    "login_hint" => login_hint, "binding_message" => binding_message,
                    "resource" => resource || @resource, "scope" => scope || @scope,
                    "authorization_details" => authorization_details && Util.json(Util.stringify(authorization_details)),
                    "requested_expiry" => requested_expiry&.to_s
                  }, dpop: false)
      out = { "authReqId" => data["auth_req_id"], "expiresIn" => (data["expires_in"] || 300).to_i, "interval" => (data["interval"] || 5).to_i }
      out["bindingCode"] = data["binding_code"] if data["binding_code"]
      out
    end

    # The member's answer (polling at the interval, slower when asked): the token once they
    # approve; APIError access_denied or expired_token otherwise, TimeoutError after it expired.
    def wait_for_member(request)
      interval = [request["interval"].to_i, 1].max
      deadline = Util.now + request["expiresIn"].to_i + 5
      while Util.now < deadline
        sleep interval
        begin
          return token_of(post("/sso/token", { "grant_type" => "urn:openid:params:grant-type:ciba", "auth_req_id" => request["authReqId"] }, dpop: true))
        rescue APIError => e
          next if e.code == "authorization_pending"

          if e.code == "slow_down"
            interval += 5
            next
          end
          raise
        end
      end
      raise TimeoutError, "The member did not answer in time"
    end

    # The two headers for one call to the app: {"Authorization" => "DPoP ...", "DPoP" => proof}.
    def authorization(method, url, resource: nil, scope: nil)
      token = get_token(resource: resource, scope: scope)["accessToken"]
      { "Authorization" => "DPoP #{token}", "DPoP" => dpop_proof(method, url, token) }
    end

    private

    def client_assertion
      return @assertion.call.to_s if @assertion

      now = Util.now
      @key.jws({ "typ" => "JWT", "kid" => @kid },
               { "iss" => @agent_id, "sub" => @agent_id, "aud" => "#{@issuer}/sso/token", "iat" => now, "exp" => now + 60, "jti" => Util.random_hex(16) })
    end

    # POSTs to the SSO with the agent's client assertion (and, at /sso/token, a DPoP proof).
    def post(path, fields, dpop:)
      url = @issuer + path
      form = { "client_id" => @agent_id, "client_assertion_type" => Agent::ASSERTION_TYPE, "client_assertion" => client_assertion }.merge(fields)
      headers = { "Content-Type" => "application/x-www-form-urlencoded" }
      headers["DPoP"] = dpop_proof("POST", url) if dpop
      status, text, = Transport.call("POST", url, headers: headers, body: Transport.form(form), timeout: @timeout)
      data = Util.parse_json(text)
      data = {} unless data.is_a?(Hash)
      raise Transport.oauth_failure(status, data) unless status == 200

      data
    end

    def token_of(data)
      token = { "accessToken" => data["access_token"], "tokenType" => "DPoP", "expiresIn" => (data["expires_in"] || 300).to_i, "scope" => data["scope"].to_s }
      token["authorizationDetails"] = data["authorization_details"] if data["authorization_details"].is_a?(Array)
      token
    end
  end

  # For an MCP server whose authorization server is Touchque SSO (Organization → MCP
  # servers in the dashboard; issuer https://sso.touchque.com/mcp):
  # protected_resource_metadata is its RFC 9728 document (serve it at metadata_paths);
  # verify checks a request's token (signed by Touchque, this issuer, audience = this
  # server, not expired, and for a DPoP-bound token a fresh proof); require_tool refuses
  # with 403 insufficient_scope naming the scope a tool needs.
  #
  #   auth = Touchque::McpAuth.new(issuer: "https://sso.touchque.com/mcp", resource: "https://mcp.acme.com/mcp",
  #                                tools: { "search_tickets" => "tickets:read" })
  #   claims = auth.verify(request.request_method, request.url, request.headers)
  #   auth.require_tool(claims, tool_name)
  class McpAuth
    def initialize(issuer:, resource:, tools: {}, resource_name: nil, clock_skew: 60, fetch: nil)
      if issuer.to_s.empty? || resource.to_s.empty?
        raise ConfigError, "McpAuth needs issuer (Touchque SSO's MCP issuer) and resource (this server's URL)"
      end

      @issuer = issuer.chomp("/")
      @resource = resource
      @tools = Util.stringify(tools || {})
      @resource_name = resource_name
      @skew = clock_skew
      @fetch = fetch || method(:get_json)
      @keys = {}
      @keys_at = 0
      @tried_at = 0
      @proofs = {}
      @lock = Mutex.new
    end

    # Where to serve protected_resource_metadata.
    def metadata_paths
      path = URI.parse(@resource).path.to_s.chomp("/")
      path.empty? ? ["/.well-known/oauth-protected-resource"] : ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource#{path}"]
    end

    def metadata_url
      u = URI.parse(@resource)
      "#{u.scheme}://#{u.host}#{u.port == u.default_port ? "" : ":#{u.port}"}#{metadata_paths.last}"
    end

    def protected_resource_metadata
      doc = {
        "resource" => @resource, "authorization_servers" => [@issuer], "bearer_methods_supported" => ["header"],
        "scopes_supported" => @tools.values.uniq, "dpop_signing_alg_values_supported" => %w[ES256 EdDSA]
      }
      doc["resource_name"] = @resource_name if @resource_name
      doc
    end

    # A request's token, checked: {"sub", "email", "clientId", "scopes", "orgId",
    # "expiresAt", "dpopBound", "claims"}. +headers+: a Hash (any key case) or anything
    # answering [] (Rack/Rails headers).
    def verify(method, url, headers)
      get = header_getter(headers)
      scheme, token = get.call("authorization").to_s.strip.split(" ", 2)
      token = token.to_s.strip
      raise refusal(401, "missing_token", "A Touchque access token is required") unless %w[bearer dpop].include?(scheme.to_s.downcase) && token.count(".") == 2

      claims = claims_of(token)
      jkt = claims.dig("cnf", "jkt")
      if jkt
        raise refusal(401, "invalid_token", "This token is bound to a DPoP key: send it as DPoP with a proof") unless scheme.downcase == "dpop"

        check_proof(get.call("dpop"), method, url, token, jkt)
      end
      {
        "sub" => claims["sub"].to_s, "email" => claims["email"], "clientId" => claims["client_id"].to_s,
        "scopes" => claims["scope"].to_s.split, "orgId" => claims["org_id"], "expiresAt" => claims["exp"].to_i,
        "dpopBound" => !jkt.nil?, "claims" => claims
      }
    end

    def require_scope(claims, scope)
      raise refusal(403, "insufficient_scope", "This needs the #{scope} scope", scope) unless claims["scopes"].include?(scope)
    end

    def require_tool(claims, tool)
      scope = @tools[tool.to_s]
      raise refusal(403, "insufficient_scope", "No scope is set for the tool #{tool}") if scope.to_s.empty?

      require_scope(claims, scope)
    end

    private

    def refusal(status, code, message, scope = nil)
      parts = ["resource_metadata=\"#{metadata_url}\""]
      unless code == "missing_token"
        parts << "error=\"#{code}\"" << "error_description=\"#{message.tr('"', "'")}\""
        parts << "scope=\"#{scope}\"" if scope
      end
      McpAuthError.new(status, code, message, "Bearer #{parts.join(", ")}")
    end

    def header_getter(headers)
      if headers.is_a?(Hash)
        lower = headers.to_h { |k, v| [k.to_s.downcase, v] }
        ->(name) { lower[name] }
      else
        ->(name) { headers[name] }
      end
    end

    def claims_of(token)
      parts = JWS.split(token)
      raise refusal(401, "invalid_token", "The token is malformed") unless parts

      head, claims, input, sig = parts
      raise refusal(401, "invalid_token", "Not a Touchque access token") unless head["typ"] == "at+jwt" && %w[RS256 ES256].include?(head["alg"])

      key = begin
        key_for(head["kid"].to_s)
      rescue StandardError
        raise refusal(401, "invalid_token", "The authorization server's keys could not be read")
      end
      raise refusal(401, "invalid_token", "The token signature does not verify") unless key && JWS.verify(head["alg"], key, input, sig)
      raise refusal(401, "invalid_token", "The token is from another issuer") unless claims["iss"].to_s.chomp("/") == @issuer
      raise refusal(401, "invalid_token", "The token is for another server") unless Array(claims["aud"]).include?(@resource)
      raise refusal(401, "invalid_token", "The token expired") unless claims["exp"].is_a?(Numeric) && claims["exp"] + @skew > Util.now

      claims
    end

    def load_keys
      u = URI.parse(@issuer)
      origin = "#{u.scheme}://#{u.host}#{u.port == u.default_port ? "" : ":#{u.port}"}"
      meta = @fetch.call("#{origin}/.well-known/oauth-authorization-server#{u.path.to_s.chomp("/")}")
      raise "the authorization server metadata does not match the issuer" unless meta["issuer"].to_s.chomp("/") == @issuer && meta["jwks_uri"]

      @keys = (@fetch.call(meta["jwks_uri"])["keys"] || []).each_with_object({}) { |k, h| h[k["kid"]] = k if k["kid"] }
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

    def check_proof(proof, method, url, token, jkt)
      reject = ->(why) { refusal(401, "invalid_dpop_proof", "DPoP proof: #{why}") }
      raise reject.call("missing") if proof.to_s.count(".") != 2

      parts = JWS.split(proof)
      raise reject.call("malformed") unless parts

      head, claims, input, sig = parts
      jwk = head["jwk"]
      unless head["typ"] == "dpop+jwt" && jwk.is_a?(Hash) && !jwk.key?("d") && %w[EC OKP].include?(jwk["kty"]) && AgentKeys.thumbprint(jwk) == jkt
        raise reject.call("not the bound key")
      end
      raise reject.call("signature") unless JWS.verify(head["alg"].to_s, jwk, input, sig)

      u = URI.parse(url)
      htu = "#{u.scheme}://#{u.host}#{u.port == u.default_port ? "" : ":#{u.port}"}#{u.path}"
      raise reject.call("htm/htu") unless claims["htm"] == method.to_s.upcase && claims["htu"] == htu
      raise reject.call("iat") if (claims["iat"].to_i - Util.now).abs > @skew
      raise reject.call("ath") unless claims["ath"] == AgentKeys.access_token_hash(token)

      @lock.synchronize do
        now = Util.now
        @proofs.delete_if { |_, until_at| until_at < now }
        jti = claims["jti"].to_s
        raise reject.call("jti used") if jti.empty? || @proofs.key?(jti)

        @proofs[jti] = now + 2 * @skew
      end
    end

    def get_json(url)
      status, text, = Transport.call("GET", url, timeout: 5)
      raise "#{url} answered #{status}" if status >= 400

      Util.parse_json(text) || {}
    end
  end
end
