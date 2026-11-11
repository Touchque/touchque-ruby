# frozen_string_literal: true

require "net/http"
require "uri"

module Touchque
  # Plain HTTP for the clients that do not sign with the API key (agents, Touchque
  # Login, MCP). Never follows redirects.
  module Transport
    module_function

    # [status, body text, response].
    def call(method, url, headers: {}, body: nil, timeout: 10)
      uri = URI.parse(url)
      klass = { "GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post, "PUT" => Net::HTTP::Put,
                "PATCH" => Net::HTTP::Patch, "DELETE" => Net::HTTP::Delete }.fetch(method.to_s.upcase)
      req = klass.new(uri.request_uri)
      headers.each { |k, v| req[k] = v }
      req["Accept"] ||= "application/json"
      req.body = body unless body.nil?
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout = timeout
      http.read_timeout = timeout
      res = http.request(req)
      raise NetworkError, "the answer is larger than 10 MB" if res.body.to_s.bytesize > HTTP::MAX_RESPONSE_BYTES

      [res.code.to_i, res.body.to_s.dup.force_encoding("UTF-8"), res]
    rescue *HTTP::NETWORK_ERRORS => e
      raise NetworkError, e.message
    end

    def form(fields)
      URI.encode_www_form(fields.reject { |_, v| v.nil? || v.to_s.empty? })
    end

    # An OAuth-style error answer as APIError (code = error, retryAfter from retry_after).
    def oauth_failure(status, data)
      data = data.is_a?(Hash) ? data : {}
      data["code"] ||= data["error"]
      data["retryAfter"] ||= data["retry_after"].to_i if data["retry_after"]
      APIError.for(status, data, data["error_description"] || data["error"] || "Touchque API error: HTTP #{status}")
    end
  end

  # The agent side: an AI agent calls Touchque with its OWN key, never with your API
  # key. It signs a private_key_jwt assertion (RFC 7523) for a 10-minute token bound to
  # its key with DPoP (RFC 9449), and proves the key on every call, so a stolen token is
  # useless on its own.
  #
  #   agent = Touchque::Agent.new          # TQ_AGENT_ID, TQ_AGENT_KEY (a JWK as JSON, or an EC PEM)
  #   approved = agent.require_approval("ayse@acme.com", "PAY_INVOICE", [payment]) do |state|
  #     say "Type #{state["challengeCode"]} on your phone"
  #   end
  class Agent
    ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ENDED = %w[rejected blocked revoked expired stale redeemed].freeze

    attr_reader :agent_id

    def initialize(agent_id: nil, private_key: nil, kid: nil, base_url: nil, scope: nil, timeout: 10)
      agent_id ||= ENV.fetch("TQ_AGENT_ID", "")
      raise ConfigError, "Set TQ_AGENT_ID (or agent_id:): the agt_... id from agents.create" unless agent_id.match?(/\Aagt_[a-z2-9]{20}\z/)

      private_key ||= ENV.fetch("TQ_AGENT_KEY", nil)
      raise ConfigError, "Set TQ_AGENT_KEY (or private_key:): the agent's private key" if private_key.nil? || private_key.to_s.empty?

      @agent_id = agent_id
      @key = SigningKey.load(private_key, "Touchque::Agent")
      jwk = private_key.is_a?(Hash) ? Util.stringify(private_key) : (private_key.to_s.lstrip.start_with?("{") ? Util.parse_json(private_key) : nil)
      @kid = kid || (jwk.is_a?(Hash) && jwk["kid"]) || AgentKeys.thumbprint(@key.public_jwk)
      @base_url = (base_url || (ENV["TQ_API_URL"].to_s.empty? ? DEFAULT_BASE_URL : ENV.fetch("TQ_API_URL"))).chomp("/")
      Util.assert_safe_url!(@base_url, "base_url")
      @scope = scope
      @timeout = timeout
      @token = nil
      @expires_at = 0
      @lock = Mutex.new
    end

    # The agent's current token (renewed a minute before it expires).
    def access_token
      @lock.synchronize do
        return @token if @token && @expires_at - Util.now > 60

        fetch_token
      end
    end

    # The agent as Touchque sees it: its action types, owner, review date and workspace.
    def me
      request("GET", "/agents/me")
    end

    # Asks the person to approve on their Touchque phone. Show "challengeCode" in your
    # conversation (presence interactive, the default): the person types it on the phone.
    # Touchque draws the phone's rows from +authorization_details+ (RFC 9396).
    # "requiresPasskey" (over the policy's requirePasskeyAbove): the person approves with a
    # passkey on your page instead, not on the phone.
    def request_approval(user, type, authorization_details, reason: nil, presence: nil, expires_in: nil, locale: nil,
                         reference_id: nil, client_ip: nil, user_agent: nil, mandate_id: nil)
      body = { "externalUsername" => user, "type" => type, "authorizationDetails" => Util.stringify(authorization_details) }
      { "reason" => reason, "presence" => presence, "expiresIn" => expires_in, "locale" => locale, "referenceId" => reference_id,
        "clientIp" => client_ip, "userAgent" => user_agent, "mandateId" => mandate_id }.each { |k, v| body[k] = v unless v.nil? }
      request("POST", "/agents/approvals", body)
    end

    # Asks the person for a mandate: one approval on the phone for a bounded series of
    # requests. max_total: { currency: "TRY", amount: "1000" }. Once active, pass
    # mandate_id: to request_approval: no push.
    def request_mandate(user, type, max_count, max_total, per_request: nil, recipients: nil, valid_for: nil, reason: nil,
                        expires_in: nil, locale: nil)
      body = { "externalUsername" => user, "type" => type, "maxCount" => max_count, "maxTotal" => Util.stringify(max_total) }
      { "perRequest" => per_request && Util.stringify(per_request), "recipients" => recipients, "validFor" => valid_for, "reason" => reason,
        "expiresIn" => expires_in, "locale" => locale }.each { |k, v| body[k] = v unless v.nil? }
      request("POST", "/agents/mandates", body)
    end

    # The token vault: a person's own access token at another service, for a connection
    # that names this agent: {"access_token", "token_type" => "Bearer", "expires_in",
    # "scope", "connection"}. APIError not_connected when nothing is kept.
    def get_connection_token(user, connection, scope: nil)
      request("POST", "/agents/vault/token", Util.compact({ "externalUsername" => user, "connection" => connection, "scope" => scope }))
    end

    def get_mandate(mandate_id)
      request("GET", "/agents/mandates/#{Util.seg(mandate_id)}")
    end

    def revoke_mandate(mandate_id)
      request("POST", "/agents/mandates/#{Util.seg(mandate_id)}/revoke", {})
    end

    # Where an approval request is; "approvalToken" once approved.
    def get_approval(approval_id)
      request("GET", "/agents/approvals/#{Util.seg(approval_id)}")
    end

    # Asks the person's phone and waits for the answer: the approved state (holding
    # "approvalToken"), or ApprovalError / TimeoutError. The block (or +on_challenge+)
    # gets the state while the phone waits: show its "challengeCode". Put it in front of
    # any tool call an agent framework makes, so the call runs only after the person approved.
    def require_approval(user, type, authorization_details, on_challenge: nil, timeout: 300, **options, &block)
      on_challenge ||= block
      asked = request_approval(user, type, authorization_details, **options)
      return asked if asked["status"] == "approved" && asked["approvalToken"]

      on_challenge&.call(asked) if asked["challengeCode"]
      wait_for_approval(asked["approvalId"], timeout: timeout)
    end

    # Polls until the person approves (the state holding "approvalToken"). ApprovalError
    # when it ends otherwise, TimeoutError after +timeout+ seconds. An approval given
    # during a phone call stays provisional until the phone confirms it.
    def wait_for_approval(approval_id, timeout: 600, interval: 2.0)
      interval = [interval, 0.5].max
      deadline = Time.now + timeout
      loop do
        state = get_approval(approval_id)
        return state if state["status"] == "approved" && state["approvalToken"]
        raise ApprovalError.new(approval_id, state["status"], state["reason"]) if ENDED.include?(state["status"])
        raise TimeoutError.new("Touchque: approval '#{approval_id}' was not approved within #{timeout}s", approval_id) if Time.now + interval > deadline

        sleep interval
      end
    end

    private

    def fetch_token
      url = "#{@base_url}/agents/token"
      now = Util.now
      assertion = @key.jws({ "typ" => "JWT", "kid" => @kid },
                           { "iss" => @agent_id, "sub" => @agent_id, "aud" => url, "iat" => now, "exp" => now + 60, "jti" => Util.random_hex(16) })
      form = { "grant_type" => "client_credentials", "client_assertion_type" => ASSERTION_TYPE, "client_assertion" => assertion, "scope" => @scope }
      status, text, = Transport.call("POST", url, headers: { "Content-Type" => "application/x-www-form-urlencoded", "DPoP" => dpop("POST", url) },
                                                  body: Transport.form(form), timeout: @timeout)
      data = Util.parse_json(text)
      raise Transport.oauth_failure(status, data) unless status == 200 && data.is_a?(Hash) && data["access_token"]

      @token = data["access_token"]
      @expires_at = Util.now + (data["expires_in"] || 600).to_i
      @token
    end

    def dpop(method, url, access_token = nil)
      claims = { "htm" => method, "htu" => url, "iat" => Util.now, "jti" => Util.random_hex(16) }
      claims["ath"] = AgentKeys.access_token_hash(access_token) if access_token
      @key.jws({ "typ" => "dpop+jwt", "jwk" => @key.public_jwk }, claims)
    end

    # A call with the agent's token and a fresh DPoP proof; one retry with a new token
    # when Touchque no longer knows it.
    def request(method, path, body = nil, retried: false)
      token = access_token
      url = @base_url + path
      headers = { "Authorization" => "DPoP #{token}", "DPoP" => dpop(method, url.split("?").first, token) }
      headers["Content-Type"] = "application/json" unless body.nil?
      status, text, = Transport.call(method, url, headers: headers, body: body.nil? ? nil : Util.json(body), timeout: @timeout)
      data = Util.parse_json(text)
      data = {} unless data.is_a?(Hash)
      if status == 401 && !retried && data["code"] == "invalid_token"
        @lock.synchronize { @token = nil if @token == token }
        return request(method, path, body, retried: true)
      end
      raise Transport.oauth_failure(status, data) unless (200..299).cover?(status)

      data
    end
  end
end
