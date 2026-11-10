# frozen_string_literal: true

module TouchQue
  # A refused Security Event Token (Shared Signals). +error+ is the RFC 8935 error
  # to answer with (HTTP 400 {"err": error}): invalid_request, invalid_key,
  # invalid_issuer or invalid_audience; temporarily_unavailable when the issuer's
  # keys could not be read (answer 503: the transmitter tries again).
  class SecurityEventError < Error
    attr_reader :error

    def initialize(error, message)
      @error = error
      super(message)
    end
  end

  # Shared Signals (OpenID Shared Signals Framework 1.0): Security Event Tokens
  # (SETs, RFC 8417) an identity provider sends when something happens to a
  # person's account after sign-in: CAEP session-revoked, credential-change,
  # device-compliance-change; RISC account-disabled, credential-compromise.
  # TouchQue SSO sends them for an organization's members to the receivers its
  # admin adds (Organization > Continuous access). Your app ends the person's
  # sessions or asks them to sign in again.
  #
  # Push delivery (RFC 8935), the SET is the request body (application/secevent+jwt):
  #
  #   VERIFIER = TouchQue::SecurityEventVerifier.new(issuer: "https://sso.touchque.com", audience: "https://app.example.com")
  #   post "/ssf" do
  #     event = VERIFIER.verify(request.body.read)
  #     end_sessions_of(event["subject"]["email"]) if event["name"] == "session-revoked"
  #     status 202
  #   rescue TouchQue::SecurityEventError => e
  #     halt 400, { err: e.error, description: e.message }.to_json
  #   end
  #
  # Poll delivery (RFC 8936): TouchQue::SecurityEvents.poll(url:, token:, ack: [...]).
  #
  # A SET does not expire: it says what happened. Keep the jtis you handled and
  # skip a repeat.
  module SecurityEvents
    # The event types TouchQue sends, by their short name.
    TYPES = {
      "session-revoked" => "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
      "credential-change" => "https://schemas.openid.net/secevent/caep/event-type/credential-change",
      "device-compliance-change" => "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change",
      "account-disabled" => "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
      "credential-compromise" => "https://schemas.openid.net/secevent/risc/event-type/credential-compromise",
      "verification" => "https://schemas.openid.net/secevent/ssf/event-type/verification",
      "stream-updated" => "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"
    }.freeze
    NAMESPACE = %r{\Ahttps://schemas\.openid\.net/secevent/(caep|risc|ssf)/event-type/([a-z0-9-]+)\z}.freeze

    module_function

    # One poll: acknowledges what you handled and returns { "sets" => { jti => token }, "more_available" => bool }.
    def poll(url:, token:, ack: nil, set_errs: nil, max_events: nil, return_immediately: nil)
      raise ConfigError, "#{url} must be an https URL" unless CrossAppAccess.safe_url?(url)
      raise ConfigError, "poll needs the stream's token" if token.to_s.empty?

      body = {}
      body["ack"] = ack unless ack.nil?
      body["setErrs"] = set_errs unless set_errs.nil?
      body["maxEvents"] = max_events unless max_events.nil?
      body["returnImmediately"] = return_immediately unless return_immediately.nil?
      headers = { "Content-Type" => "application/json", "Accept" => "application/json", "Authorization" => "Bearer #{token}" }
      status, text, = Transport.call("POST", url, headers: headers, body: JSON.generate(body), timeout: 30)
      data = Util.parse_json(text)
      data = {} unless data.is_a?(Hash)
      raise SecurityEventError.new((data["error"] || "server_error").to_s, "#{url} answered #{status}") unless status == 200

      { "sets" => data["sets"].is_a?(Hash) ? data["sets"] : {}, "more_available" => data["moreAvailable"] == true }
    end
  end

  # Checks a SET: signature (RS256, the issuer's keys), typ, issuer, audience, one event.
  class SecurityEventVerifier
    def initialize(issuer:, audience:, jwks_uri: nil, jwks: nil, clock_skew: 300, fetch: nil)
      raise ConfigError, "SecurityEventVerifier needs issuer (the transmitter) and audience (your stream's aud)" if issuer.to_s.empty? || audience.to_s.empty?

      @issuer = issuer
      @audience = audience
      @jwks_uri = jwks_uri
      @skew = clock_skew
      @fetch = fetch || CrossAppAccess.method(:get_json)
      @pinned = !jwks.nil?
      @keys = {}
      @keys_at = 0
      @tried_at = 0
      @lock = Mutex.new
      set_keys(jwks) if jwks
    end

    # The SET, checked: { "jti", "issuer", "audience" (list), "issued_at", "txn" (TouchQue's case code),
    # "subject" (sub_id), "type" (URI), "name" (short name, or nil), "claims" (the event's own) },
    # or SecurityEventError.
    def verify(token)
      bad = ->(message) { SecurityEventError.new("invalid_request", message) }
      parts = JWS.split(token.to_s.strip)
      raise bad.call("not a JWT") unless parts

      head, c, input, sig = parts
      raise bad.call("not a Security Event Token (typ secevent+jwt)") unless head["typ"].to_s.downcase == "secevent+jwt"
      raise SecurityEventError.new("invalid_key", "unsupported signature") unless head["alg"] == "RS256" && head["kid"].is_a?(String)

      key = begin
        key_for(head["kid"])
      rescue StandardError => e
        raise SecurityEventError.new("temporarily_unavailable", "the transmitter's keys could not be read: #{e.message}")
      end
      raise SecurityEventError.new("invalid_key", "signature does not verify") unless key && JWS.verify("RS256", key, input, sig)
      raise SecurityEventError.new("invalid_issuer", "another issuer") unless c["iss"] == @issuer

      audience = (c["aud"].is_a?(Array) ? c["aud"] : [c["aud"]]).select { |a| a.is_a?(String) }
      raise SecurityEventError.new("invalid_audience", "not for this receiver") unless audience.include?(@audience)
      raise bad.call("jti and iat are required") unless c["jti"].is_a?(String) && c["iat"].is_a?(Integer)
      raise bad.call("issued in the future") if c["iat"] - @skew > Util.now

      events = c["events"]
      raise bad.call("a SET carries exactly one event") unless events.is_a?(Hash) && events.length == 1

      type, claims = events.first
      m = SecurityEvents::NAMESPACE.match(type)
      {
        "jti" => c["jti"], "issuer" => c["iss"], "audience" => audience, "issued_at" => c["iat"],
        "txn" => c["txn"].is_a?(String) ? c["txn"] : nil, "subject" => c["sub_id"].is_a?(Hash) ? c["sub_id"] : {},
        "type" => type, "name" => m ? m[2] : nil, "claims" => claims.is_a?(Hash) ? claims : {}
      }
    end

    private

    def set_keys(jwks)
      @keys = (jwks["keys"] || []).each_with_object({}) { |k, h| h[k["kid"]] = k if k["kid"] }
      @keys_at = Util.now
    end

    def load_keys
      unless @jwks_uri
        meta = @fetch.call("#{@issuer.chomp("/")}/.well-known/ssf-configuration")
        raise "the transmitter's metadata does not match its issuer" unless meta["issuer"] == @issuer && meta["jwks_uri"].is_a?(String)

        @jwks_uri = meta["jwks_uri"]
      end
      raise "#{@jwks_uri} must be an https URL" unless CrossAppAccess.safe_url?(@jwks_uri)

      set_keys(@fetch.call(@jwks_uri))
    end

    def key_for(kid)
      return @keys[kid] if @pinned

      @lock.synchronize do
        load_keys if @keys_at.zero? || Util.now - @keys_at > 3600
        if !@keys.key?(kid) && Util.now - @tried_at > 300
          @tried_at = Util.now
          load_keys
        end
        @keys[kid]
      end
    end
  end
end
