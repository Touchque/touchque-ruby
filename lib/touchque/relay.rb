# frozen_string_literal: true

module Touchque
  # What the relay wants sent back: a status, a JSON body and headers. +on_authenticated+
  # receives the pending success response and may change it (e.g. add a Set-Cookie);
  # the handler sets the body afterwards.
  class RelayResponse
    attr_accessor :status, :body
    attr_reader :headers

    def initialize(status = 200, body = {})
      @status = status
      @body = body
      @headers = []
    end

    # Sets a header, replacing any value it had.
    def set_header(name, value)
      @headers.reject! { |(n, _)| n.casecmp?(name) }
      @headers << [name, value.to_s]
      self
    end

    # Adds a header value, keeping existing ones (several Set-Cookie).
    def add_header(name, value)
      @headers << [name, value.to_s]
      self
    end

    def header(name)
      @headers.find { |(n, _)| n.casecmp?(name) }&.last
    end

    def to_json(*)
      Util.json(@body)
    end
  end

  # Counters for the relay's rate limits. +hit+ must atomically count one hit for +key+
  # in its fixed window and return [count, reset_at_ms]. Several processes (Puma
  # clusters, several hosts): implement it over Redis (INCR + PEXPIRE, then PTTL).
  class MemoryRateLimitStore
    def initialize(max_entries: 50_000)
      @max_entries = [max_entries, 2].max
      @entries = {}
      @lock = Mutex.new
    end

    def hit(key, window_ms, now_ms)
      @lock.synchronize do
        count, reset_at = @entries[key]
        if count.nil? || reset_at <= now_ms
          prune(now_ms) if count.nil? && @entries.size >= @max_entries
          count = 0
          reset_at = now_ms + window_ms
        end
        @entries[key] = [count + 1, reset_at]
      end
    end

    private

    def prune(now_ms)
      @entries.delete_if { |_, (_, reset_at)| reset_at <= now_ms }
      # Still full (a flood of distinct keys): drop the oldest half rather than grow without bound.
      @entries.shift while @entries.size >= @max_entries / 2 + 1 if @entries.size >= @max_entries
    end
  end

  # Fixed-window rate limiter for the relay's pre-auth routes.
  class FixedWindowLimiter
    attr_reader :per_ip, :per_user

    def initialize(window_seconds: 60, per_ip: 20, per_user: 5, store: nil)
      @window_ms = (window_seconds * 1000).to_i
      @per_ip = per_ip
      @per_user = per_user
      @store = store || MemoryRateLimitStore.new
    end

    # Counts one hit. Seconds to wait when over +limit+, otherwise 0.
    def hit(key, limit, now_ms = Util.now_ms)
      count, reset_at = @store.hit(key, @window_ms, now_ms)
      return 0 if count <= limit

      [1, ((reset_at - now_ms) / 1000.0).ceil].max
    end
  end

  # Framework-agnostic relay: the routes a frontend (@touchque/web) needs for push 2FA,
  # offline codes and passkeys, so you don't hand-write them (Touchque::Rack::Relay
  # mounts it in Rails, Sinatra or any Rack app):
  #
  #   POST   /enroll/start                  (signed in)  generate_secret answer
  #   GET    /enroll/status                 (signed in)  {linked, used, deviceId}
  #   POST   /login                         (pre-auth)   202 {touchque: step, token} until approved
  #   POST   /offline/challenge|verify|totp (pre-auth)   offline codes
  #   POST   /passkey/authenticate/options|verify        passwordless sign-in (no email: any passkey)
  #   POST   /passkey/login/options|verify               approve a pending request with a passkey
  #   POST   /passkey/register/options|verify (signed in) the phone approves adding a passkey first
  #   GET    /passkey/credentials           (signed in)
  #   DELETE /passkey/credentials/{id}      (signed in)
  #
  # Options (callables get the native request you pass to +handle+):
  #   get_user_id      (required) the signed-in user, for the signed-in routes.
  #   get_login_user   the user who passed YOUR first factor. STRONGLY RECOMMENDED: /login
  #                    and the offline routes then act for this user and ignore the body's.
  #                    Without it /login never shows the linking QR: a user with no phone gets
  #                    202 {touchque: {state: "enroll", reason: "enrollment_off"}}, as passkey
  #                    registration does.
  #   rate_limit       { window_seconds:, per_ip: 20, per_user: 5, store: } or false.
  #   allow_offline_without_first_factor  let the offline routes trust the body's username.
  #   action_type      for /login and the offline routes (default LOGIN).
  #   get_details      transaction context, built from server-side state.
  #   on_authenticated ->(req, response, info) right before a success answer: open your
  #                    session here; info: {"externalUsername", "requestId", "via"}
  #                    (via: login, passkey, offline, offline-totp, silent).
  #   silent_sign_in   true or { max_age_seconds: }: a known browser with nothing new skips the push.
  class RelayHandler
    POLLS_PER_ATTEMPT = 10
    PASSKEY_ENROLL_ACTION = "PASSKEY_ENROLL"
    ROUTES = {
      "POST /enroll/start" => :enroll_start, "GET /enroll/status" => :enroll_status, "POST /login" => :login,
      "POST /offline/challenge" => :offline_challenge, "POST /offline/verify" => :offline_verify, "POST /offline/totp" => :offline_totp,
      "POST /passkey/authenticate/options" => :passkey_authenticate_options, "POST /passkey/authenticate/verify" => :passkey_authenticate_verify,
      "POST /passkey/login/options" => :passkey_login_options, "POST /passkey/login/verify" => :passkey_login_verify,
      "POST /passkey/register/options" => :passkey_register_options, "POST /passkey/register/verify" => :passkey_register_verify,
      "GET /passkey/credentials" => :passkey_credentials
    }.freeze

    @warned = false

    class << self
      attr_accessor :warned
    end

    def initialize(client, get_user_id:, get_login_user: nil, rate_limit: {}, allow_offline_without_first_factor: false,
                   action_type: "LOGIN", get_details: nil, on_authenticated: nil, silent_sign_in: false)
      raise ArgumentError, "RelayHandler: get_user_id must be callable" unless get_user_id.respond_to?(:call)

      Guard.assert_silent_sign_in!(silent_sign_in, "RelayHandler")
      @tq = client
      @get_user_id = get_user_id
      @get_login_user = get_login_user
      @get_details = get_details
      @on_authenticated = on_authenticated
      @action_type = action_type
      @silent_sign_in = silent_sign_in
      @limiter = rate_limit == false ? nil : FixedWindowLimiter.new(**(rate_limit || {}))
      @offline_enabled = !get_login_user.nil? || allow_offline_without_first_factor == true
      return if get_login_user || self.class.warned

      self.class.warned = true
      Touchque.log :warn, "[Touchque] RelayHandler: POST /login takes the username from the request body" \
           "#{@offline_enabled ? ", and so do the offline routes" : "; the offline routes are disabled until you set it"}" \
           ". Set get_login_user to bind them to your first factor (password step) so they cannot be used against arbitrary users."
    end

    # Handles one relay request; nil when no relay route matches (answer 404 yourself).
    # path: relative to where the relay is mounted ("/login"). body: the decoded JSON
    # (a Hash). ip: the real client IP ("" when unknown). header: ->(name) { value }.
    def handle(method:, path:, body: {}, ip: "", user_agent: nil, header: ->(_) {}, request: nil)
      method = method.to_s.upcase
      method = "GET" if method == "HEAD"
      path = "/" + path.to_s.split("?", 2).first.to_s.gsub(%r{\A/+|/+\z}, "")
      ctx = { body: body.is_a?(Hash) ? Util.stringify(body) : {}, ip: ip.to_s, user_agent: user_agent, header: header, req: request }
      route = ROUTES["#{method} #{path.downcase}"]
      return send(route, ctx) if route

      if method == "DELETE" && (m = path.match(%r{\A/passkey/credentials/([^/]+)\z}i))
        return delete_credential(ctx, m[1])
      end

      nil
    end

    private

    def enroll_start(ctx)
      user_id = user_id(ctx)
      return unauthorized unless user_id

      begin
        RelayResponse.new(200, @tq.auth.generate_secret(user_id))
      rescue APIError => e
        return relay_error(e) unless e.status == 409

        # 409: a QR was issued and not scanned yet (safe to issue a new one), or a phone is
        # ALREADY linked. Replacing a linked phone must never happen from a plain session.
        begin
          current = @tq.auth.get_user(user_id)
          if current["used"] || current["deviceId"]
            return RelayResponse.new(409, { "error" => "already_linked", "message" => "A phone is already linked to this account." })
          end

          RelayResponse.new(200, @tq.auth.reset_secret(user_id))
        rescue StandardError => retry_error
          relay_error(retry_error)
        end
      rescue StandardError => e
        relay_error(e)
      end
    end

    def enroll_status(ctx)
      user_id = user_id(ctx)
      return unauthorized unless user_id

      u = @tq.auth.get_user(user_id)
      RelayResponse.new(200, { "linked" => !!(u["used"] && u["deviceId"]), "used" => u["used"], "deviceId" => u["deviceId"] })
    rescue APIError => e
      return RelayResponse.new(200, { "linked" => false, "used" => false, "deviceId" => nil }) if e.status == 404

      relay_error(e)
    rescue StandardError => e
      relay_error(e)
    end

    def login(ctx)
      user, refusal = login_user(ctx)
      return refusal if refusal

      input = Guard.input_from_headers(ctx[:header])
      details = @get_details&.call(ctx[:req])
      proof = Guard.silent_on?(@silent_sign_in) ? Guard.presence(ctx[:header].call(Guard::BROWSER_HEADER)) : nil
      # Polling an approval already sent is not a new attempt: its own, larger per-IP budget.
      poll = Guard.status_poll?(@tq, user, @action_type, details: details, token: input[:token], offline: input[:offline], code: input[:code])
      limited = poll ? allow(ctx, "login-poll", nil, POLLS_PER_ATTEMPT) : allow(ctx, "login", user)
      return limited if limited

      # A first-time QR poll that starts after all (the user linked, or the QR is gone) is
      # charged like a new attempt: a replayed token must not push on the poll budget.
      refused = nil
      before_start = if poll
                       lambda do
                         refused = allow(ctx, "login", user)
                         refused && { status: refused.status, body: refused.body }
                       end
                     end
      result = Guard.run(@tq, user, @action_type, details: details, ip: ctx[:ip].empty? ? nil : ctx[:ip], user_agent: ctx[:user_agent],
                                                  token: input[:token], offline: input[:offline], code: input[:code], code_type: input[:code_type],
                                                  # Pre-auth: a typed username proves nothing, so no linking QR unless get_login_user ties this route to the password step.
                                                  enroll: !@get_login_user.nil?, browser_proof: proof, silent_sign_in: @silent_sign_in,
                                                  before_start: before_start)
      return refused if refused
      return guard_response(result) unless result[:approved]

      approved = result[:approved]
      res = RelayResponse.new(200)
      begin
        if @on_authenticated
          via = { "OFFLINE_TOTP" => "offline-totp", "OFFLINE_CODE" => "offline", "SILENT" => "silent" }.fetch(approved["confirmedVia"], "login")
          @on_authenticated.call(ctx[:req], res, { "externalUsername" => user, "requestId" => approved["requestId"], "via" => via })
        end
        res.body = { "status" => "success", "requestId" => approved["requestId"], "assurance" => approved["assurance"] }
        res
      rescue StandardError => e
        auth_result_error(e)
      end
    end

    # A guard answer that is not an approval, as Guard.response gives it (no-store, Retry-After,
    # X-Touchque-State / -Reason); the Rack relay adds the content type itself.
    def guard_response(result)
      status, headers, body_json = Guard.response(result)
      res = RelayResponse.new(status, JSON.parse(body_json))
      headers.each { |name, value| res.set_header(name, value) unless name == "content-type" }
      res
    end

    # The username used for on_authenticated is the one Touchque returns for the code, never the body's.
    def offline_challenge(ctx)
      return offline_disabled unless @offline_enabled

      user, refusal = login_user(ctx)
      return refusal if refusal

      limited = allow(ctx, "offline-challenge", user)
      return limited if limited

      c = @tq.offline.challenge(user, type: @action_type, details: @get_details&.call(ctx[:req]), client_ip: ctx[:ip].empty? ? nil : ctx[:ip],
                                      user_agent: ctx[:user_agent], request_id: body_request_id(ctx[:body]))
      out = c.slice("challengeId", "qr", "qrDataUrl", "expiresAt", "expiresInSeconds", "totpAvailable")
      out["challengeCode"] = c["challengeCode"] if c["challengeCode"] && !c["challengeCode"].empty?
      RelayResponse.new(200, out)
    rescue StandardError => e
      relay_error(e)
    end

    def offline_verify(ctx)
      return offline_disabled unless @offline_enabled

      limited = allow(ctx, "offline-verify")
      return limited if limited

      r = @tq.offline.verify(body_string(ctx[:body], "challengeId"), body_string(ctx[:body], "code"))
      if !r["approved"] || r["externalUsername"].to_s.empty?
        return RelayResponse.new(r["reason"] == "invalid_code" ? 401 : 400, { "approved" => false }.merge(r.slice("reason", "attemptsLeft").compact))
      end
      # With a first factor, the code must belong to the user who passed it.
      if @get_login_user && !same_user?(@get_login_user.call(ctx[:req]), r["externalUsername"])
        return RelayResponse.new(401, { "approved" => false, "reason" => "invalid_code" })
      end

      res = RelayResponse.new(200)
      @on_authenticated&.call(ctx[:req], res, { "externalUsername" => r["externalUsername"], "requestId" => r["challengeId"], "via" => "offline" })
      res.body = { "status" => "success", "approved" => true, "requestId" => r["challengeId"] }.compact
      res
    rescue StandardError => e
      relay_error(e)
    end

    def offline_totp(ctx)
      return offline_disabled unless @offline_enabled

      user, refusal = login_user(ctx)
      return refusal if refusal

      limited = allow(ctx, "offline-totp", user)
      return limited if limited

      r = @tq.offline.verify_totp(user, body_string(ctx[:body], "code"), type: @action_type, client_ip: ctx[:ip].empty? ? nil : ctx[:ip],
                                                                         request_id: body_request_id(ctx[:body]))
      if !r["approved"] || r["externalUsername"].to_s.empty?
        return RelayResponse.new(r["reason"] == "invalid_code" ? 401 : 400, { "approved" => false }.merge(r.slice("reason").compact))
      end

      res = RelayResponse.new(200)
      @on_authenticated&.call(ctx[:req], res, { "externalUsername" => r["externalUsername"], "via" => "offline-totp" })
      res.body = { "status" => "success", "approved" => true }
      res
    rescue StandardError => e
      relay_error(e)
    end

    def passkey_authenticate_options(ctx)
      email = body_string(ctx[:body], "email").downcase
      limited = allow(ctx, "passkey-options", email.empty? ? nil : email)
      return limited if limited

      RelayResponse.new(200, @tq.webauthn.primary_options(email.empty? ? nil : email))
    rescue StandardError => e
      relay_error(e)
    end

    def passkey_authenticate_verify(ctx)
      limited = allow(ctx, "passkey-verify")
      return limited if limited

      r = @tq.webauthn.primary_verify(body_string(ctx[:body], "attemptId"), body_hash(ctx[:body], "response"))
      if r["success"]
        res = RelayResponse.new(200)
        @on_authenticated&.call(ctx[:req], res, { "externalUsername" => r["externalUsername"], "requestId" => r["requestId"], "via" => "passkey" })
        res.body = { "status" => "success", "requestId" => r["requestId"] }.compact
        return res
      end
      return RelayResponse.new(200, { "requiresStepUp" => true }) if r["requiresStepUp"]

      RelayResponse.new(401, { "error" => "verification_failed" })
    rescue StandardError => e
      relay_error(e)
    end

    def passkey_login_options(ctx)
      limited = allow(ctx, "passkey-approve")
      return limited if limited

      RelayResponse.new(200, @tq.webauthn.authenticate_options(body_string(ctx[:body], "requestId")))
    rescue StandardError => e
      relay_error(e)
    end

    def passkey_login_verify(ctx)
      limited = allow(ctx, "passkey-approve")
      return limited if limited

      r = @tq.webauthn.authenticate_verify(body_string(ctx[:body], "requestId"), body_hash(ctx[:body], "response"))
      who = r["externalUsername"]
      # Open the session only for the user Touchque says was approved; a name the browser sent is never trusted.
      if r["success"] && @get_login_user && who.is_a?(String) && !same_user?(@get_login_user.call(ctx[:req]), who)
        return RelayResponse.new(401, { "error" => "verification_failed" })
      end

      res = RelayResponse.new(200)
      if r["success"] && @on_authenticated && who.is_a?(String) && !who.empty?
        request_id = r["requestId"].to_s.empty? ? ctx[:body]["requestId"] : r["requestId"]
        @on_authenticated.call(ctx[:req], res, { "externalUsername" => who, "requestId" => request_id, "via" => "passkey" })
      end
      res.body = r
      res
    rescue StandardError => e
      relay_error(e)
    end

    # A user with a linked phone approves adding a passkey there first: a passkey approves
    # requests on its own, so a stolen session must not be able to add one.
    def passkey_register_options(ctx)
      user_id = user_id(ctx)
      return unauthorized unless user_id

      input = Guard.input_from_headers(ctx[:header])
      unless input[:token]
        begin
          return RelayResponse.new(200, @tq.webauthn.register_options(user_id, discoverable: true))
        rescue APIError => e
          raise unless e.status == 403 && e.code == "enrollment_approval_required"
        end
      end
      limited = if Guard.status_poll?(@tq, user_id, PASSKEY_ENROLL_ACTION, token: input[:token], offline: input[:offline], code: input[:code])
                  allow(ctx, "login-poll", nil, POLLS_PER_ATTEMPT)
                else
                  allow(ctx, "passkey-enroll", user_id)
                end
      return limited if limited

      result = Guard.run(@tq, user_id, PASSKEY_ENROLL_ACTION, ip: ctx[:ip].empty? ? nil : ctx[:ip], user_agent: ctx[:user_agent],
                                                             token: input[:token], offline: input[:offline], code: input[:code], code_type: input[:code_type], enroll: false)
      return guard_response(result) unless result[:approved]

      RelayResponse.new(200, @tq.webauthn.register_options(user_id, discoverable: true, approval_request_id: result[:approved]["requestId"]))
    rescue StandardError => e
      relay_error(e)
    end

    def passkey_register_verify(ctx)
      user_id = user_id(ctx)
      return unauthorized unless user_id

      label = ctx[:body]["label"].is_a?(String) ? ctx[:body]["label"] : nil
      RelayResponse.new(200, @tq.webauthn.register_verify(user_id, body_hash(ctx[:body], "response"), label: label))
    rescue StandardError => e
      relay_error(e)
    end

    def passkey_credentials(ctx)
      user_id = user_id(ctx)
      return unauthorized unless user_id

      RelayResponse.new(200, @tq.webauthn.list_credentials(user_id))
    rescue StandardError => e
      relay_error(e)
    end

    def delete_credential(ctx, raw_id)
      user_id = user_id(ctx)
      return unauthorized unless user_id

      id = begin
        URI.decode_www_form_component(raw_id)
      rescue ArgumentError
        # A malformed %-encoding (%zz) is the browser's mistake, not a relay failure.
        return RelayResponse.new(400, { "error" => "invalid_credential_id" })
      end
      RelayResponse.new(200, @tq.webauthn.delete_credential(id, external_username: user_id))
    rescue StandardError => e
      relay_error(e)
    end

    def user_id(ctx)
      v = @get_user_id.call(ctx[:req])
      v.nil? || v == false || v.to_s.empty? ? nil : v.to_s
    end

    # Who a pre-auth route acts for: the first-factor user when configured, otherwise the typed username.
    def login_user(ctx)
      if @get_login_user
        u = @get_login_user.call(ctx[:req])
        return [nil, RelayResponse.new(401, { "error" => "FIRST_FACTOR_REQUIRED", "message" => "Sign in with your password first." })] if u.nil? || u == false || u.to_s.empty?

        return [u.to_s.downcase, nil]
      end
      typed = body_string(ctx[:body], "externalUsername").downcase
      return [nil, RelayResponse.new(400, { "error" => "externalUsername_required" })] if typed.empty?

      [typed, nil]
    end

    # nil when allowed; otherwise the 429 to send.
    def allow(ctx, route, user = nil, ip_factor = 1)
      return nil unless @limiter

      ip_wait = @limiter.hit("ip|#{route}|#{ctx[:ip].empty? ? "unknown" : ctx[:ip]}", @limiter.per_ip * ip_factor)
      user_wait = user.to_s.empty? ? 0 : @limiter.hit("user|#{route}|#{user}", @limiter.per_user)
      wait = [ip_wait, user_wait].max
      return nil if wait.zero?

      RelayResponse.new(429, { "error" => "RATE_LIMITED", "message" => "Too many attempts. Try again later.", "retryAfter" => wait })
                   .set_header("Retry-After", wait)
    end

    def unauthorized
      RelayResponse.new(401, { "error" => "UNAUTHORIZED_FOR_2FA",
                               "message" => "Could not find user ID in request. Put your own auth middleware in front of this router." })
    end

    def offline_disabled
      RelayResponse.new(403, { "error" => "OFFLINE_REQUIRES_FIRST_FACTOR",
                               "message" => "Offline sign-in is disabled: configure get_login_user (or allow_offline_without_first_factor) on the Touchque relay." })
    end

    # Same status mapping as the guard middleware, kept in sync with the Node SDK.
    def auth_result_error(error)
      case error
      when RejectedError then RelayResponse.new(403, { "error" => "2FA_REJECTED", "message" => "User rejected the 2FA request on their device." })
      when PasskeyRequiredError then RelayResponse.new(409, { "error" => "PASSKEY_REQUIRED", "requestId" => error.request_id, "message" => "Approve this sign-in with your passkey." })
      when TimeoutError then RelayResponse.new(408, { "error" => "2FA_TIMEOUT", "message" => "User did not respond to the 2FA request in time." })
      else
        if error.is_a?(APIError) && error.status < 500
          return RelayResponse.new(error.status, { "error" => [error.error, error.data["message"], error.message].find { |t| t.is_a?(String) && !t.empty? } || "request_failed" })
        end

        Touchque.log :error, "[Touchque Relay Error] #{error.class}: #{error.message}"
        RelayResponse.new(503, { "error" => "2FA_UNAVAILABLE", "message" => "The 2FA verification service is temporarily unavailable." })
      end
    end

    # A client-range Touchque status is forwarded with its machine-readable code only
    # (never Touchque's message text); anything else becomes 502.
    def relay_error(error)
      if error.is_a?(APIError) && error.status < 500
        return RelayResponse.new(error.status, { "error" => [error.code, error.error].find { |t| t.is_a?(String) && !t.empty? } || "request_failed" })
      end

      RelayResponse.new(502, { "error" => "relay_error" })
    end

    def same_user?(expected, actual)
      return false if expected.nil? || expected == false || expected.to_s.empty?

      expected.to_s.downcase == actual.to_s.downcase
    end

    def body_string(body, field)
      v = body[field]
      v.is_a?(String) || v.is_a?(Numeric) ? v.to_s : ""
    end

    def body_hash(body, field)
      body[field].is_a?(Hash) ? body[field] : {}
    end

    def body_request_id(body)
      body["requestId"].is_a?(String) && !body["requestId"].empty? ? body["requestId"] : nil
    end
  end
end
