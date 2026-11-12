# frozen_string_literal: true

module Touchque
  # The headless step-up flow shared by every integration: start → show the step in
  # YOUR UI → check → complete exactly once. A "step" is a plain Hash, safe to send to
  # the browser as JSON: state (waiting | approved | rejected | expired | enroll |
  # passkey_required | offline | blocked | frozen | rate_limited) and whatever the user
  # has to see (the matching number, the enrollment QR, the offline QR). No secrets.
  module Steps
    STATE_MAP = { "PENDING" => "waiting", "CONFIRMED" => "approved", "REJECTED" => "rejected", "EXPIRED" => "expired" }.freeze

    module_function

    # Starts an approval for +action+; never waits. A user with no phone linked gets the
    # linking QR ("enroll"); with enroll: false, {"state" => "enroll", "reason" => "enrollment_off"}.
    def start(client, action, user, details: nil, reference_id: nil, ip: nil, user_agent: nil, enroll: true, browser_proof: nil, context: nil)
      raise ConfigError, "start() needs the user id" if user.to_s.empty?

      norm = Details.normalize(details)
      norm = nil if norm.empty?
      begin
        res = client.login.request(user, type: action, reference_id: reference_id, client_ip: ip, user_agent: user_agent,
                                         details: norm, browser_proof: browser_proof, context: context)
        canary = res.dig("canary", "url").is_a?(String) ? { "url" => res.dig("canary", "url") } : nil
        if res["requiresPasskey"]
          step = { "state" => "passkey_required", "requestId" => res["requestId"], "expiresAt" => res["expiresAt"], "details" => norm }.merge(why(res))
          step["canary"] = canary if canary
          return step
        end
        step = { "state" => "waiting", "requestId" => res["requestId"], "number" => res["challengeCode"],
                 "expiresAt" => res["expiresAt"], "details" => norm }.merge(why(res))
        # Only when the workspace collects behavioural signals.
        step["telemetryToken"] = res["telemetryToken"] if res["telemetryToken"] && !res["telemetryToken"].empty?
        # Mirror Alarm: the page showing this first step loads the canary.
        step["canary"] = canary if canary
        step
      rescue APIError => e
        code = e.code || e.error
        why = e.case_code ? { "caseCode" => e.case_code } : {}
        if e.status == 404 && (code == "device_not_linked" || e.message.downcase.include?("linked device"))
          # No phone, and this guard may not show the linking QR: final, a page stops polling.
          return enroll ? enroll_step(client, user) : { "state" => "enroll", "reason" => "enrollment_off" }
        end
        return { "state" => "frozen", "retryAfter" => e.retry_after }.merge(why) if e.status == 423
        return { "state" => "rate_limited", "retryAfter" => e.retry_after }.merge(why) if e.status == 429
        if e.status == 400 && (code == "unknown_action" || e.message.downcase.include?("invalid action type"))
          raise ConfigError, "Unknown action \"#{action}\". Create it once with client.action_types.define(\"#{action}\") or in the dashboard (Action Types)."
        end
        if e.status == 403
          reason = (code == "blocked" ? e.reason : nil) ||
                   (code == "passkey_not_registered" || e.error == "phishing_resistant_required" ? "passkey_not_registered" : nil) ||
                   (code == "action_disabled" ? "action_disabled" : nil) || code || "blocked"
          return { "state" => "blocked", "reason" => reason }.merge(why)
        end
        raise
      end
    end

    # First-time linking. Never unlinks a phone: a secret is only re-issued when the
    # account is confirmed NOT linked.
    def enroll_step(client, user)
      enroll_qr(client.auth.generate_secret(user))
    rescue APIError => e
      raise unless e.status == 409

      current = begin
        client.auth.get_user(user)
      rescue APIError
        nil
      end
      return { "state" => "enroll", "reason" => "already_linked" } if current && (current["used"] || current["deviceId"])

      enroll_qr(client.auth.reset_secret(user))
    end

    # The enroll step for a new linking QR. "expiresAt" is when the QR stops working: the
    # API's expiresAt when it is an ISO 8601 date-time, else now + its ttlMs, else none.
    def enroll_qr(res)
      enroll = res.slice("qrCodeDataUrl", "recoveryCodes")
      if iso_ms(res["expiresAt"])
        enroll["expiresAt"] = res["expiresAt"]
      elsif res["ttlMs"].is_a?(Numeric) && res["ttlMs"].positive?
        enroll["expiresAt"] = iso_of(Util.now_ms + res["ttlMs"].to_i)
      end
      { "state" => "enroll", "enroll" => enroll }
    end

    ISO_8601 = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})\z/i

    # @api private: milliseconds since the epoch of an ISO 8601 date-time with a zone
    # ("2026-11-12T10:05:00.000Z"), or nil.
    def iso_ms(value)
      return nil unless value.is_a?(String) && value.match?(ISO_8601)

      require "time"
      time = Time.iso8601(value)
      time.to_i * 1000 + time.usec / 1000
    rescue ArgumentError
      nil
    end

    # @api private: milliseconds since the epoch as ISO 8601 in UTC, like JavaScript's toISOString().
    def iso_of(ms)
      Time.at(ms / 1000, ms % 1000, :millisecond).utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ")
    end

    # "Why?": the case code and plain reasons of a login request's answer, for its step.
    def why(res)
      out = {}
      out["caseCode"] = res["caseCode"] if res["caseCode"].is_a?(String) && !res["caseCode"].empty?
      reasons = (res["reasons"].is_a?(Array) ? res["reasons"] : []).filter_map do |r|
        { "code" => r["code"], "text" => r["text"].is_a?(String) ? r["text"] : "" } if r.is_a?(Hash) && r["code"].is_a?(String)
      end
      out["reasons"] = reasons unless reasons.empty?
      out
    end

    # Where a started approval is now. While it waits (waiting, passkey_required) the step has
    # the request's live "expiresAt" when Touchque sends it: a switch to a passkey during a call
    # extends it.
    def check(client, request_id)
      s = client.login.status(request_id)
      state = s["status"] == "PENDING" && s["requiresPasskey"] ? "passkey_required" : STATE_MAP.fetch(s["status"], "waiting")
      step = { "state" => state, "requestId" => request_id }
      step["assurance"] = s["assurance"] if state == "approved" && s["assurance"]
      step["expiresAt"] = s["expiresAt"] if %w[waiting passkey_required].include?(state) && iso_ms(s["expiresAt"])
      step
    end

    # Uses an approved request exactly once and checks it is for THIS user, action and
    # transaction. ApprovalMismatchError when it is for something else.
    def complete(client, request_id, user, action, details: nil, reference_id: nil)
      res = client.login.consume(request_id)
      same_user = res["externalUsername"].to_s.downcase == user.to_s.downcase
      same_details = Details.digest(details) == Details.digest(res["details"])
      # No reference and an empty one are the same: the API answers null for both.
      same_ref = (res["referenceId"].to_s.empty? ? nil : res["referenceId"]) == (reference_id.to_s.empty? ? nil : reference_id)
      if !same_user || res["type"] != action || !same_details || !same_ref
        raise ApprovalMismatchError, "this approval is for a different user, action or transaction."
      end

      approval = {
        "requestId" => request_id, "user" => res["externalUsername"], "action" => res["type"],
        "assurance" => res["assurance"], "confirmedVia" => res["confirmedVia"], "approvalProof" => res["approvalProof"]
      }
      if res.key?("provisional")
        # Vishing Shield: approved during a call. Treat the session as limited: critical actions are
        # refused until APPROVAL_RECONFIRMED, and APPROVAL_REVOKED means end it.
        approval.merge!("provisional" => res["provisional"] ? true : false, "revoked" => res["revoked"] ? true : false,
                        "revokeReason" => res["revokeReason"], "reconfirmedAt" => res["reconfirmedAt"])
      end
      approval
    end

    # The browser echoes this token back while it waits. Signed with a key derived from
    # the API secret, it binds the approval to one user, action and transaction.
    def sign_guard_token(api_secret, claims)
      body = Util.b64url(Util.json(claims))
      "v1.#{body}.#{Util.b64url(Util.hmac(token_key(api_secret), body))}"
    end

    def verify_guard_token(api_secret, token)
      return nil if token.nil? || token.empty? || token.length > 4096

      parts = token.split(".", -1)
      return nil unless parts.length == 3 && parts[0] == "v1"
      return nil unless Util.secure_compare(Util.b64url(Util.hmac(token_key(api_secret), parts[1])), parts[2])

      claims = Util.parse_json(Util.b64url_decode(parts[1]).force_encoding("UTF-8"))
      return nil unless claims.is_a?(Hash) && claims["exp"].is_a?(Numeric) && claims["exp"] >= Util.now_ms

      claims
    rescue ArgumentError
      nil
    end

    def token_key(api_secret)
      Util.hmac(api_secret, "touchque-guard-token-v1")
    end
  end

  # Framework-agnostic step-up guard (the Rails concern is a thin wrapper over it).
  # Contract, the same in every Touchque server SDK:
  #   1st request            -> 202 {"touchque" => step, "token" => ...}  show the step in your UI
  #   repeat with the token   -> 202 while waiting (each answer carries the request's live "expiresAt"),
  #                              then the protected action runs once
  #   refused                 -> 403 / 408 / 423 / 429 {"touchque" => {"state" => ...}}
  #   first-time QR up        -> 202 {"touchque" => {"state" => "enroll", "expiresAt" => ...}} with no
  #                              "enroll": keep showing the QR; about 15 s before it expires a new one
  #                              comes with "enroll" => {"qrCodeDataUrl"} and new recovery codes
  #   no phone, enroll: false -> 202 {"touchque" => {"state" => "enroll", "reason" => "enrollment_off"}}: final
  # run(nil, ...) uses default_client (Touchque.client; set with default_client=); response(result)
  # gives the Rack-style answer to send.
  # Request headers the browser sends back: X-Touchque-Token, X-Touchque-Offline: 1,
  # X-Touchque-Code (+ X-Touchque-Code-Type: totp), X-Touchque-Browser (silent sign-ins).
  module Guard
    TOKEN_HEADER = "X-Touchque-Token"
    OFFLINE_HEADER = "X-Touchque-Offline"
    CODE_HEADER = "X-Touchque-Code"
    CODE_TYPE_HEADER = "X-Touchque-Code-Type"
    BROWSER_HEADER = "X-Touchque-Browser"

    TOKEN_TTL_MS = 10 * 60 * 1000
    MAX_BROWSER_PROOF = 4096
    STATUS = { "waiting" => 202, "enroll" => 202, "passkey_required" => 202, "offline" => 202, "approved" => 200,
               "rejected" => 403, "blocked" => 403, "expired" => 408, "frozen" => 423, "rate_limited" => 429 }.freeze
    WAITING = %w[waiting passkey_required offline].freeze
    # Steps whose token carries the request's expiry (claim "rx"): every poll answers an expiresAt.
    EXPIRING = %w[waiting passkey_required].freeze
    # A first-time QR this close to its expiry is replaced instead of kept on screen.
    ENROLL_MARGIN_MS = 15_000
    # The refusal message for a state when the guard set none (anything else: "The approval was refused.").
    REFUSAL_MESSAGES = {
      "rejected" => "The approval was rejected.",
      "expired" => "The approval expired. Try again.",
      "frozen" => "Too many rejected approvals. Try again later.",
      "rate_limited" => "Too many attempts. Try again later."
    }.freeze

    @unconfigured_logged = false

    class << self
      # @api private: the adapters logged once that the client cannot be built.
      attr_accessor :unconfigured_logged
    end

    module_function

    # The guard headers from a header getter (name => value or nil).
    def input_from_headers(get)
      {
        token: presence(get.call(TOKEN_HEADER)),
        offline: %w[1 true].include?(get.call(OFFLINE_HEADER)),
        code: presence(get.call(CODE_HEADER)),
        code_type: presence(get.call(CODE_TYPE_HEADER))
      }
    end

    # +silent_sign_in+: false/nil (default), true, or { max_age_seconds: Integer >= 0 }.
    def assert_silent_sign_in!(option, who)
      return if option.nil? || option == true || option == false

      if option.is_a?(Hash) && (option.keys.map(&:to_s) - ["max_age_seconds"]).empty?
        max = option[:max_age_seconds] || option["max_age_seconds"]
        return if max.nil? || (max.is_a?(Integer) && max >= 0)
      end
      raise ArgumentError, "#{who}: silent_sign_in must be true, false or { max_age_seconds: Integer >= 0 }."
    end

    def silent_on?(option)
      option == true || option.is_a?(Hash)
    end

    # True when this request only polls an approval already on its way: a valid token
    # bound to this user/action/details, still waiting, or showing the first-time QR while
    # it is up (more than 15 s before it expires), and no offline switch or code. Relays do
    # not count it against the per-user push limit. Such an enroll poll can still start
    # (the user linked, or the QR is gone): relays charge that through run's before_start.
    # Renewing an expiring QR counts. +client+: as run's; nil is default_client, and false
    # while it cannot be built.
    def status_poll?(client, user, action, details: nil, reference_id: nil, token: nil, offline: false, code: nil)
      return false if user.to_s.empty? || token.to_s.empty? || offline || !code.to_s.empty?

      client ||= default_client
      return false unless client

      claims = Steps.verify_guard_token(client.api_secret, token)
      return false unless claims && bound?(claims, user, action, details, reference_id)
      return claims["ee"].is_a?(Integer) && Util.now_ms < claims["ee"] - ENROLL_MARGIN_MS if claims["st"] == "enroll"

      claims["rid"] ? WAITING.include?(claims["st"]) : false
    end

    # The headers for a result that is not an approval: Cache-Control: no-store,
    # Retry-After when the step has one (423, 429) and, for status >= 400,
    # X-Touchque-State plus X-Touchque-Reason when the step has a reason. @touchque/web
    # rebuilds the step from them when a body has no "touchque" key; cross-origin pages
    # need them in Access-Control-Expose-Headers.
    def headers(result)
      step = result[:body].is_a?(Hash) && result[:body]["touchque"].is_a?(Hash) ? result[:body]["touchque"] : {}
      out = { "Cache-Control" => "no-store" }
      out["Retry-After"] = step["retryAfter"].to_s if step["retryAfter"]
      if result[:status] >= 400 && header_code?(step["state"])
        out["X-Touchque-State"] = step["state"]
        out["X-Touchque-Reason"] = step["reason"] if header_code?(step["reason"])
      end
      out
    end

    # A state or reason code that is safe as a header value.
    def header_code?(value)
      value.is_a?(String) && value.match?(/\A[A-Za-z0-9_.:-]{1,100}\z/)
    end

    def bound?(claims, user, action, details, reference_id)
      claims["u"] == user && claims["a"] == action && claims["d"] == Details.digest(details) && claims["r"] == reference_id
    end

    # Touchque.client for run(nil, ...) and the per-route adapters: built on the request,
    # kept once built. nil when it cannot be built (TQ_API_KEY / TQ_API_SECRET missing, a bad
    # key or URL), logged once per process through Touchque.logger; the guard then answers
    # 500 misconfigured, and a later request tries again. To fail fast at boot instead, call
    # Touchque.client there: it raises Touchque::ConfigError, naming what is missing.
    def default_client
      Touchque.client
    rescue ConfigError => e
      unless Guard.unconfigured_logged
        Guard.unconfigured_logged = true
        line = if e.message.end_with?(Client::MISSING_KEYS)
                 "[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured."
               else
                 "[Touchque] #{e.message}"
               end
        Touchque.log :error, line
      end
      nil
    end

    # Makes +client+ the default client (Touchque.client) of run(nil, ...), status_poll?(nil,
    # ...) and require_touchque: the way to give them your own client (built with your
    # base_url, say; Touchque.logger is the SDK's logger). nil forgets it, so the next call
    # builds from Touchque.configure / the environment again.
    def default_client=(client)
      Touchque.client = client
    end

    # The 401 for a request without a signed-in user.
    def unauthenticated
      error(401, { "state" => "blocked", "reason" => "unauthenticated" }, "unauthenticated", "Sign in first.")
    end

    # The 500 for a setup error: missing keys, an undefined action type.
    def misconfigured
      error(500, { "state" => "blocked", "reason" => "misconfigured" }, "misconfigured", "Two-factor approval is not configured correctly.")
    end

    # What an error_body callable gets for a result with status >= 400:
    # { status:, code:, message:, touchque: }. code: the error's code, else the step's
    # reason, else its state; message: the error's message, else one for the state ("The
    # approval was rejected." ...); touchque: a copy of the step as it would be sent.
    def refusal(result)
      body = Util.deep_copy(result[:body]) # the callable may change what it gets, never the answer
      step = body["touchque"] || {}
      error = body["error"] || {}
      { status: result[:status], code: error["code"] || step["reason"] || step["state"],
        message: error["message"] || REFUSAL_MESSAGES.fetch(step["state"], "The approval was refused."), touchque: step }
    end

    # Your own error shape for a result with status >= 400, as the JSON text to send: what
    # +callable+ returns for refusal(result). What it encodes to decides (a Struct or Data as
    # its Hash, to_hash, an as_json Hash, else to_json): a JSON object gets "touchque" set
    # to the step, replacing yours, so @touchque/web still sees the state (no token is
    # added); anything else is sent as it is. When the callable raises, or its result cannot
    # be encoded, this logs "[Touchque] errorBody failed: ..." and returns the default body.
    def error_body(result, callable)
      json = jsonable(callable.call(refusal(result))).to_json
      return json unless json.start_with?("{")

      JSON.parse(json).merge("touchque" => result[:body]["touchque"]).to_json
    rescue StandardError => e
      Touchque.log :error, "[Touchque] errorBody failed: #{e.message}"
      result[:body].to_json
    end

    JSON_TYPE = "application/json; charset=utf-8"

    # The HTTP answer for a result of run that is not an approval, Rack style:
    # [status, headers, body], the body as JSON text: what require_touchque and the relay
    # send for it. headers: content-type, cache-control: no-store, retry-after on 423 / 429
    # and, on 400 and above, x-touchque-state / x-touchque-reason (lower-case names, as Rack 3
    # wants). +error_body+: a callable for your own error shape on 400 and above, as
    # error_body(result, callable): one that raises, or a result that cannot be encoded, is
    # logged and the default body sent. An approval raises ArgumentError: run your action.
    #
    #   status, headers, body = Touchque::Guard.response(result)
    #   [status, headers, [body]] # a Rack response
    def response(result, error_body: nil)
      raise ArgumentError, "Guard.response: the result is an approval: run your action instead" if result[:approved]
      unless error_body.nil? || error_body.respond_to?(:call)
        raise ArgumentError, "Guard.response: error_body must respond to call"
      end

      body = error_body && result[:status] >= 400 ? Guard.error_body(result, error_body) : result[:body].to_json
      out = { "content-type" => JSON_TYPE }
      Guard.headers(result).each { |name, value| out[name.downcase] = value }
      [result[:status], out, body]
    end

    # An error_body result in the form it is encoded in: a Struct or Data as its Hash, an
    # object with to_hash as that, one whose as_json is a Hash as that; anything else as it is.
    def jsonable(value)
      case value
      when Hash, Array, String, Numeric, Symbol, true, false, nil then value
      when Struct then value.to_h
      else
        return value.to_h if defined?(::Data) && value.is_a?(::Data)
        return value.to_hash if value.respond_to?(:to_hash)

        json = value.respond_to?(:as_json) ? value.as_json : nil
        json.is_a?(Hash) ? json : value
      end
    end

    # Runs one step of the guard: {status: 200, approved: approval} (run your protected
    # action once) or {status:, body: {"touchque" => step, "token" => ...}} to send back as
    # response(result) gives it.
    # +client+: your Touchque::Client, or nil for default_client (Touchque.client, built on
    # the first request that needs it; while it cannot be built the answer is 500
    # misconfigured, 401 unauthenticated without a user, logged once).
    # +enroll+: false for a guard that may not show the linking QR: a user with no phone gets
    # 202 {"state" => "enroll", "reason" => "enrollment_off"}.
    # Silent sign-ins: with +silent_sign_in+ on, a new attempt that carries a browser
    # proof first asks Touchque (risk.check); only an answer of exactly prompt: false
    # approves at once with no push. Otherwise, and on any error, the usual push starts.
    # +before_start+ (for rate limiters): called at most once, only for a poll with a
    # first-time QR token, right before it would start instead of keeping the QR (the user
    # linked: the silent check or the push; the QR expired, is about to, or is gone: a new
    # QR). Return nil or false to go on, or a result ({status:, body:}) to answer instead;
    # anything else fails closed (503 unavailable), so nothing starts. A relay charges the
    # user's budget there, since status_poll? exempted that poll.
    def run(client, user, action, details: nil, reference_id: nil, ip: nil, user_agent: nil, token: nil, offline: false,
            code: nil, code_type: nil, enroll: true, browser_proof: nil, silent_sign_in: false, context: nil, before_start: nil)
      return unauthenticated if user.to_s.empty?

      client ||= default_client
      return misconfigured unless client

      norm = Details.normalize(details)
      norm = nil if norm.empty?
      base = { "u" => user, "a" => action, "d" => Details.digest(details), "r" => reference_id }
      secret = client.api_secret
      issue = lambda do |step, extra = {}|
        step = step.merge("details" => norm) if norm && step["details"].nil? && step["state"] != "blocked"
        claims = base.merge("st" => step["state"], "rid" => step["requestId"], "n" => step["number"],
                            "oc" => step.dig("offline", "challengeId"), "exp" => Util.now_ms + TOKEN_TTL_MS)
        claims["cc"] = step["caseCode"] if step["caseCode"]
        # A push or passkey: its token carries when the request expires (rx), for polls without a live expiry.
        if EXPIRING.include?(step["state"])
          expiry = Steps.iso_ms(step["expiresAt"])
          claims["rx"] = expiry if expiry
        end
        # A first-time QR: its token carries when the QR expires (ee), so polls keep it on screen.
        if step["state"] == "enroll" && step["enroll"].is_a?(Hash) && !step["enroll"]["qrCodeDataUrl"].to_s.empty?
          ee = Steps.iso_ms(step["enroll"]["expiresAt"])
          claims["ee"] = ee if ee
        end
        claims.merge!(extra)
        { status: STATUS.fetch(step["state"]), body: { "touchque" => step.compact, "token" => Steps.sign_guard_token(secret, claims) } }
      end

      begin
        claims = Steps.verify_guard_token(secret, token)
        bound = claims && bound?(claims, user, action, details, reference_id) ? claims : nil
        rid = bound && bound["rid"]
        n = bound && bound["n"]
        oc = bound && bound["oc"]
        st = bound && bound["st"]
        # The request's expiry (rx) stays with it: waiting / passkey answers carry it as expiresAt (the
        # live one from Touchque's status answer when there is one), and the offline steps carry it on.
        rx = bound && bound["rx"].is_a?(Integer) ? bound["rx"] : nil
        keep_rx = rx ? { "rx" => rx } : {}
        expiring = lambda do |step, live = nil|
          at = live || rx
          at ? step.merge("expiresAt" => Steps.iso_of(at)) : step
        end
        keep = { "oc" => oc, "rid" => rid, "n" => n }.merge(keep_rx)

        # Offline: the user typed the code from the phone.
        if bound && !code.to_s.empty? && (st == "offline" || code_type == "totp")
          totp = code_type == "totp"
          res = totp ? client.offline.verify_totp(user, code, type: action, client_ip: ip, request_id: rid) : client.offline.verify(oc.to_s, code)
          for_this = (res["externalUsername"].to_s.empty? || res["externalUsername"].downcase == user.downcase) &&
                     (res["type"].to_s.empty? || res["type"] == action)
          if res["approved"] && for_this
            return { status: 200, approved: {
              "requestId" => oc || "offline-totp", "user" => user, "action" => action,
              "assurance" => { "phishingResistant" => false, "method" => totp ? "offline_totp" : "offline_code" },
              "confirmedVia" => totp ? "OFFLINE_TOTP" : "OFFLINE_CODE", "approvalProof" => nil
            } }
          end
          if res["reason"] == "invalid_code" && !totp
            return issue.call({ "state" => "offline", "offline" => { "challengeId" => oc.to_s, "attemptsLeft" => res["attemptsLeft"] } }, keep)
          end
          return issue.call({ "state" => "offline", "reason" => "invalid_code" }, keep) if res["reason"] == "invalid_code"
          # The phone rejected the push this QR belongs to: the whole sign-in is over.
          return issue.call({ "state" => "rejected", "requestId" => rid, "reason" => "request_rejected" }) if res["reason"] == "request_rejected"
          # The push now waits for a passkey (Vishing Shield): no code may finish it.
          if res["reason"] == "passkey_required" && rid
            return issue.call(expiring.call({ "state" => "passkey_required", "requestId" => rid, "number" => n }), { "n" => n })
          end

          return issue.call({ "state" => res["reason"] == "expired" ? "expired" : "blocked", "reason" => res["reason"] || "offline_failed" })
        end

        if offline
          begin
            # Tie the QR to the push it follows: a phone-side rejection kills it; number matching carries over.
            ch = client.offline.challenge(user, type: action, details: norm, client_ip: ip, user_agent: user_agent, request_id: rid)
            offline_step = ch.slice("challengeId", "qrDataUrl", "expiresAt", "totpAvailable")
            offline_step["challengeCode"] = ch["challengeCode"] if ch["challengeCode"] && !ch["challengeCode"].empty?
            return issue.call({ "state" => "offline", "offline" => offline_step }, { "rid" => rid, "n" => ch["challengeCode"] || n }.merge(keep_rx))
          rescue APIError => e
            err = e.code || e.error
            return issue.call({ "state" => "rejected", "requestId" => rid, "reason" => "request_rejected" }) if e.status == 409 && err == "request_rejected"
            if rid && err == "passkey_required"
              return issue.call(expiring.call({ "state" => "passkey_required", "requestId" => rid, "number" => n }), { "n" => n })
            end
            return issue.call({ "state" => "blocked", "reason" => e.code || e.error || "offline_unavailable" }) if e.status < 500

            raise
          end
        end

        # Waiting on a push / passkey, or the offline QR next to a push still open: poll, run once approved.
        if bound && rid && WAITING.include?(st)
          now = Steps.check(client, rid)
          # The live expiry: a switch to a passkey during a call extends it. The new token keeps it (rx).
          live = Steps.iso_ms(now["expiresAt"])
          if now["state"] == "approved"
            begin
              return { status: 200, approved: Steps.complete(client, rid, user, action, details: details, reference_id: reference_id) }
            rescue APIError => e
              raise unless e.status == 409

              return issue.call({ "state" => "expired", "reason" => e.code || "already_used" })
            end
          end
          # The push behind the QR moved to a passkey after a tap during a call.
          if st == "offline" && now["state"] == "passkey_required"
            return issue.call(expiring.call({ "state" => "passkey_required", "requestId" => rid, "number" => n }, live), { "n" => n })
          end
          # Nothing changed for the user: keep showing the QR they have.
          if st == "offline" && %w[waiting expired].include?(now["state"])
            return issue.call({ "state" => "offline", "offline" => { "challengeId" => oc.to_s } }, live ? keep.merge("rx" => live) : keep)
          end
          if %w[waiting passkey_required].include?(now["state"])
            waiting = expiring.call({ "state" => now["state"], "requestId" => rid, "number" => n }, live)
            # "Why?": the case code stays on screen while it waits, and so does when the request expires.
            waiting["caseCode"] = bound["cc"] if bound["cc"]
            return issue.call(waiting, { "n" => n })
          end
          return issue.call({ "state" => now["state"], "requestId" => rid })
        end

        # The first-time QR is up: while the phone is not linked and the QR lives, keep it on screen
        # (no new secret, no push); the page keeps the QR and recovery codes it shows. Linked,
        # expiring or gone: start.
        if bound && st == "enroll" && (ee = bound["ee"]).is_a?(Integer)
          if link_state(client, user) == false && Util.now_ms < ee - ENROLL_MARGIN_MS
            return issue.call({ "state" => "enroll", "expiresAt" => Steps.iso_of(ee) }, { "ee" => ee })
          end

          # This poll starts after all (a push, or a new QR): the caller may charge or refuse it first.
          # Anything truthy it returns is the answer; what is not a result fails closed (503).
          instead = before_start&.call
          if instead
            unless instead.is_a?(Hash) && instead[:status].is_a?(Integer) && instead[:body].is_a?(Hash)
              raise ArgumentError, "before_start must return nil or false to go on, or a result { status:, body: } to answer"
            end

            return instead
          end
        end

        # Anything else (no or foreign token, enrollment finished, new attempt): start.
        proof = browser_proof.is_a?(String) && !browser_proof.empty? && browser_proof.length <= MAX_BROWSER_PROOF ? browser_proof : nil
        if proof && silent_on?(silent_sign_in)
          silent = silent_approval(client, user, action, proof, ip, user_agent, silent_sign_in, context)
          return { status: 200, approved: silent } if silent
        end
        issue.call(Steps.start(client, action, user, details: norm, reference_id: reference_id, ip: ip, user_agent: user_agent,
                                                     enroll: enroll, browser_proof: proof, context: context))
      rescue ConfigError => e
        Touchque.log :error, "[Touchque] #{e.message}"
        misconfigured
      rescue StandardError => e
        # Anything else (Touchque unreachable, an approval for another transaction, a bug)
        # fails closed with the contract's 503, never a bare 500.
        Touchque.log :error, "[Touchque] approval failed: #{e.class}: #{e.message}"
        error(503, { "state" => "blocked", "reason" => "unavailable" }, "unavailable", "Two-factor approval is temporarily unavailable.")
      end
    end

    def error(status, step, code, message)
      { status: status, body: { "touchque" => step, "error" => { "code" => code, "message" => message } } }
    end

    # Whether a phone is linked to the user (used, or a deviceId); nil when Touchque does
    # not know the user (404: the QR is gone). Other errors raise.
    def link_state(client, user)
      current = client.auth.get_user(user)
      current["used"] || current["deviceId"] ? true : false
    rescue APIError => e
      raise unless e.status == 404

      nil
    end

    # Fails closed: only an answer of exactly prompt: false approves.
    def silent_approval(client, user, action, proof, ip, user_agent, option, context)
      max_age = option.is_a?(Hash) ? (option[:max_age_seconds] || option["max_age_seconds"]) : nil
      res = client.risk.check(user, type: action, client_ip: ip, user_agent: user_agent, browser_proof: proof,
                                    max_age_seconds: max_age, context: context)
      return nil unless res["prompt"] == false

      {
        "requestId" => "silent", "user" => user, "action" => action,
        "assurance" => { "phishingResistant" => false, "method" => "silent" },
        "confirmedVia" => "SILENT", "approvalProof" => nil,
        # Nothing was sent to the phone; why Touchque let this known browser in.
        "reasons" => res["reasons"]
      }
    rescue StandardError => e
      Touchque.log :warn, "[Touchque] silent sign-in check failed, asking the phone: #{e.class}: #{e.message}"
      nil
    end

    def presence(value)
      value.nil? || value.to_s.empty? ? nil : value.to_s
    end
  end
end
