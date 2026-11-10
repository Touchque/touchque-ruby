# frozen_string_literal: true

module TouchQue
  module Resources
    # Silent sign-ins: ask TouchQue's risk engine whether a sign-in needs the phone at
    # all, and manage the browsers it knows for a user. A browser becomes known when the
    # user approves a request that carried its device-bound key proof; later +check+ with
    # a fresh proof from the same browser answers "prompt" => false when nothing about
    # the sign-in is new. Nothing goes to the phone.
    class Risk
      ASSURANCE = %w[high normal low].freeze

      def initialize(http)
        @http = http
      end

      # Reads a POST /risk/check answer, failing closed: "prompt" is false ONLY when the
      # answer says exactly prompt: false. Malformed reasons become [], an unknown or
      # missing assurance is "normal".
      def self.parse_check(raw)
        body = raw.is_a?(Hash) ? raw : {}
        reasons = (body["reasons"].is_a?(Array) ? body["reasons"] : []).filter_map do |r|
          next unless r.is_a?(Hash) && r["code"].is_a?(String)

          { "code" => r["code"], "text" => r["text"].is_a?(String) ? r["text"] : "" }
        end
        out = {
          "prompt" => !(body.key?("prompt") && body["prompt"] == false),
          "reasons" => reasons,
          "assurance" => ASSURANCE.include?(body["assurance"]) ? body["assurance"] : "normal",
          "silentMode" => body["silentMode"] == "shadow" ? "shadow" : "enforce"
        }
        # "Why?": the check's case code, to show the user.
        out["caseCode"] = body["caseCode"] if body["caseCode"].is_a?(String)
        out
      end

      # Should this sign-in ask the phone? Skip the push only when "prompt" is false;
      # on any error, ask as usual. A critical action always asks.
      # max_age_seconds: your own limit on how long ago the last phone approval in this
      # browser may be (0 = always ask). context: for your TouchQue Actions only.
      # device_risk_request_id: the page's identification (deviceRisk.identify), or device_risk:
      # the page's report (deviceRisk.collect); a device signal is never silent.
      def check(external_username, type: nil, client_ip: nil, user_agent: nil, browser_proof: nil,
                client_signals: nil, max_age_seconds: nil, context: nil, device_risk: nil, device_risk_request_id: nil)
        raise ConfigError, "risk.check() needs the user (external_username)" if external_username.to_s.empty?
        if !max_age_seconds.nil? && (!max_age_seconds.is_a?(Integer) || max_age_seconds.negative?)
          raise ConfigError, "risk.check(): max_age_seconds must be an integer >= 0 (0 = always ask)"
        end

        body = { "externalUsername" => external_username }
        { "type" => type, "clientIp" => client_ip, "userAgent" => user_agent, "browserProof" => browser_proof,
          "clientSignals" => client_signals, "deviceRisk" => device_risk,
          "deviceRiskRequestId" => device_risk_request_id }.each { |k, v| body[k] = v if v.is_a?(String) && !v.empty? }
        body["maxAgeSeconds"] = max_age_seconds unless max_age_seconds.nil?
        body["context"] = Util.stringify(context) if context.is_a?(Hash) && !context.empty?
        self.class.parse_check(@http.post("/risk/check", body))
      end

      # The browsers TouchQue knows for a user: {"browsers" => [...]}.
      def browsers(external_username)
        raise ConfigError, "risk.browsers() needs the user (external_username)" if external_username.to_s.empty?

        res = @http.get("/risk/browsers", { "externalUsername" => external_username })
        { "browsers" => res["browsers"].is_a?(Array) ? res["browsers"] : [] }
      end

      # Forgets one browser (+thumbprint+) or all of a user's browsers: {"forgotten" => n}.
      def forget_browsers(external_username, thumbprint: nil)
        raise ConfigError, "risk.forget_browsers() needs the user (external_username)" if external_username.to_s.empty?

        @http.post("/risk/browsers/forget", Util.compact({ "externalUsername" => external_username, "thumbprint" => thumbprint }))
      end
    end

    # Never Locked Out: move a user whose phone is lost, dead or replaced to a new phone
    # without a help desk. Users name colleagues who vouch for them (set_vouchers, behind
    # an approval on their phone); when the phone is gone, after the password: start (show
    # "bindUri" as a QR for the TouchQue app on the new phone), poll status and show each
    # voucher's "code"; after a cooling-off nobody vetoed the account is on the new phone.
    class Recovery
      OPEN_STATUSES = %w[AWAITING_DEVICE VOUCHING COOLING].freeze

      def initialize(http)
        @http = http
      end

      # Still waiting for the new phone, the vouchers or the cooling-off.
      def self.open?(recovery)
        OPEN_STATUSES.include?(recovery.is_a?(Hash) ? recovery["status"] : nil)
      end

      def vouchers(external_username)
        require!("vouchers", "external_username", external_username)
        @http.get("/recovery/vouchers", { "externalUsername" => external_username })
      end

      # Replaces the user's vouchers (at most 5 are kept). Ask for the user's phone first.
      def set_vouchers(external_username, vouchers)
        require!("set_vouchers", "external_username", external_username)
        raise ConfigError, "recovery.set_vouchers(): every voucher must be a string" unless vouchers.all?(String)

        @http.post("/recovery/vouchers", { "externalUsername" => external_username, "vouchers" => vouchers.to_a })
      end

      # Starts moving the user to a new phone. Call it only after the first factor. APIError
      # with code not_enough_vouchers, recovery_in_progress, blocked, frozen or rate_limited.
      def start(external_username, client_ip: nil, user_agent: nil, display_name: nil, fallback_vouchers: nil,
                required: nil, cool_off_minutes: nil, details: nil, notice_details: nil)
        require!("start", "the user (external_username)", external_username)
        { "required" => required, "cool_off_minutes" => cool_off_minutes }.each do |name, v|
          next if v.nil?
          raise ConfigError, "recovery.start(): #{name} must be a positive integer" unless v.is_a?(Integer) && v.positive?
        end
        body = { "externalUsername" => external_username }
        body.merge!(Util.compact({ "clientIp" => client_ip, "userAgent" => user_agent, "displayName" => display_name }))
        body["fallbackVouchers"] = fallback_vouchers.to_a if fallback_vouchers && !fallback_vouchers.empty?
        body["required"] = required unless required.nil?
        body["coolOffMinutes"] = cool_off_minutes unless cool_off_minutes.nil?
        body["details"] = Util.stringify(details) if details && !details.empty?
        body["noticeDetails"] = Util.stringify(notice_details) if notice_details && !notice_details.empty?
        @http.post("/recovery/start", body)
      end

      # The recovery now, with its receipt chain. Poll it while the user waits.
      def status(recovery_id)
        require!("status", "recovery_id", recovery_id)
        @http.get("/recovery/#{Util.seg(recovery_id)}")
      end

      # A user's recoveries, or (open: true) every running one of your workspace.
      def list(external_username: nil, open: false)
        if external_username.to_s.empty? && !open
          raise ConfigError, "recovery.list() needs external_username or open: true"
        end

        res = @http.get("/recovery", { "externalUsername" => external_username.to_s.empty? ? nil : external_username, "open" => open ? "true" : nil })
        res["recoveries"].is_a?(Array) ? res["recoveries"] : []
      end

      # Stops a running recovery (e.g. an admin who does not believe it). Does not freeze the user.
      def veto(recovery_id, by: nil, reason: nil)
        require!("veto", "recovery_id", recovery_id)
        @http.post("/recovery/#{Util.seg(recovery_id)}/veto", Util.compact({ "by" => by, "reason" => reason }))
      end

      private

      def require!(method, what, value)
        raise ConfigError, "recovery.#{method}() needs #{what}" if value.to_s.empty?
      end
    end

    # Help desk: IT working on a person's account in the open. open before your help desk
    # acts on someone's account (their phone gets a calm notice); verify before a sensitive
    # action (a 2-digit "challengeCode" the agent reads to the person, who types it and
    # approves on their phone); spend right before the action. No phone (code no_phone,
    # route never_locked_out): the person moves to a new phone with Never Locked Out.
    class Assist
      def initialize(http)
        @http = http
      end

      # The check of +request_id+ passed on the person's phone and was not used yet.
      def self.check_passed?(session, request_id)
        check = (session["checks"] || []).find { |c| c["requestId"] == request_id }
        !check.nil? && check["outcome"] == "verified" && check["spentAt"].nil?
      end

      # Starts helping a person: agent is {name:, title:, ref: your id for the agent}.
      # A session of the same agent for the same person is replaced.
      def open(external_username, agent:, reason: nil, ttl_minutes: nil, notify: true)
        agent = Util.stringify(agent || {})
        if external_username.to_s.empty? || agent["name"].to_s.empty?
          raise ConfigError, "assist.open() needs external_username and agent name"
        end

        body = { "externalUsername" => external_username, "agent" => Util.compact(agent) }
        body["reason"] = reason unless reason.nil?
        body["ttlMinutes"] = ttl_minutes unless ttl_minutes.nil?
        body["notify"] = false unless notify
        @http.post("/assist", body)
      end

      # The session and its checks. Poll it while a check is pending.
      def get(id)
        require!("get", "the session id", id)
        @http.get(path(id))
      end

      # A person's sessions, or every open one, newest first.
      def list(external_username: nil, open: false)
        raise ConfigError, "assist.list() needs external_username or open: true" if external_username.to_s.empty? && !open

        @http.get("/assist", { "externalUsername" => external_username.to_s.empty? ? nil : external_username, "open" => open ? "true" : nil })["sessions"] || []
      end

      # Asks the person's phone to confirm +action+ (reset_2fa, reset_password,
      # activation_link, recovery_link, unlock, new_phone, remove_passkey or your own).
      def verify(id, action, action_text: nil, details: nil)
        require!("verify", "the session id and an action", id, action)
        body = { "action" => action }
        body["actionText"] = action_text if action_text && !action_text.empty?
        body["details"] = Util.stringify(details) if details && !details.empty?
        @http.post(path(id, "/verify"), body)
      end

      # Uses a passed check for its action, right before you take it; check_required (428) otherwise.
      def spend(id, request_id, action)
        require!("spend", "the session id, request_id and action", id, request_id, action)
        @http.post(path(id, "/spend"), { "requestId" => request_id, "action" => action })
      end

      # Lifts the person's approval freeze with a passed check for "unlock".
      def unfreeze(id, request_id)
        require!("unfreeze", "the session id and request_id", id, request_id)
        @http.post(path(id, "/unfreeze"), { "requestId" => request_id })
      end

      # Stops helping; checks still waiting on the phone expire.
      def end(id, by: nil, reason: nil)
        require!("end", "the session id", id)
        @http.post(path(id, "/end"), Util.compact({ "by" => by, "reason" => reason }))
      end

      private

      def path(id, rest = "")
        "/assist/#{Util.seg(id)}#{rest}"
      end

      def require!(method, what, *values)
        raise ConfigError, "assist.#{method}() needs #{what}" if values.any? { |v| v.to_s.empty? }
      end
    end
  end
end
