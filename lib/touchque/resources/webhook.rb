# frozen_string_literal: true

module TouchQue
  # Storage for webhook jtis already accepted. +check_and_set+ must atomically record
  # the jti for +ttl_seconds+ and return true when it was NOT seen before. Use
  # MemoryReplayCache in one process, or one over Redis (SET key 1 NX EX ttl) or your
  # database when you run several (Puma clusters, several hosts).
  class MemoryReplayCache
    def initialize(max_entries: 100_000)
      @max_entries = [max_entries, 2].max
      @seen = {}
      @lock = Mutex.new
    end

    def check_and_set(jti, ttl_seconds)
      @lock.synchronize do
        now = Time.now.to_f
        return false if @seen[jti] && @seen[jti] > now

        if @seen.size >= @max_entries
          @seen.delete_if { |_, exp| exp <= now }
          @seen.shift while @seen.size >= @max_entries
        end
        @seen[jti] = now + ttl_seconds
        true
      end
    end
  end

  module Resources
    # Webhook signature verification (signed with your API secret).
    class Webhook
      DEFAULT_TOLERANCE_SECONDS = 300

      # "reason" values of a REJECTED login webhook. Treat a value you do not know as a rejection.
      REASON_USER_REJECTED = "user_rejected"
      # The user said "this wasn't me": 2FA is frozen.
      REASON_USER_REPORTED_FRAUD = "user_reported_fraud"
      # The user said someone on the phone told them to approve: 2FA is frozen; treat it as a takeover in progress.
      REASON_USER_REPORTED_COACHED = "user_reported_coached"
      # An AI agent's request: the user said no and blocked the agent from asking them again (no 2FA freeze).
      REASON_USER_BLOCKED_AGENT = "user_blocked_agent"
      REASON_RISK_REVERSED = "risk_reversed"
      REASON_RISK_STEP_UP = "risk_step_up"
      REASON_APPROVAL_SIGNATURE_INVALID = "approval_signature_invalid"
      REASON_DEVICE_INTEGRITY_FAILED = "device_integrity_failed"
      # Vishing Shield: approved during a call (or with the screen shared / remote-controlled), critical, no passkey.
      REASON_VISHING_SUSPECTED = "vishing_suspected"
      # Mirror Alarm: the sign-in page was not on your site (a real-time phishing proxy).
      REASON_PHISHING_ORIGIN = "phishing_origin"

      # "event" values of event webhooks. Ignore types you do not know.
      EVENT_DEVICE_LINKED = "DEVICE_LINKED"
      EVENT_DEVICE_UNLINKED = "DEVICE_UNLINKED"
      EVENT_PASSKEY_REGISTERED = "PASSKEY_REGISTERED"
      EVENT_PASSKEY_DELETED = "PASSKEY_DELETED"
      # Device risk: an identification or a device_risk.check raised a signal that asks for more. Never a trait.
      EVENT_DEVICE_RISK_SIGNAL = "DEVICE_RISK_SIGNAL"
      # Device risk: an alert rule of the workspace went off.
      EVENT_DEVICE_RISK_ALERT = "DEVICE_RISK_ALERT"
      # After the call, the user confirmed a provisional approval was theirs: critical actions are allowed again.
      EVENT_APPROVAL_RECONFIRMED = "APPROVAL_RECONFIRMED"
      # The user took an approval back (reason COACHED or UNDO): end the session built on it.
      EVENT_APPROVAL_REVOKED = "APPROVAL_REVOKED"
      # Mobile SDK: send this push with your own keys (Mobile.push_from_webhook).
      EVENT_MOBILE_PUSH = "MOBILE_PUSH"
      EVENT_AGENT_CREATED = "AGENT_CREATED"
      EVENT_AGENT_SUSPENDED = "AGENT_SUSPENDED"
      EVENT_AGENT_RESUMED = "AGENT_RESUMED"
      EVENT_AGENT_REVOKED = "AGENT_REVOKED"
      EVENT_AGENT_KEY_ADDED = "AGENT_KEY_ADDED"
      EVENT_AGENT_KEY_REMOVED = "AGENT_KEY_REMOVED"
      # The kill switch stopped every AI agent of the workspace.
      EVENT_AGENTS_PAUSED = "AGENTS_PAUSED"
      EVENT_AGENTS_RESUMED = "AGENTS_RESUMED"
      EVENT_AGENT_POLICY_CHANGED = "AGENT_POLICY_CHANGED"
      EVENT_AGENT_WORKSPACE_POLICY_CHANGED = "AGENT_WORKSPACE_POLICY_CHANGED"
      EVENT_AGENT_APPROVAL_REDEEMED = "AGENT_APPROVAL_REDEEMED"
      # A person stopped an AI agent from asking them ("this wasn't me", coached, or three rejections).
      EVENT_AGENT_BLOCKED_BY_PERSON = "AGENT_BLOCKED_BY_PERSON"
      EVENT_AGENT_UNBLOCKED_FOR_PERSON = "AGENT_UNBLOCKED_FOR_PERSON"
      # An AI agent sent the same request to the same person three times in 10 minutes.
      EVENT_AGENT_LOOP_DETECTED = "AGENT_LOOP_DETECTED"
      EVENT_AGENT_MANDATE_REQUESTED = "AGENT_MANDATE_REQUESTED"
      EVENT_AGENT_MANDATE_REVOKED = "AGENT_MANDATE_REVOKED"
      # An AI agent's text carried an instruction to the model or a link that carries data; the request was refused.
      EVENT_AGENT_INJECTION_SUSPECTED = "AGENT_INJECTION_SUSPECTED"
      # An approval came back sooner than a person can answer; it is never usable.
      EVENT_AGENT_INHUMAN_APPROVAL = "AGENT_INHUMAN_APPROVAL"
      # A new or renamed AI agent's name read like another agent's; it was refused.
      EVENT_AGENT_LOOKALIKE_NAME = "AGENT_LOOKALIKE_NAME"
      # Never Locked Out (tq.recovery): every step of a recovery, with "recoveryId" and "status".
      # RECOVERY_COMPLETED is followed by DEVICE_LINKED ("via" => "recovery"); VETOED, EXPIRED
      # and FAILED end it without a move.
      EVENT_RECOVERY_STARTED = "RECOVERY_STARTED"
      EVENT_RECOVERY_DEVICE_BOUND = "RECOVERY_DEVICE_BOUND"
      # The vouchers' quorum was reached: the account moves at "coolOffUntil" unless vetoed.
      EVENT_RECOVERY_COOLING = "RECOVERY_COOLING"
      EVENT_RECOVERY_COMPLETED = "RECOVERY_COMPLETED"
      EVENT_RECOVERY_VETOED = "RECOVERY_VETOED"
      EVENT_RECOVERY_EXPIRED = "RECOVERY_EXPIRED"
      EVENT_RECOVERY_FAILED = "RECOVERY_FAILED"
      # Help desk (tq.assist): a session opened or ended, a check on the phone passed or failed
      # ("outcome": wrong_number, not_me, coached, declined), approvals unfrozen after a check.
      EVENT_ASSIST_OPENED = "ASSIST_OPENED"
      EVENT_ASSIST_ENDED = "ASSIST_ENDED"
      EVENT_ASSIST_CHECK_PASSED = "ASSIST_CHECK_PASSED"
      EVENT_ASSIST_CHECK_FAILED = "ASSIST_CHECK_FAILED"
      EVENT_ASSIST_UNFROZEN = "ASSIST_UNFROZEN"
      # The person checked that the agent from IT is really working on their account.
      EVENT_ASSIST_CLAIM_CONFIRMED = "ASSIST_CLAIM_CONFIRMED"
      # Nobody from IT was working on the account when the person asked: someone is pretending to be IT.
      EVENT_ASSIST_CLAIM_UNVERIFIED = "ASSIST_CLAIM_UNVERIFIED"

      def initialize(api_secret)
        @secret = api_secret
      end

      # Never shows the API secret (logs, consoles, error reporters).
      def inspect
        "#<#{self.class.name}>"
      end

      # Verifies an incoming webhook and returns its payload.
      #
      # raw_body: the request body exactly as received. signature: the x-signature header
      # (nil uses the "signature" field inside the body). tolerance_seconds: reject a
      # callback whose signed timestamp is missing, invalid or further than this from now
      # (0 disables it). replay_cache: a second delivery of the same jti raises
      # WebhookReplayError (answer 200, don't run your side effects again).
      def verify(raw_body, signature = nil, tolerance_seconds: DEFAULT_TOLERANCE_SECONDS, replay_cache: nil)
        payload = Util.parse_json(raw_body.to_s)
        raise WebhookSignatureError, "invalid JSON payload" unless payload.is_a?(Hash)

        provided = signature.to_s.empty? ? payload["signature"] : signature
        raise WebhookSignatureError, "no signature provided" unless provided.is_a?(String) && !provided.empty?

        begin
          canonical = self.class.canonicalize(raw_body.to_s)
        rescue JSON::ParserError
          raise WebhookSignatureError, "could not canonicalize the payload"
        end
        # Never put the expected signature in the error: it would be a signing oracle.
        raise WebhookSignatureError, "invalid signature" unless Util.secure_compare(Util.hmac_hex(@secret, canonical), provided)

        # TouchQue always signs a timestamp: a missing or unparseable one fails closed.
        if tolerance_seconds.positive?
          at = Util.parse_time(payload["timestamp"])
          raise WebhookSignatureError, "timestamp is missing or invalid" if at.nil?
          raise WebhookSignatureError, "timestamp is outside the allowed window" if (Time.now.to_f - at).abs > tolerance_seconds
        end

        if replay_cache
          jti = payload["jti"]
          raise WebhookSignatureError, "jti is missing" unless jti.is_a?(String) && !jti.empty?
          # Remember it for twice the window so it outlives any timestamp that could still pass.
          raise WebhookReplayError.new(jti) unless replay_cache.check_and_set(jti, [tolerance_seconds * 2, 600].max)
        end
        payload
      end

      # The server's stableStringify: drop "signature", sort the TOP-LEVEL keys only (by
      # UTF-16 code units, like JavaScript), keep each value's bytes (nested key order,
      # number spelling); insignificant whitespace is removed.
      def self.canonicalize(raw_body)
        raise JSON::ParserError, "not an object" unless JSON.parse(raw_body).is_a?(Hash)

        members = {}
        Util.top_level_members(raw_body).each { |key, value| members[key] = value unless key == "signature" }
        body = members.keys.sort_by { |k| k.encode("UTF-16BE").bytes }.map do |key|
          "#{Util.js_string(key)}:#{Util.compact_json(members[key])}"
        end
        "{#{body.join(",")}}"
      end
    end
  end
end
