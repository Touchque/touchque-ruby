# frozen_string_literal: true

module TouchQue
  module Resources
    # Safe Guard: a Safe transaction approved on the approver's phone for TouchQueSafeGuard (the
    # guard on your Safe). You send the raw transaction; the phone gets the raw fields only,
    # decodes them itself, shows its own rows and signs, with a key only its biometrics unlock, a
    # 105-byte approval of the hash it computed. TouchQue never holds a key that can approve.
    #
    # 1. request(user, type, safe_tx) asks the phone (same pipeline as login.request: risk
    #    engine, push limit, Vishing Shield, case code, always biometrics).
    # 2. wait_for_approval(request_id) (or poll status) until the phone answered.
    # 3. Check safeTx["approval"] yourself with TouchQue::SafeApproval.verify: it needs your own
    #    transaction and the approver's key from the guard, not this answer. Pass purpose:
    #    "schedule" for a governance change; without it only "approve" is accepted.
    # 4. "purpose" "approve": SafeApproval.with_approvals(owner_signatures, approvals) as the
    #    signatures of execTransaction. "schedule": send SafeApproval.schedule_call(safe,
    #    governance_hash, approvals) to the guard; the change runs once its waiting time is over.
    class SafeGuard
      NUMBERS = %w[value safeTxGas baseGas gasPrice nonce].freeze

      def initialize(http)
        @http = http
      end

      # Asks the approver's phone to approve a Safe transaction. +type+ is an action type from
      # your dashboard; +safe_tx+ is { "chainId", "safe", "guard", "tx", "config" => { "threshold",
      # "govThreshold", "govDelay", "exitDelay", "recipientLock" }, "batchTargets", "recipients",
      # "approverIndex", "locale" }; +expires_in+ is seconds, 30 to 300 (default 300).
      #
      #   tq.safe_guard.request("treasurer@acme.com", "safe_payment", {
      #     "chainId" => 1, "safe" => safe, "guard" => guard,
      #     "tx" => { "to" => to, "value" => 0, "data" => data, "operation" => 0, "nonce" => 42 },
      #     "config" => { "threshold" => 2, "govThreshold" => 3, "govDelay" => 172_800, "exitDelay" => 259_200 },
      #     "approverIndex" => 0
      #   })
      def request(external_username, type, safe_tx, reference_id: nil, expires_in: nil, client_ip: nil, user_agent: nil)
        raise ConfigError, "safe_guard.request needs an external_username" if external_username.to_s.empty?
        raise ConfigError, "safe_guard.request needs a type: an action type from your dashboard" if type.to_s.empty?

        body = { "externalUsername" => external_username, "type" => type, "safeTx" => wire(safe_tx) }
        body.merge!(Util.compact({ "referenceId" => reference_id, "expiresIn" => expires_in, "clientIp" => client_ip, "userAgent" => user_agent }))
        @http.post("/safe-guard/approvals", body)
      end

      # The request's status and, once approved, the approval (safeTx["approval"], 105 bytes hex).
      def status(request_id)
        raise ConfigError, "safe_guard.status needs a request id" if request_id.to_s.empty?

        @http.get("/safe-guard/approvals/#{Util.seg(request_id)}")
      end

      # Polls until the phone approved and returns the status with the approval. Raises
      # RejectedError when the person said no, TimeoutError when it expired or +timeout+ seconds
      # (default 5 minutes, the request's own life) ran out.
      def wait_for_approval(request_id, timeout: 300, poll_interval: 1.5)
        deadline = Time.now + timeout
        loop do
          s = status(request_id)
          case s["status"]
          when "CONFIRMED" then return s
          when "REJECTED" then raise RejectedError.new(request_id)
          when "EXPIRED" then raise TimeoutError.new("TouchQue: request '#{request_id}' expired before it was approved.", request_id)
          end
          raise TimeoutError.new("TouchQue: Safe Guard approval '#{request_id}' was not given within #{timeout}s.", request_id) if Time.now > deadline

          sleep poll_interval
        end
      end

      private

      # String keys, and large integers as decimal strings, as the API takes them.
      def wire(safe_tx)
        raise ConfigError, "safe_guard.request needs safe_tx: { \"chainId\", \"safe\", \"guard\", \"tx\", \"config\", \"approverIndex\" }" unless safe_tx.is_a?(Hash)

        out = safe_tx.transform_keys(&:to_s)
        tx = out["tx"]
        raise ConfigError, "safe_guard.request needs safe_tx[\"tx\"]" unless tx.is_a?(Hash)

        out["chainId"] = out["chainId"].to_s if out["chainId"].is_a?(Integer)
        out["tx"] = tx.transform_keys(&:to_s).to_h { |k, v| [k, NUMBERS.include?(k) && v.is_a?(Integer) ? v.to_s : v] }
        out
      end
    end
  end
end
