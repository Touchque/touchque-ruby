# frozen_string_literal: true

module Touchque
  module Resources
    # Setup secrets (the QR code the Touchque app scans) and a user's link status.
    class Auth
      def initialize(http)
        @http = http
      end

      # A new setup secret: show +qrCodeDataUrl+ so the Touchque app links the phone.
      # 409 when an unscanned or used secret exists (reset_secret issues a new one).
      def generate_secret(external_username)
        @http.post("/auth/generate-secret", { "externalUsername" => external_username })
      end

      def reset_secret(external_username)
        @http.post("/auth/secret/reset", { "externalUsername" => external_username })
      end

      def validate_secret(secret)
        @http.post("/auth/secret/validate", { "secret" => secret })
      end

      # A user's link status without sending a push: +used+ flips true and +deviceId+ is
      # set once the app scans the secret. +device+ is the linked phone's self-reported
      # posture (device trust), nil before a phone is linked. APIError 404 for an unknown user.
      def get_user(external_username)
        @http.get("/users/#{Util.seg(external_username)}")
      end
    end

    # Push approvals on the user's phone: request, status, wait, use once, report fraud.
    class Login
      FRAUD_REASONS = %w[chargeback account_takeover social_engineering other].freeze

      def initialize(http)
        @http = http
      end

      # A push to the user's phone (returns at once).
      #
      # details: transaction context for the approval screen, {"Amount" => "250 EUR"} or
      # [{label:, value:}], at most 8 lines (labels <= 40, values <= 120 characters). Build
      # it from server-side state. browser_proof: the X-Touchque-Browser header (silent
      # sign-ins), passed through untouched. context: for your Touchque Actions only.
      # security_changes: {password:, mfa:, device:, email:, phone:} => Time / ISO 8601 /
      # epoch ms, when each last changed in your system. destination: {kind:, value:, known:}
      # where the action sends money (shown in full on the phone). locale: "tr" or "en".
      def request(external_username, type: "LOGIN", reference_id: nil, client_ip: nil, user_agent: nil,
                  require_biometric: false, require_number_match: false, details: nil, browser_proof: nil,
                  context: nil, challenge_digits: nil, expires_in: nil, client_signals: nil,
                  security_changes: nil, destination: nil, locale: nil, qr_pairing: nil, device_risk: nil, device_risk_request_id: nil, reply: nil)
        body = { "externalUsername" => external_username, "type" => type || "LOGIN" }
        # An empty reference is no reference (the API answers null for it).
        body["referenceId"] = reference_id unless reference_id.to_s.empty?
        body["clientIp"] = client_ip unless client_ip.nil?
        body["userAgent"] = user_agent unless user_agent.nil?
        body["requireBiometric"] = true if require_biometric
        body["requireNumberMatch"] = true if require_number_match
        body["challengeDigits"] = challenge_digits if [2, 3].include?(challenge_digits)
        # How long the push waits for the person: 30 (default) to 300 seconds.
        body["expiresIn"] = expires_in unless expires_in.nil?
        # A browser pairing by QR code (qr_pairings), confirmed on the phone: only that phone is asked, once.
        body["qrPairing"] = qr_pairing unless qr_pairing.to_s.empty?
        # Ask the person to type back on the phone a sign-in code another service sent them:
        # { kind: "code", key: Touchque::CodeReply.new_key["publicKey"], channel: "sms", target: "+**********26" }.
        # status(id)["reply"]["ct"] holds only the ciphertext: Touchque::CodeReply.open opens it. Not with qr_pairing.
        body["reply"] = Util.stringify(reply) if reply
        body["clientSignals"] = client_signals if client_signals && !client_signals.empty?
        # The page's device report from @touchque/web (deviceRisk.collect), when the workspace
        # turned Device risk on: its signals only ever ask for more.
        body["deviceRisk"] = device_risk unless device_risk.to_s.empty?
        body["deviceRiskRequestId"] = device_risk_request_id unless device_risk_request_id.to_s.empty?
        body["details"] = Util.stringify(details) if details && !details.empty?
        body["browserProof"] = browser_proof if browser_proof && !browser_proof.empty?
        body["context"] = Util.stringify(context) if context && !context.empty?
        body["securityChanges"] = self.class.security_changes_body(security_changes) if security_changes && !security_changes.empty?
        body["destination"] = Util.stringify(destination) if destination && !destination.empty?
        body["locale"] = locale if locale && !locale.empty?
        @http.post("/login/request", body)
      end

      # Times go out as ISO 8601 UTC; strings and epoch milliseconds as given.
      def self.security_changes_body(changes)
        changes.each_with_object({}) do |(kind, at), out|
          next if at.nil?

          out[kind.to_s] = at.respond_to?(:utc) ? at.utc.strftime("%Y-%m-%dT%H:%M:%S.%LZ") : at
        end
      end

      # Where a request is now: PENDING, CONFIRMED, REJECTED or EXPIRED.
      def status(request_id)
        @http.get("/login/status/#{Util.seg(request_id)}")
      end

      # Asks the phone and polls until the user approves or rejects (every 0.4 s, up to
      # +timeout+ seconds). With number matching the user picks a number on the phone:
      # +on_challenge+ (or the block) gets {"requestId", "challengeCode", "expiresAt",
      # "reasons", "caseCode"} right after the request exists and before any waiting.
      # Show +challengeCode+ to the user now; the phone asks for it. An error it raises
      # is logged and ignored.
      #
      # Raises PasskeyRequiredError (policy: no push was sent; step_up: tapped during a
      # call), RejectedError, or TimeoutError.
      def verify(external_username, type: "LOGIN", timeout: 30, poll_interval: 0.4, on_challenge: nil, **options, &block)
        on_challenge ||= block
        sent = request(external_username, type: type, **options)
        request_id = sent["requestId"]
        raise PasskeyRequiredError.new(request_id) if sent["requiresPasskey"]

        if on_challenge
          challenge = { "requestId" => request_id, "expiresAt" => sent["expiresAt"] }
          %w[challengeCode reasons caseCode].each { |k| challenge[k] = sent[k] if sent[k] && !(sent[k].respond_to?(:empty?) && sent[k].empty?) }
          begin
            on_challenge.call(challenge)
          rescue StandardError => e
            # The caller's callback must not stop the wait.
            Touchque.log :warn, "[Touchque] on_challenge failed: #{e.class}: #{e.message}"
          end
        end
        wait(request_id, sent["challengeCode"], timeout, poll_interval)
      end

      # Waits for a request you already sent.
      def wait_for_approval(request_id, timeout: 30, poll_interval: 0.4)
        wait(request_id, nil, timeout, poll_interval)
      end

      # Approves a pending request with one of the user's recovery codes (no phone).
      def approve_with_recovery_code(request_id, code)
        @http.post("/login/recovery", { "requestId" => request_id, "code" => code })
      end

      # Uses an approved request exactly once. The first call on a CONFIRMED request wins
      # atomically; every later call raises APIError with code +already_used+ (409).
      def consume(request_id)
        @http.post("/login/#{Util.seg(request_id)}/consume", {})
      end

      # Reports a request you later learned was fraud (a chargeback, a confirmed account
      # takeover, a scam the user was talked into). The risk engine learns from it; the
      # request's status does not change. A repeat answers "alreadyReported" => true.
      def report_fraud(request_id, reason: nil, note: nil)
        raise ConfigError, "report_fraud() needs the request id" if request_id.to_s.empty?

        @http.post("/login/#{Util.seg(request_id)}/report-fraud", Util.compact({ "reason" => reason, "note" => note }))
      end

      private

      def wait(request_id, challenge_code, timeout, interval)
        deadline = Time.now + timeout
        loop do
          s = status(request_id)
          case s["status"]
          when "CONFIRMED"
            return {
              "approved" => true, "status" => "CONFIRMED", "requestId" => request_id,
              "challengeCode" => challenge_code, "assurance" => s["assurance"], "confirmedVia" => s["confirmedVia"],
              # Vishing Shield: approved during a call; critical actions wait for the phone to re-confirm.
              "provisional" => s["provisional"] ? true : false
            }
          when "REJECTED" then raise RejectedError.new(request_id)
          when "EXPIRED" then raise TimeoutError.new("Touchque: request '#{request_id}' expired before it was approved.", request_id)
          end
          # Vishing Shield: tapped during a call, the request now waits for a passkey in the browser.
          raise PasskeyRequiredError.new(request_id, "step_up") if s["status"] == "PENDING" && s["requiresPasskey"]
          if Time.now + interval > deadline
            raise TimeoutError.new("Touchque: request '#{request_id}' was not approved within #{timeout}s. The user did not respond in time.", request_id)
          end

          sleep interval
        end
      end
    end

    # WebAuthn / FIDO2 (passkeys), the backend half: the ceremony runs in the browser
    # (@touchque/web); your backend relays its JSON through these methods.
    class WebAuthn
      def initialize(http)
        @http = http
      end

      # Registration step 1. +approval_request_id+: a PASSKEY_ENROLL request the user approved
      # on their linked phone (403 enrollment_approval_required otherwise).
      def register_options(external_username, discoverable: false, approval_request_id: nil)
        body = { "externalUsername" => external_username }
        body["discoverable"] = true if discoverable
        body["approvalRequestId"] = approval_request_id if approval_request_id && !approval_request_id.empty?
        @http.post("/webauthn/register/options", body)
      end

      def register_verify(external_username, response, label: nil)
        body = { "externalUsername" => external_username, "response" => response }
        body["label"] = label unless label.nil?
        @http.post("/webauthn/register/verify", body)
      end

      # Second factor: options scoped to a pending request.
      def authenticate_options(request_id)
        @http.post("/webauthn/login/options", { "requestId" => request_id })
      end

      def authenticate_verify(request_id, response)
        @http.post("/webauthn/login/verify", { "requestId" => request_id, "response" => response })
      end

      # Whether passkey sign-in (passwordlessLoginEnabled) is on for your workspace.
      # Ask before your sign-in page shows its passkey button and passkey autofill:
      # when it is off, primary_options answers 403 passwordless_login_disabled.
      # { "enabled" => bool, "userVerification" => "required" | "preferred" | nil }.
      def primary_availability
        raw = @http.get("/webauthn/authenticate/primary/availability") || {}
        enabled = raw["enabled"] == true
        uv = raw["userVerification"]
        { "enabled" => enabled, "userVerification" => enabled && %w[required preferred].include?(uv) ? uv : nil }
      end

      # Passwordless sign-in step 1; without a user, any passkey of your site (autofill).
      def primary_options(external_username = nil)
        @http.post("/webauthn/authenticate/primary/options", Util.compact({ "externalUsername" => external_username }))
      end

      def primary_verify(attempt_id, response)
        @http.post("/webauthn/authenticate/primary/verify", { "attemptId" => attempt_id, "response" => response })
      end

      def list_credentials(external_username)
        @http.get("/webauthn/credentials", { "externalUsername" => external_username })
      end

      # Scope the deletion to +external_username+ (recommended).
      def delete_credential(credential_record_id, external_username: nil)
        path = "/webauthn/credentials/#{Util.seg(credential_record_id)}"
        path += "?externalUsername=#{Util.seg(external_username)}" if external_username
        @http.delete(path)
      end
    end

    # Offline Sign: QR challenge and typed-code approvals that work with the phone offline.
    class Offline
      ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

      def initialize(http)
        @http = http
      end

      # An offline QR challenge. Always pass +request_id+ when the QR follows a push: a
      # phone-side rejection then kills the QR, and number matching carries over.
      def challenge(external_username, type: "LOGIN", details: nil, client_ip: nil, user_agent: nil,
                    ttl_seconds: nil, include_qr_image: true, request_id: nil, require_number_match: false)
        body = { "externalUsername" => external_username, "type" => type }
        body["details"] = Util.stringify(details) unless details.nil?
        body["clientIp"] = client_ip unless client_ip.nil?
        body["userAgent"] = user_agent unless user_agent.nil?
        body["ttlSeconds"] = ttl_seconds unless ttl_seconds.nil?
        body["includeQrImage"] = false unless include_qr_image
        body["requestId"] = request_id unless request_id.nil?
        body["requireNumberMatch"] = true if require_number_match
        @http.post("/offline/challenge", body)
      end

      # The 7-character code from the phone. Never raises for a wrong, expired or used code:
      # check "approved"; "reason" is invalid_code, locked, expired, used, unknown_challenge,
      # request_rejected, too_many_failures or device_not_enrolled.
      def verify(challenge_id, code)
        not_approved_as_result { @http.post("/offline/verify", { "challengeId" => challenge_id, "code" => code }) }
      end

      # The rolling time-based code. Refused for critical action types.
      def verify_totp(external_username, code, type: "LOGIN", client_ip: nil, request_id: nil)
        body = { "externalUsername" => external_username, "code" => code, "type" => type }
        body["clientIp"] = client_ip unless client_ip.nil?
        body["requestId"] = request_id unless request_id.nil?
        not_approved_as_result { @http.post("/offline/totp/verify", body) }
      end

      # Salted, slow digests of each user's next codes, for checking typed codes while your
      # server cannot reach Touchque. Check a code with Offline.match_totp_verifier.
      def totp_verifiers(external_usernames, from_step: nil, steps: nil)
        body = { "externalUsernames" => external_usernames.to_a }
        body["fromStep"] = from_step unless from_step.nil?
        body["steps"] = steps unless steps.nil?
        @http.post("/offline/totp/verifiers", body)
      end

      # The step a typed code belongs to (the current one or one either side), or nil,
      # without calling Touchque. Accept each step once.
      def self.match_totp_verifier(verifiers, user, code, at: nil)
        given = code.to_s.upcase.delete(" \t-")
        return nil unless given.length == 7 && given.chars.all? { |c| ALPHABET.include?(c) }

        step_seconds = verifiers["stepSeconds"].to_i
        length = verifiers.dig("kdf", "length").to_i
        return nil if step_seconds <= 0 || length <= 0

        salt = Util.b64_decode(user["salt"])
        digests = Util.b64_decode(user["digests"])
        now = (at || Time.now).to_i / step_seconds
        [now, now - 1, now + 1].each do |step|
          next if step < user["fromStep"].to_i || step > verifiers["notAfterStep"].to_i

          i = (step - user["fromStep"].to_i) * 2 * length
          next if i + 2 * length > digests.bytesize

          got = OpenSSL::KDF.pbkdf2_hmac(given, salt: salt + ":#{step}", iterations: verifiers.dig("kdf", "iterations").to_i, length: length, hash: "sha256")
          return step if Util.secure_compare(digests.byteslice(i, length), got) || Util.secure_compare(digests.byteslice(i + length, length), got)
        end
        nil
      end

      private

      def not_approved_as_result
        yield
      rescue APIError => e
        raise if e.status >= 500

        { "approved" => false, "reason" => e.reason || e.code || e.error, "attemptsLeft" => e.attempts_left }
      end
    end
  end
end
