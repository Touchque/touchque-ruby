# frozen_string_literal: true

require "monitor"
require "set"
require_relative "../touchque"

module Touchque
  # Helpers for your app's tests (require "touchque/testing"; never in production code).
  module Testing
    # A Touchque client for your app's tests: no network, no API keys, no Node.js. It is a
    # real Touchque::Client whose API calls are answered in memory, so the real guard runs:
    # your routes answer exactly what they answer in production (202 and a token, then your
    # action once approved), and your test plays the phone.
    #
    #   require "touchque/testing"
    #
    #   tq = Touchque::Testing::FakeTouchque.new.install # the default client (Touchque.client)
    #   post "/transfers", params: { amount: 5 }, as: :json
    #   assert_response 202
    #   tq.approve                                        # the person approves on the phone
    #   post "/transfers", params: { amount: 5 }, as: :json,
    #                      headers: { "X-Touchque-Token" => response.parsed_body["token"] }
    #   assert_response :success
    #   tq.uninstall
    #
    # +linked+ (default true): every user has a phone linked, so a guarded route sends a
    # push. unlink(user) gives that user the first-time QR instead; with linked: false only
    # the users you link have one.
    #
    # The phone is yours to drive: approve, reject or expire the latest request (or one by
    # its id), or set auto_approve to approve every request as it is made. +requests+ lists
    # the approval requests ("id", "user", "type", "details", "referenceId", "status":
    # PENDING / CONFIRMED / REJECTED / EXPIRED, "expiresAt": 30 s after it was made, answered
    # on each status check), +calls+ every API call ("method", "path", "body"), in order.
    #
    # +number_match+: pushes ask for the number "47". +secret_ttl_ms+: how long a first-time
    # QR works (5 minutes, like the API). The offline code is "ABCD123" and the time-based
    # code "123456" (+offline_code+, +totp_code+).
    #
    # It answers the calls the step-up guard makes (approval requests, first-time linking,
    # offline codes, silent sign-in checks) and defining action types, like the shared fake
    # API the SDKs' own tests use. Any other call raises Touchque::APIError 404.
    class FakeTouchque < Client
      # The code the phone shows for an offline QR (X-Touchque-Code).
      OFFLINE_CODE = "ABCD123"
      # The time-based code (X-Touchque-Code-Type: totp).
      TOTP_CODE = "123456"

      NOT_INSTALLED = Object.new.freeze
      private_constant :NOT_INSTALLED

      # Approve every new request at once, as if the person tapped Approve straight away.
      attr_accessor :auto_approve
      # Ask for the number "47" on every push.
      attr_accessor :number_match
      # How long a first-time QR works, in ms.
      attr_accessor :secret_ttl_ms
      # The codes the fake accepts for an offline QR and as the time-based code.
      attr_accessor :offline_code, :totp_code
      # Whether users you did not link or unlink have a phone (the linked: option).
      attr_reader :linked_by_default
      # The approval requests made so far, oldest first.
      attr_reader :requests
      # Every API call so far: {"method", "path", "body"}, oldest first.
      attr_reader :calls

      def initialize(linked: true, auto_approve: false, number_match: false)
        @lock = Monitor.new
        @linked_by_default = linked
        @auto_approve = auto_approve
        @number_match = number_match
        @secret_ttl_ms = 300_000
        @offline_code = OFFLINE_CODE
        @totp_code = TOTP_CODE
        @requests = []
        @calls = []
        @linked = Set.new
        @unlinked = Set.new
        @pending = {}
        @challenges = {}
        @defined_types = {}
        @seq = 0
        @replaced = NOT_INSTALLED
        # Signs the guard tokens only: nothing leaves the process.
        super(api_key: "tq_fake_key", api_secret: "fake_secret", base_url: "http://localhost")
      end

      # ── the phone ──────────────────────────────────────────────────────

      # +user+ has a phone linked (as if they scanned the first-time QR).
      def link(user)
        @lock.synchronize do
          @linked << user
          @unlinked.delete(user)
          @pending.delete(user)
        end
        self
      end

      # +user+ has no phone linked: a guarded route shows them the first-time QR.
      def unlink(user)
        @lock.synchronize do
          @unlinked << user
          @linked.delete(user)
          @pending.delete(user)
        end
        self
      end

      def linked?(user)
        @lock.synchronize { @linked.include?(user) || (linked_by_default && !@unlinked.include?(user)) }
      end

      # The person approves on the phone: the latest request, or +request_id+.
      # via: "WEBAUTHN" approves it with a passkey. Returns the request's id.
      def approve(request_id = nil, via: "DEVICE")
        @lock.synchronize do
          request = pick(request_id)
          request.merge!("status" => "CONFIRMED", "confirmedVia" => via)
          request["id"]
        end
      end

      # The person taps Reject: the latest request, or +request_id+.
      def reject(request_id = nil)
        @lock.synchronize do
          request = pick(request_id)
          request["status"] = "REJECTED"
          request["id"]
        end
      end

      # Nobody answered in time: the latest request, or +request_id+.
      def expire(request_id = nil)
        @lock.synchronize do
          request = pick(request_id)
          request["status"] = "EXPIRED"
          request["id"]
        end
      end

      # ── the default client ─────────────────────────────────────────────

      # Makes this the default client (Touchque::Guard.default_client = self, so
      # Touchque.client), which require_touchque, Touchque::Guard.run(nil, ...) and a relay
      # given no client use, until uninstall.
      # With a block: installed for the block only. Install it after your app configured
      # Touchque: Touchque.configure drops it.
      def install
        @lock.synchronize do
          @replaced = Touchque.instance_variable_get(:@client) if @replaced.equal?(NOT_INSTALLED)
          Touchque::Guard.default_client = self
        end
        return self unless block_given?

        begin
          yield self
        ensure
          uninstall
        end
      end

      # Puts back the default client that install replaced.
      def uninstall
        @lock.synchronize do
          next if @replaced.equal?(NOT_INSTALLED)

          Touchque::Guard.default_client = @replaced
          @replaced = NOT_INSTALLED
        end
        self
      end

      private

      def transport(**options)
        Transport.new(self, **options)
      end

      def pick(request_id)
        request = request_id ? find(request_id) : @requests.last
        return request if request

        raise ArgumentError, request_id ? "FakeTouchque: no approval request #{request_id}" : "FakeTouchque: no approval request yet"
      end

      def find(request_id)
        @requests.find { |r| r["id"] == request_id }
      end

      # What the fake answers: [status, data].
      def answer(method, path_with_query, body)
        path = path_with_query.split("?", 2).first
        @lock.synchronize do
          @calls << { "method" => method, "path" => path, "body" => body }
          ROUTES.each do |route_method, pattern, handler|
            next unless route_method == method && (m = pattern.match(path))

            return send(handler, body.is_a?(Hash) ? body : {}, *m.captures.map { |part| URI.decode_www_form_component(part) })
          end
          [404, { "error" => "FakeTouchque does not answer #{method} #{path}" }]
        end
      end

      def login_request(body)
        user = body["externalUsername"]
        return [404, { "code" => "device_not_linked", "error" => "No linked device found for this user" }] unless linked?(user)

        @seq += 1
        number = number_match || body["requireNumberMatch"] == true ? "47" : nil
        request = {
          "id" => format("00000000-0000-4000-8000-%012d", @seq), "user" => user, "type" => body["type"],
          "referenceId" => body["referenceId"], "details" => body["details"], "status" => "PENDING",
          "consumed" => false, "challengeCode" => number, "confirmedVia" => nil,
          "expiresAt" => Steps.iso_of(Util.now_ms + 30_000)
        }
        request.merge!("status" => "CONFIRMED", "confirmedVia" => "DEVICE") if auto_approve
        @requests << request
        [200, { "message" => "Request sent", "requestId" => request["id"], "challengeCode" => number,
                "expiresAt" => request["expiresAt"], "caseCode" => "K7P-2QX" }]
      end

      def approval(request)
        passkey = request["confirmedVia"] == "WEBAUTHN"
        {
          "externalUsername" => request["user"], "type" => request["type"], "referenceId" => request["referenceId"],
          "details" => request["details"], "confirmedVia" => request["confirmedVia"],
          "assurance" => request["status"] == "CONFIRMED" ? { "phishingResistant" => passkey, "method" => passkey ? "passkey" : "push" } : nil,
          "provisional" => false, "reconfirmedAt" => nil, "revoked" => false, "revokeReason" => nil
        }
      end

      def login_status(_body, request_id)
        request = find(request_id)
        return [404, { "code" => "not_found" }] unless request

        # The request's expiry, as the API answers it on every status check.
        [200, { "status" => request["status"], "consumed" => request["consumed"], "expiresAt" => request["expiresAt"] }.merge(approval(request))]
      end

      def login_consume(_body, request_id)
        request = find(request_id)
        return [404, { "code" => "not_found" }] unless request
        unless request["status"] == "CONFIRMED"
          return [409, { "code" => { "REJECTED" => "rejected", "EXPIRED" => "expired" }.fetch(request["status"], "not_approved") }]
        end
        return [409, { "code" => "already_used" }] if request["consumed"]

        request["consumed"] = true
        [200, { "consumed" => true, "requestId" => request["id"], "approvalProof" => nil }.merge(approval(request))]
      end

      def new_secret(user)
        @seq += 1
        expires = Util.now_ms + secret_ttl_ms
        @pending[user] = expires
        { "secret" => "S#{@seq}", "qrCodeDataUrl" => "data:image/png;base64,QR#{@seq}-#{user}", "externalUsername" => user,
          "expiresAt" => Steps.iso_of(expires), "ttlMs" => secret_ttl_ms, "recoveryCodes" => ["r#{@seq}"] }
      end

      def generate_secret(body)
        user = body["externalUsername"]
        return [409, { "error" => "already linked" }] if linked?(user)
        return [409, { "error" => "Secret already generated" }] if @pending.key?(user)

        [200, new_secret(user)]
      end

      # Like the API: a reset unlinks the phone (the guard only resets a user it found not linked).
      def reset_secret(body)
        user = body["externalUsername"]
        @unlinked << user
        @linked.delete(user)
        [200, { "success" => true }.merge(new_secret(user))]
      end

      def get_user(_body, user)
        linked = linked?(user)
        return [404, { "error" => "not found" }] if !linked && !@pending.key?(user)

        [200, { "externalUsername" => user, "deviceId" => linked ? "dev-1" : nil, "used" => linked, "frozen" => false, "device" => nil }]
      end

      def offline_challenge(body)
        request_id = body["requestId"]
        follows = request_id ? find(request_id) : nil
        return [404, { "error" => "request_not_found" }] if request_id && follows.nil?
        return [409, { "error" => "request_rejected" }] if follows && follows["status"] == "REJECTED"

        @seq += 1
        challenge_id = "ch-#{@seq}"
        @challenges[challenge_id] = { "user" => body["externalUsername"], "type" => body["type"], "used" => false, "requestId" => request_id }
        out = { "challengeId" => challenge_id, "qr" => "TQ2.fake", "qrDataUrl" => "data:image/png;base64,OFFLINE",
                "expiresAt" => Steps.iso_of(Util.now_ms + 120_000), "expiresInSeconds" => 120, "totpAvailable" => true }
        number = follows&.fetch("challengeCode", nil) || (body["requireNumberMatch"] == true ? "47" : nil)
        out["challengeCode"] = number if number
        [200, out]
      end

      def rejected?(request_id)
        request = request_id ? find(request_id) : nil
        request ? request["status"] == "REJECTED" : false
      end

      def offline_verify(body)
        challenge = @challenges[body["challengeId"]]
        return [404, { "approved" => false, "reason" => "unknown_challenge" }] unless challenge
        return [410, { "approved" => false, "reason" => "used" }] if challenge["used"]
        return [410, { "approved" => false, "reason" => "request_rejected" }] if rejected?(challenge["requestId"])
        return [401, { "approved" => false, "reason" => "invalid_code", "attemptsLeft" => 4 }] unless body["code"] == offline_code

        challenge["used"] = true
        [200, { "approved" => true, "challengeId" => body["challengeId"], "externalUsername" => challenge["user"], "type" => challenge["type"] }]
      end

      def offline_totp_verify(body)
        return [410, { "approved" => false, "reason" => "request_rejected" }] if rejected?(body["requestId"])
        return [401, { "approved" => false, "reason" => "invalid_code" }] unless body["code"] == totp_code

        [200, { "approved" => true, "externalUsername" => body["externalUsername"] }]
      end

      # Silent sign-ins: the fake always asks the phone.
      def risk_check(body)
        reason = if body["browserProof"]
                   { "code" => "new_browser", "text" => "This browser has not been approved on the phone for this account" }
                 else
                   { "code" => "no_browser_key", "text" => "No device-bound browser key was presented" }
                 end
        [200, { "prompt" => true, "reasons" => [reason], "assurance" => "normal", "silentMode" => "enforce", "caseCode" => "CHK-2QX" }]
      end

      def define_action_type(body)
        @seq += 1
        defined = { "id" => "at-#{@seq}", "type" => body["type"], "name" => body["name"], "description" => body["description"] || "",
                    "critical" => body["critical"] ? true : false, "active" => true }
        @defined_types[body["type"]] = defined
        [200, defined]
      end

      def list_action_types(_body)
        [200, @defined_types.values]
      end

      # What the fake answers: method, path pattern, handler (body, path parts).
      ROUTES = [
        ["POST", %r{\A/login/request\z}, :login_request],
        ["GET", %r{\A/login/status/([^/]+)\z}, :login_status],
        ["POST", %r{\A/login/([^/]+)/consume\z}, :login_consume],
        ["POST", %r{\A/auth/generate-secret\z}, :generate_secret],
        ["POST", %r{\A/auth/secret/reset\z}, :reset_secret],
        ["GET", %r{\A/users/([^/]+)\z}, :get_user],
        ["POST", %r{\A/offline/challenge\z}, :offline_challenge],
        ["POST", %r{\A/offline/verify\z}, :offline_verify],
        ["POST", %r{\A/offline/totp/verify\z}, :offline_totp_verify],
        ["POST", %r{\A/risk/check\z}, :risk_check],
        ["POST", %r{\A/action-types\z}, :define_action_type],
        ["GET", %r{\A/action-types\z}, :list_action_types]
      ].freeze
      private_constant :ROUTES

      # The HTTP of a FakeTouchque: every call goes to the fake as JSON, and comes back as
      # JSON or as the error the real client raises.
      class Transport < HTTP
        def initialize(fake, **options)
          @fake = fake
          super(**options)
        end

        private

        def send_request(method, path_with_query, body, raw: false)
          sent = body.nil? ? {} : JSON.parse(Util.json(Util.stringify(body)))
          status, data = @fake.__send__(:answer, method, path_with_query, sent)
          text = Util.json(data)
          return text if raw && status < 300
          raise APIError.for(status, JSON.parse(text)) if status >= 300

          JSON.parse(text)
        end
      end
      private_constant :Transport
    end

    # Another name for FakeTouchque.
    FakeClient = FakeTouchque
  end
end
