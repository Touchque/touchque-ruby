# frozen_string_literal: true

module Touchque
  DEFAULT_BASE_URL = "https://api.touchque.com"

  # The Touchque client. Every call is signed with your API secret, so it belongs on
  # your server; browser pieces relay through it.
  #
  #   # TQ_API_KEY=tq_...  TQ_API_SECRET=...
  #   tq = Touchque::Client.new
  #   step = tq.start("SEND_MONEY", "jane@acme.com", details: { "Amount" => "250 EUR" })
  #
  # Thread-safe: create one and reuse it (in Rails, Touchque.client).
  class Client
    # @api private: the ConfigError message for a missing key or secret.
    MISSING_KEYS = "Set TQ_API_KEY and TQ_API_SECRET (or pass api_key: and api_secret:)."

    attr_reader :auth, :login, :webauthn, :webhook, :offline, :action_types, :actions, :risk, :recovery,
                :assist, :agents, :identity, :mobile, :qr_pairings, :device_risk, :safe_guard

    # Anything left nil falls back to the environment: TQ_API_KEY, TQ_API_SECRET and
    # TQ_API_URL (default https://api.touchque.com). +timeout+ is seconds per request.
    def initialize(api_key: nil, api_secret: nil, base_url: nil, timeout: 10)
      api_key ||= ENV.fetch("TQ_API_KEY", nil)
      api_secret ||= ENV.fetch("TQ_API_SECRET", nil)
      base_url ||= ENV["TQ_API_URL"].to_s.empty? ? DEFAULT_BASE_URL : ENV.fetch("TQ_API_URL")
      raise ConfigError, MISSING_KEYS if api_key.to_s.empty? || api_secret.to_s.empty?
      raise ConfigError, "api_key must start with \"tq_\". Did you accidentally swap api_key and api_secret?" unless api_key.start_with?("tq_")

      Util.assert_safe_url!(base_url, "base_url")
      @http = transport(api_key: api_key, api_secret: api_secret, base_url: base_url.chomp("/"), timeout: timeout)
      @auth = Resources::Auth.new(@http)
      @login = Resources::Login.new(@http)
      @webauthn = Resources::WebAuthn.new(@http)
      @webhook = Resources::Webhook.new(api_secret)
      @offline = Resources::Offline.new(@http)
      @action_types = Resources::ActionTypes.new(@http)
      @actions = Resources::Actions.new(@http)
      @risk = Resources::Risk.new(@http)
      @recovery = Resources::Recovery.new(@http)
      @assist = Resources::Assist.new(@http)
      @agents = Resources::Agents.new(@http)
      @identity = Resources::Identity.new(@http)
      @mobile = Resources::Mobile.new(@http)
      @qr_pairings = Resources::QrPairings.new(@http)
      @device_risk = Resources::DeviceRisk.new(@http)
      @safe_guard = Resources::SafeGuard.new(@http)
    end

    # @api private: signs the guard tokens.
    def api_secret
      @http.api_secret
    end

    # Starts an approval and returns at once: show the step in your UI. "waiting" with
    # "number": show the number, the user picks it on the phone. "enroll": show
    # step["enroll"]["qrCodeDataUrl"] so the user links the Touchque app first.
    # +browser_proof+ (silent sign-ins): the X-Touchque-Browser header, passed through.
    def start(action, user, details: nil, reference_id: nil, ip: nil, user_agent: nil, browser_proof: nil, context: nil)
      Steps.start(self, action, user, details: details, reference_id: reference_id, ip: ip, user_agent: user_agent,
                                      browser_proof: browser_proof, context: context)
    end

    # Where a started approval is now: waiting, approved, rejected, expired...
    def check(request_id)
      Steps.check(self, request_id)
    end

    # Uses an approved request exactly once, after checking it is for this user, action
    # and transaction. Call it right before doing the protected thing.
    def complete(request_id, user, action, details: nil, reference_id: nil)
      Steps.complete(self, request_id, user, action, details: details, reference_id: reference_id)
    end

    # Runs the block only after the user approved on the phone (a push and the wait of
    # login.verify).
    def protect(user, type: "LOGIN", **options)
      login.verify(user, type: type, **options)
      yield
    end

    private

    # What every resource calls the API through (Touchque::Testing::FakeTouchque answers in memory).
    def transport(**options)
      HTTP.new(**options)
    end
  end
end
