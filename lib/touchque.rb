# frozen_string_literal: true

require_relative "touchque/version"
require_relative "touchque/errors"
require_relative "touchque/util"
require_relative "touchque/http"
require_relative "touchque/crypto"
require_relative "touchque/approvals"
require_relative "touchque/code_reply"
require_relative "touchque/safe_approval"
require_relative "touchque/resources/login"
require_relative "touchque/resources/actions"
require_relative "touchque/resources/people"
require_relative "touchque/resources/agents"
require_relative "touchque/resources/identity"
require_relative "touchque/resources/mobile"
require_relative "touchque/resources/qr_pairings"
require_relative "touchque/resources/device_risk"
require_relative "touchque/resources/safe_guard"
require_relative "touchque/resources/webhook"
require_relative "touchque/flow"
require_relative "touchque/client"
require_relative "touchque/relay"
require_relative "touchque/agent"
require_relative "touchque/org_agent"
require_relative "touchque/cross_app_access"
require_relative "touchque/security_events"
require_relative "touchque/agent_card"
require_relative "touchque/hosted_login"
require_relative "touchque/login_session"

# TouchQue: push approvals with number matching, passkeys, silent sign-ins, offline
# codes, verified webhooks, TouchQue Actions, AI agent approvals, TouchQue Login and the
# server side of the Mobile SDK.
#
#   # TQ_API_KEY=tq_...  TQ_API_SECRET=...
#   step = TouchQue.client.start("SEND_MONEY", "jane@acme.com", details: { "Amount" => "250 EUR" })
module TouchQue
  @lock = Mutex.new

  class << self
    attr_writer :client, :replay_cache, :hosted_login, :login_secret

    # Where the SDK reports its own problems: a misconfigured guard, a failed on_challenge,
    # a relay without get_login_user. nil (the default) logs nothing; set any Logger
    # (TouchQue.logger = Rails.logger). Lines carry an error's class and message, never
    # request data.
    attr_accessor :logger

    # @api private: one of the SDK's own problems (:warn or :error) to TouchQue.logger, if any.
    # A logger that raises never breaks the request.
    def log(level, message)
      logger&.public_send(level, message)
    rescue StandardError
      nil
    end

    # Options for TouchQue.client (api_key:, api_secret:, base_url:, timeout:); anything
    # left out comes from the environment.
    def configure(**options)
      @lock.synchronize do
        @client_options = options
        @client = nil
      end
    end

    # The shared client, built on first use from configure or the environment.
    def client
      @client || @lock.synchronize { @client ||= Client.new(**(@client_options || {})) }
    end

    # Webhook jtis already accepted (in-process by default; set one over Redis when you
    # run several processes: anything answering check_and_set(jti, ttl_seconds)).
    def replay_cache
      @replay_cache || @lock.synchronize { @replay_cache ||= MemoryReplayCache.new }
    end

    # TouchQue Login settings: domain:, client_id:, client_secret:, scope:, audience:,
    # redirect_uri:, callback_path:, login_path:, post_logout_redirect_uri:, session_max_age:.
    def login_options=(options)
      @login_options = Util.stringify(options || {}).transform_keys(&:to_sym)
      @hosted_login = nil
    end

    def login_options
      @login_options || {}
    end

    # The TouchQue Login client of login_options.
    def hosted_login
      @hosted_login || @lock.synchronize do
        @hosted_login ||= begin
          o = login_options
          raise ConfigError, "Set config.touchque.login (domain:, client_id:) or TouchQue.login_options" if o[:domain].to_s.empty?

          HostedLogin.new(domain: o[:domain], client_id: o[:client_id], client_secret: o[:client_secret],
                          scope: o[:scope] || "openid profile email", audience: o[:audience],
                          redirect_uri: o[:redirect_uri].to_s.match?(%r{\Ahttps?://}) ? o[:redirect_uri] : nil)
        end
      end
    end

    # The secret that encrypts the TouchQue Login cookies (at least 32 characters).
    def login_secret
      secret = @login_secret.respond_to?(:call) ? @login_secret.call : @login_secret
      raise ConfigError, "Set TouchQue.login_secret (32+ characters) for the TouchQue Login cookies" if secret.to_s.length < 32

      secret
    end
  end

  # The relay as a Rack app (Sinatra, plain Rack), loaded on first use: Rack is not a
  # dependency of the gem.
  module Rack
    autoload :Relay, File.expand_path("touchque/rack/relay", __dir__)
  end
end

if defined?(Rails::Railtie)
  require_relative "touchque/rack/relay"
  require_relative "touchque/rails/guard"
  require_relative "touchque/rails/hosted_login"
  require_relative "touchque/railtie"
end
