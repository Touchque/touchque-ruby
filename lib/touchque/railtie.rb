# frozen_string_literal: true

require "rails/railtie"

module Touchque
  # Rails: config.touchque (or credentials.touchque, or TQ_API_KEY / TQ_API_SECRET)
  # configures Touchque.client; config.touchque.login configures Touchque Login.
  #
  #   config.touchque.api_key = "tq_..."           # default: credentials.touchque.api_key, then TQ_API_KEY
  #   config.touchque.api_secret = "..."
  #   config.touchque.login = { domain: "acme.login.touchque.com", client_id: "...", client_secret: "..." }
  #   config.touchque.session_secret = "..."       # Touchque Login cookies; default: secret_key_base
  #
  # Touchque.logger defaults to Rails.logger, so the SDK's own problems (a guard without its
  # keys, a failing error_body) reach your log. Set your own in an initializer (nil: none).
  class Railtie < ::Rails::Railtie
    config.touchque = ActiveSupport::OrderedOptions.new

    # Before the app's config/initializers, which may set their own.
    initializer "touchque.logger" do
      Touchque.logger ||= ::Rails.logger
    end

    initializer "touchque.configure" do |app|
      settings = app.config.touchque
      credentials = app.respond_to?(:credentials) ? (app.credentials.config[:touchque] || {}) : {}
      options = {
        api_key: settings.api_key || credentials[:api_key],
        api_secret: settings.api_secret || credentials[:api_secret],
        base_url: settings.base_url || credentials[:base_url]
      }.compact
      Touchque.configure(**options) unless options.empty?
      login = settings.login || credentials[:login]
      Touchque.login_options = login.to_h if login
      Touchque.login_secret = -> { settings.session_secret || app.secret_key_base }
    end

    initializer "touchque.sessions_controller" do
      ActiveSupport.on_load(:action_controller_base) { require "touchque/rails/sessions_controller" }
    end
  end
end
