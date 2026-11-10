# frozen_string_literal: true

require "rails/railtie"

module TouchQue
  # Rails: config.touchque (or credentials.touchque, or TQ_API_KEY / TQ_API_SECRET)
  # configures TouchQue.client; config.touchque.login configures TouchQue Login.
  #
  #   config.touchque.api_key = "tq_..."           # default: credentials.touchque.api_key, then TQ_API_KEY
  #   config.touchque.api_secret = "..."
  #   config.touchque.login = { domain: "acme.login.touchque.com", client_id: "...", client_secret: "..." }
  #   config.touchque.session_secret = "..."       # TouchQue Login cookies; default: secret_key_base
  class Railtie < ::Rails::Railtie
    config.touchque = ActiveSupport::OrderedOptions.new

    initializer "touchque.configure" do |app|
      settings = app.config.touchque
      credentials = app.respond_to?(:credentials) ? (app.credentials.config[:touchque] || {}) : {}
      options = {
        api_key: settings.api_key || credentials[:api_key],
        api_secret: settings.api_secret || credentials[:api_secret],
        base_url: settings.base_url || credentials[:base_url]
      }.compact
      TouchQue.configure(**options) unless options.empty?
      login = settings.login || credentials[:login]
      TouchQue.login_options = login.to_h if login
      TouchQue.login_secret = -> { settings.session_secret || app.secret_key_base }
    end

    initializer "touchque.sessions_controller" do
      ActiveSupport.on_load(:action_controller_base) { require "touchque/rails/sessions_controller" }
    end
  end
end
