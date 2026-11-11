# frozen_string_literal: true

module Touchque
  # GET /login, /callback and /logout of Touchque Login (Touchque::Rails.login_routes).
  # Subclass it (and point login_routes at yours) to link the user to your records in
  # touchque_after_sign_in.
  class SessionsController < ActionController::Base
    include Touchque::Rails::HostedLogin

    skip_forgery_protection
  end
end
