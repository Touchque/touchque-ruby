# frozen_string_literal: true

module TouchQue
  # GET /login, /callback and /logout of TouchQue Login (TouchQue::Rails.login_routes).
  # Subclass it (and point login_routes at yours) to link the user to your records in
  # touchque_after_sign_in.
  class SessionsController < ActionController::Base
    include TouchQue::Rails::HostedLogin

    skip_forgery_protection
  end
end
