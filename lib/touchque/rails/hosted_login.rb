# frozen_string_literal: true

module Touchque
  module Rails
    # Touchque Login in a Rails app: a controller with the sign-in routes, and a
    # before_action for the pages that need a signed-in customer.
    #
    #   # config/application.rb (or an initializer)
    #   config.touchque.login = { domain: "acme.login.touchque.com", client_id: "...", client_secret: "...",
    #                             scope: "openid profile email offline_access" }
    #
    #   # config/routes.rb
    #   Touchque::Rails.login_routes(self)                      # GET /login, /callback, /logout → Touchque::SessionsController
    #
    #   class AccountController < ApplicationController
    #     include Touchque::Rails::HostedLogin
    #     before_action :require_touchque_sign_in
    #     def show = render(json: touchque_session["user"])
    #   end
    #
    # The session lives in encrypted cookies (AES-256-GCM, split when large; no session
    # store needed), keyed from config.touchque.session_secret or secret_key_base. A token
    # about to expire is refreshed when a refresh token is there (ask for offline_access).
    module HostedLogin
      SESSION_COOKIE = "tq_session"
      TX_COOKIE = "tq_login_tx"

      # GET /login: redirects to the tenant (returnTo, screen_hint=signup, login_hint,
      # connection, organization and invitation are passed on).
      def touchque_login
        login = Touchque.hosted_login
        auth = login.authorization_url(
          redirect_uri: touchque_redirect_uri, screen_hint: params[:screen_hint] == "signup" ? "signup" : nil,
          login_hint: params[:login_hint].presence, connection: params[:connection].presence,
          organization: params[:organization].presence, invitation: params[:invitation].presence
        )
        tx = { "state" => auth["state"], "nonce" => auth["nonce"], "codeVerifier" => auth["codeVerifier"],
               "returnTo" => Touchque::LoginSession.safe_return_to(params[:returnTo]) }
        touchque_write_cookie(TX_COOKIE, Touchque::LoginSession.seal(tx, Touchque.login_secret, "tx", 900), 900)
        redirect_to auth["url"], allow_other_host: true
      end

      # GET /callback: checks the sign-in and opens the session.
      def touchque_callback
        tx = Touchque::LoginSession.unseal(Touchque::LoginSession.read(TX_COOKIE, cookies.to_h), Touchque.login_secret, "tx")
        touchque_write_cookie(TX_COOKIE, nil, 0)
        return render(json: { error: "state_missing", error_description: "This sign-in expired or started in another browser" }, status: :bad_request) unless tx

        tokens = Touchque.hosted_login.handle_callback(request.query_parameters, state: tx["state"], nonce: tx["nonce"],
                                                                                 code_verifier: tx["codeVerifier"], redirect_uri: touchque_redirect_uri)
        session = touchque_session_from(tokens)
        touchque_after_sign_in(session)
        touchque_store_session(session)
        redirect_to Touchque::LoginSession.safe_return_to(tx["returnTo"])
      rescue Touchque::HostedLoginError => e
        render json: { error: e.error_code, error_description: e.description }, status: :bad_request
      end

      # GET /logout: ends the session here and at the tenant.
      def touchque_logout
        session = touchque_session
        touchque_store_session(nil)
        redirect_to Touchque.hosted_login.logout_url(id_token_hint: session && session["idToken"],
                                                     post_logout_redirect_uri: Touchque.login_options[:post_logout_redirect_uri]),
                    allow_other_host: true
      end

      # The signed-in session ({"user" => claims, "accessToken", "expiresAt", "idToken",
      # "refreshToken", "scope"}), refreshed when it is about to expire, or nil.
      def touchque_session
        return @touchque_session if defined?(@touchque_session)

        secret = Touchque.login_secret
        session = Touchque::LoginSession.unseal(Touchque::LoginSession.read(SESSION_COOKIE, cookies.to_h), secret, "session")
        if session && session["expiresAt"].to_i - 30 < Touchque::Util.now
          session = begin
            session["refreshToken"] ? touchque_session_from(Touchque.hosted_login.refresh(session["refreshToken"]), session) : nil
          rescue Touchque::HostedLoginError
            nil
          end
          touchque_store_session(session)
        end
        @touchque_session = session
      end

      # before_action: the session, or a redirect to /login (JSON requests get 401).
      def require_touchque_sign_in
        return if touchque_session

        if request.format.json?
          render json: { error: "sign_in_required" }, status: :unauthorized
        else
          redirect_to "#{Touchque.login_options[:login_path] || "/login"}?returnTo=#{Touchque::Util.seg(Touchque::LoginSession.safe_return_to(request.fullpath))}"
        end
      end

      private

      # Override to link the user to your records before the redirect.
      def touchque_after_sign_in(_session); end

      def touchque_redirect_uri
        configured = Touchque.login_options[:redirect_uri]
        return configured if configured.to_s.match?(%r{\Ahttps?://})

        "#{request.base_url}#{configured || Touchque.login_options[:callback_path] || "/callback"}"
      end

      def touchque_session_from(tokens, previous = nil)
        {
          "user" => tokens["claims"].nil? || tokens["claims"].empty? ? previous&.dig("user") : tokens["claims"],
          "accessToken" => tokens["accessToken"], "expiresAt" => tokens["expiresAt"], "scope" => tokens["scope"],
          "idToken" => tokens["idToken"] || previous&.dig("idToken"), "refreshToken" => tokens["refreshToken"] || previous&.dig("refreshToken")
        }.compact
      end

      def touchque_store_session(session)
        max_age = (Touchque.login_options[:session_max_age] || 7 * 86_400).to_i
        sealed = session && Touchque::LoginSession.seal(session, Touchque.login_secret, "session", max_age)
        Touchque::LoginSession.cookie_values(SESSION_COOKIE, sealed, cookies.to_h.keys).each do |name, value|
          touchque_write_cookie(name, value, max_age)
        end
        @touchque_session = session
      end

      def touchque_write_cookie(name, value, max_age)
        if value.nil?
          cookies.delete(name, path: "/")
        else
          cookies[name] = { value: value, path: "/", httponly: true, same_site: :lax, secure: request.ssl?, expires: Time.now + max_age }
        end
      end
    end

    # The Touchque Login routes: GET /login, /callback and /logout to +controller+ (default
    # "touchque/sessions": Touchque::SessionsController, provided by this gem).
    def self.login_routes(router, controller: "touchque/sessions", login: "/login", callback: "/callback", logout: "/logout")
      router.get login, to: "#{controller}#touchque_login"
      router.get callback, to: "#{controller}#touchque_callback"
      router.get logout, to: "#{controller}#touchque_logout"
    end
  end
end
