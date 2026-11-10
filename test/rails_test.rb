# frozen_string_literal: true

require "test_helper"
require "hosted_login_test"
require "logger"
require "rails"
require "action_controller/railtie"
require "rack/test"
require "touchque/rack/relay"
require "touchque/rails/guard"
require "touchque/rails/hosted_login"
require "touchque/railtie"

TENANT = FakeTenant.new
WEBHOOK_EVENTS = []

class TouchQueTestApp < Rails::Application
  config.root = __dir__
  config.eager_load = false
  config.secret_key_base = "s" * 64
  config.logger = Logger.new(nil)
  config.hosts.clear
  config.action_controller.allow_forgery_protection = false
  config.touchque.api_key = "tq_test_key"
  config.touchque.api_secret = "test_secret"
  config.touchque.base_url = TestSupport::FakeApi.instance.base_url
  config.touchque.login = { domain: FakeTenant::ISSUER, client_id: FakeTenant::CLIENT, client_secret: "s3cret" }
end

class TransfersController < ActionController::Base
  include TouchQue::Rails::Guard

  require_touchque "SEND_MONEY", only: :create, user: -> { request.headers["X-User"] }, details: -> { { "Amount" => params[:amount].to_s } }

  def create
    render json: { via: touchque_approval["confirmedVia"] }
  end
end

class WebhooksController < ActionController::Base
  include TouchQue::Rails::Webhook

  verify_touchque_webhook

  def create
    WEBHOOK_EVENTS << touchque_webhook["event"]
    head :ok
  end
end

class AccountController < ActionController::Base
  include TouchQue::Rails::HostedLogin

  before_action :require_touchque_sign_in

  def show
    render json: { email: touchque_session["user"]["email"] }
  end
end

TouchQueTestApp.initialize!
TouchQue.hosted_login = TouchQue::HostedLogin.new(domain: FakeTenant::ISSUER, client_id: FakeTenant::CLIENT, client_secret: "s3cret", transport: TENANT.transport)
TouchQueTestApp.routes.draw do
  post "/transfer" => "transfers#create"
  post "/webhooks/touchque" => "webhooks#create"
  get "/account" => "account#show"
  TouchQue::Rails.login_routes(self)
  mount TouchQue::Rack::Relay.new(
    get_user_id: ->(req) { req.get_header("HTTP_X_USER") },
    get_login_user: ->(req) { req.get_header("HTTP_X_PASSWORD_OK") },
    on_authenticated: ->(_req, response, info) { response.add_header("Set-Cookie", "app_session=#{info["externalUsername"]}; Path=/; HttpOnly") }
  ) => "/touchque"
end

# The Rails integration (Railtie, guard, webhook and sign-in concerns) and the Rack relay
# in a small Rails app, against the fake API and an in-process fake tenant.
class RailsTest < FakeApiTest
  include Rack::Test::Methods

  def app
    TouchQueTestApp
  end

  def json
    JSON.parse(last_response.body)
  end

  def test_railtie_configures_the_client
    assert_equal "test_secret", TouchQue.client.api_secret
    assert_equal FakeTenant::ISSUER, TouchQue.login_options[:domain]
    assert TouchQue.login_secret.length >= 32
  end

  def test_require_touchque_runs_the_action_once_after_the_phone
    api.link("ada@acme.com")
    header "X-User", "ada@acme.com"
    post "/transfer", { amount: "250 EUR" }
    assert_equal [202, "waiting", "47"], [last_response.status, json["touchque"]["state"], json["touchque"]["number"]]
    assert_equal "no-store", last_response.headers["Cache-Control"]
    assert_equal [{ "label" => "Amount", "value" => "250 EUR" }], api.last_call["body"]["details"]
    token = json["token"]
    header TouchQue::Guard::TOKEN_HEADER, token
    post "/transfer", { amount: "250 EUR" }
    assert_equal 202, last_response.status
    api.approve
    post "/transfer", { amount: "9999 EUR" }
    assert_equal 202, last_response.status
    post "/transfer", { amount: "250 EUR" }
    assert_equal [200, "DEVICE"], [last_response.status, json["via"]]
    header "X-User", nil
    header TouchQue::Guard::TOKEN_HEADER, nil
    post "/transfer", { amount: "1" }
    assert_equal 401, last_response.status
    api.link("bo@acme.com")
    api.opts(frozen: true)
    header "X-User", "bo@acme.com"
    post "/transfer", { amount: "1" }
    assert_equal [423, "900"], [last_response.status, last_response.headers["Retry-After"]]
  end

  def test_relay_login_with_a_first_factor
    api.link("cy@acme.com")
    post "/touchque/login", JSON.generate({ externalUsername: "attacker@evil.com" }), "CONTENT_TYPE" => "application/json"
    assert_equal 401, last_response.status
    header "X-Password-Ok", "cy@acme.com"
    post "/touchque/login", JSON.generate({ externalUsername: "attacker@evil.com" }), "CONTENT_TYPE" => "application/json"
    assert_equal 202, last_response.status
    assert_equal "cy@acme.com", api.last_call["body"]["externalUsername"]
    token = json["token"]
    api.approve
    header TouchQue::Guard::TOKEN_HEADER, token
    post "/touchque/login", "{}", "CONTENT_TYPE" => "application/json"
    assert_equal [200, "success"], [last_response.status, json["status"]]
    assert_includes Array(last_response.headers["set-cookie"]).join("\n"), "app_session=cy@acme.com"
    header TouchQue::Guard::TOKEN_HEADER, nil
    header "X-User", "cy@acme.com"
    get "/touchque/enroll/status"
    assert_equal({ "linked" => true, "used" => true, "deviceId" => "dev-1" }, json)
    post "/touchque/passkey/register/options", "{}", "CONTENT_TYPE" => "application/json"
    assert_equal 202, last_response.status
    assert_equal "PASSKEY_ENROLL", api.last_call["body"]["type"]
    post "/touchque/nope"
    assert_equal 404, last_response.status
  end

  def test_relay_rate_limits_and_keeps_offline_off_without_a_first_factor
    api.link("dee@acme.com")
    relay = TouchQue::Rack::Relay.new(client: tq, get_user_id: ->(_) {}, rate_limit: { per_user: 2, per_ip: 100 })
    env = ->(path, body) { Rack::MockRequest.env_for(path, method: "POST", input: JSON.generate(body), "CONTENT_TYPE" => "application/json") }
    assert_equal 403, relay.call(env.call("/offline/challenge", { externalUsername: "dee@acme.com" }))[0]
    assert_equal 202, relay.call(env.call("/login", { externalUsername: "dee@acme.com" }))[0]
    assert_equal 202, relay.call(env.call("/login", { externalUsername: "dee@acme.com" }))[0]
    status, headers, = relay.call(env.call("/login", { externalUsername: "dee@acme.com" }))
    assert_equal 429, status
    assert headers["retry-after"].to_i.positive?
    assert_equal 401, relay.call(env.call("/enroll/start", {}))[0]
  end

  def test_relay_refuses_a_malformed_credential_id
    relay = TouchQue::Rack::Relay.new(client: tq, get_user_id: ->(_) { "dee@acme.com" }, get_login_user: ->(_) {})
    env = Rack::MockRequest.env_for("/passkey/credentials/x", method: "DELETE")
    env["PATH_INFO"] = "/passkey/credentials/%zz"
    status, _, body = relay.call(env)
    assert_equal [400, { "error" => "invalid_credential_id" }], [status, JSON.parse(body.join)]
  end

  def test_rack_relay_loads_without_rails
    script = 'require "touchque"; abort "Rails is loaded" if defined?(Rails); print TouchQue::Rack::Relay.name'
    out, status = Open3.capture2e(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, out
    assert_equal "TouchQue::Rack::Relay", out
  end

  def test_webhook_controller_verifies_and_skips_replays
    WEBHOOK_EVENTS.clear
    payload = { "event" => "APPROVAL_REVOKED", "requestId" => "r1", "timestamp" => Time.now.utc.iso8601(3), "jti" => "jti-77-#{SecureRandom.hex(4)}" }
    sig = TouchQue::Util.hmac_hex("test_secret", TouchQue::Resources::Webhook.canonicalize(JSON.generate(payload)))
    deliver = ->(signature) { post "/webhooks/touchque", JSON.generate(payload), "CONTENT_TYPE" => "application/json", "HTTP_X_SIGNATURE" => signature }
    deliver.call(sig)
    assert_equal 200, last_response.status
    deliver.call(sig)
    assert_equal [200, true], [last_response.status, json["duplicate"]]
    deliver.call("0" * 64)
    assert_equal 401, last_response.status
    assert_equal ["APPROVAL_REVOKED"], WEBHOOK_EVENTS
  end

  def test_hosted_login_signs_in_with_encrypted_cookies
    get "/account"
    assert_equal 302, last_response.status
    assert_equal "/login?returnTo=%2Faccount", URI.parse(last_response.location).request_uri
    get "/login", { returnTo: "/account" }
    assert_equal 302, last_response.status
    authorize = last_response.location
    assert_equal "http://example.org/callback", TouchQue::HostedLogin.params_of(authorize)["redirect_uri"]
    code, state = TENANT.authorize(authorize)
    get "/callback", { code: code, state: state }
    assert_equal [302, "/account"], [last_response.status, URI.parse(last_response.location).path]
    get "/account"
    assert_equal [200, "a@acme.test"], [last_response.status, json["email"]]
    get "/logout"
    assert last_response.location.start_with?("#{FakeTenant::ISSUER}/oidc/logout?client_id=client-123&id_token_hint=")
    get "/account"
    assert_equal 302, last_response.status
    get "/callback", { code: "x", state: "y" }
    assert_equal 400, last_response.status
  end

  def test_hosted_login_callback_checks_iss
    # RFC 9207: the callback passes iss on; a foreign or empty one is refused, the tenant's own is taken.
    ["https://evil", ""].each do |iss|
      get "/login"
      code, state = TENANT.authorize(last_response.location)
      get "/callback", { code: code, state: state, iss: iss }
      assert_equal [400, "issuer_mismatch"], [last_response.status, json["error"]], iss
    end
    get "/login"
    code, state = TENANT.authorize(last_response.location)
    get "/callback", { code: code, state: state, iss: FakeTenant::ISSUER }
    assert_equal 302, last_response.status
    get "/account"
    assert_equal [200, "a@acme.test"], [last_response.status, json["email"]]
  end
end
