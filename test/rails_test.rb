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
TRANSFERS_RAN = []

class TouchqueTestApp < Rails::Application
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
  include Touchque::Rails::Guard

  require_touchque "SEND_MONEY", only: :create, user: -> { request.headers["X-User"] }, details: -> { { "Amount" => params[:amount].to_s } }

  def create
    TRANSFERS_RAN << touchque_approval["requestId"]
    render json: { via: touchque_approval["confirmedVia"] }
  end
end

# require_touchque with error_body: the test sets the shape; the proc runs in the controller.
class ShapedTransfersController < ActionController::Base
  include Touchque::Rails::Guard

  class << self
    attr_accessor :shape, :refusals
  end

  require_touchque "SEND_MONEY", only: :create, user: -> { request.headers["X-User"] },
                                 error_body: lambda { |refusal|
                                   self.class.refusals << refusal
                                   self.class.shape.call(refusal)
                                 }

  def create
    render json: { ran: true }
  end
end

class WebhooksController < ActionController::Base
  include Touchque::Rails::Webhook

  verify_touchque_webhook

  def create
    WEBHOOK_EVENTS << touchque_webhook["event"]
    head :ok
  end
end

class AccountController < ActionController::Base
  include Touchque::Rails::HostedLogin

  before_action :require_touchque_sign_in

  def show
    render json: { email: touchque_session["user"]["email"] }
  end
end

TouchqueTestApp.initialize!
Touchque.hosted_login = Touchque::HostedLogin.new(domain: FakeTenant::ISSUER, client_id: FakeTenant::CLIENT, client_secret: "s3cret", transport: TENANT.transport)
TouchqueTestApp.routes.draw do
  post "/transfer" => "transfers#create"
  post "/shaped" => "shaped_transfers#create"
  post "/webhooks/touchque" => "webhooks#create"
  get "/account" => "account#show"
  Touchque::Rails.login_routes(self)
  mount Touchque::Rack::Relay.new(
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
    TouchqueTestApp
  end

  def json
    JSON.parse(last_response.body)
  end

  def test_railtie_configures_the_client
    assert_equal "test_secret", Touchque.client.api_secret
    assert_equal FakeTenant::ISSUER, Touchque.login_options[:domain]
    assert Touchque.login_secret.length >= 32
  end

  def test_require_touchque_runs_the_action_once_after_the_phone
    api.link("ada@acme.com")
    header "X-User", "ada@acme.com"
    post "/transfer", { amount: "250 EUR" }
    assert_equal [202, "waiting", "47"], [last_response.status, json["touchque"]["state"], json["touchque"]["number"]]
    assert_equal "no-store", last_response.headers["Cache-Control"]
    assert_equal [{ "label" => "Amount", "value" => "250 EUR" }], api.last_call["body"]["details"]
    token = json["token"]
    header Touchque::Guard::TOKEN_HEADER, token
    post "/transfer", { amount: "250 EUR" }
    assert_equal 202, last_response.status
    api.approve
    post "/transfer", { amount: "9999 EUR" }
    assert_equal 202, last_response.status
    post "/transfer", { amount: "250 EUR" }
    assert_equal [200, "DEVICE"], [last_response.status, json["via"]]
    header "X-User", nil
    header Touchque::Guard::TOKEN_HEADER, nil
    post "/transfer", { amount: "1" }
    assert_equal 401, last_response.status
    api.link("bo@acme.com")
    api.opts(frozen: true)
    header "X-User", "bo@acme.com"
    post "/transfer", { amount: "1" }
    assert_equal [423, "900"], [last_response.status, last_response.headers["Retry-After"]]
  end

  MISCONFIGURED = { "touchque" => { "state" => "blocked", "reason" => "misconfigured" },
                    "error" => { "code" => "misconfigured", "message" => "Two-factor approval is not configured correctly." } }.freeze
  UNAUTHENTICATED = { "touchque" => { "state" => "blocked", "reason" => "unauthenticated" },
                      "error" => { "code" => "unauthenticated", "message" => "Sign in first." } }.freeze

  # Runs the block like a deploy without TQ_API_KEY / TQ_API_SECRET; returns what Touchque.logger got.
  def without_keys
    saved = ENV.to_h.slice("TQ_API_KEY", "TQ_API_SECRET")
    ENV.delete("TQ_API_KEY")
    ENV.delete("TQ_API_SECRET")
    Touchque.configure(base_url: api.base_url)
    Touchque::Guard.unconfigured_logged = false
    lines = []
    Touchque.logger = Object.new.tap { |l| l.define_singleton_method(:error) { |m| lines << m } }
    yield
    lines
  ensure
    Touchque.logger = nil
    saved.each { |name, value| ENV[name] = value }
    Touchque.configure(api_key: "tq_test_key", api_secret: "test_secret", base_url: api.base_url)
  end

  def shaped(shape)
    ShapedTransfersController.shape = shape
    ShapedTransfersController.refusals = []
  end

  def test_missing_keys_answer_500_misconfigured_and_the_action_never_runs
    TRANSFERS_RAN.clear
    lines = without_keys do
      header "X-User", "ada@acme.com"
      2.times do
        post "/transfer", { amount: "250 EUR" }
        assert_equal [500, MISCONFIGURED], [last_response.status, json]
        assert_equal "no-store", last_response.headers["Cache-Control"]
        assert_match %r{\Aapplication/json}, last_response.headers["Content-Type"]
      end
      header "X-User", nil
      post "/transfer", { amount: "250 EUR" }
      assert_equal [401, UNAUTHENTICATED], [last_response.status, json]
    end
    assert_empty TRANSFERS_RAN, "the protected action must never run"
    assert_equal ["[Touchque] TQ_API_KEY and TQ_API_SECRET are not set: routes guarded by Touchque answer 500 misconfigured."], lines
  end

  def test_missing_keys_go_through_error_body
    shaped(->(r) { { error: r[:code], status: r[:status] } })
    without_keys do
      header "X-User", "ada@acme.com"
      post "/shaped"
      assert_equal [500, { "error" => "misconfigured", "status" => 500, "touchque" => MISCONFIGURED["touchque"] }], [last_response.status, json]
    end
  end

  def test_error_body_shapes_refusals_and_keeps_the_step
    shaped(->(r) { { message: r[:message], code: r[:code] } })
    api.link("shape@acme.com")
    header "X-User", "shape@acme.com"
    post "/shaped"
    assert_equal [202, "waiting"], [last_response.status, json["touchque"]["state"]]
    assert_empty ShapedTransfersController.refusals, "never called for a 202 step"
    header Touchque::Guard::TOKEN_HEADER, json["token"]
    api.reject
    post "/shaped"
    assert_equal 403, last_response.status
    assert_equal %w[message code touchque], json.keys, "no token is added"
    assert_equal ["The approval was rejected.", "rejected", "rejected"], [json["message"], json["code"], json["touchque"]["state"]]
    assert_equal "no-store", last_response.headers["Cache-Control"]
    assert_equal [403, "rejected"], ShapedTransfersController.refusals.last.values_at(:status, :code)

    # Status and headers stay: 423 with Retry-After.
    header Touchque::Guard::TOKEN_HEADER, nil
    api.opts(frozen: true)
    post "/shaped"
    assert_equal [423, "900"], [last_response.status, last_response.headers["Retry-After"]]
    assert_equal ["Too many rejected approvals. Try again later.", "frozen", 900], [json["message"], json["code"], json["touchque"]["retryAfter"]]
  end

  def test_error_body_hash_gets_the_step_and_the_sdks_key_wins
    shaped(->(_) { { error: "login_required", touchque: "mine" } })
    post "/shaped"
    assert_equal [401, { "error" => "login_required", "touchque" => UNAUTHENTICATED["touchque"] }], [last_response.status, json]
  end

  def test_error_body_non_hash_is_sent_as_it_is
    ["Sign in first", 42, %w[a b], [], nil].each do |value|
      shaped(->(_) { value })
      post "/shaped"
      assert_equal [401, JSON.generate(value)], [last_response.status, last_response.body]
      assert_match %r{\Aapplication/json}, last_response.headers["Content-Type"]
    end
  end

  def test_a_raising_error_body_is_logged_and_the_default_body_sent
    lines = []
    Touchque.logger = Object.new.tap { |l| l.define_singleton_method(:error) { |m| lines << m } }
    shaped(->(_) { raise "template missing" })
    post "/shaped"
    assert_equal [401, UNAUTHENTICATED], [last_response.status, json]
    assert_equal ["[Touchque] errorBody failed: template missing"], lines
  ensure
    Touchque.logger = nil
  end

  def test_answers_of_400_and_above_carry_the_state_headers
    # Even when error_body sends no "touchque" key, the headers carry the step.
    shaped(->(_) { "Sign in first" })
    post "/shaped"
    assert_equal [401, "blocked", "unauthenticated"], [last_response.status, last_response.headers["X-Touchque-State"], last_response.headers["X-Touchque-Reason"]]

    api.link("headers@acme.com")
    header "X-User", "headers@acme.com"
    post "/transfer", { amount: "1" }
    assert_equal 202, last_response.status
    assert_nil last_response.headers["X-Touchque-State"], "not on a 202 step"
    api.opts(frozen: true)
    post "/transfer", { amount: "1" }
    assert_equal [423, "frozen", "900"], [last_response.status, last_response.headers["X-Touchque-State"], last_response.headers["Retry-After"]]
    assert_nil last_response.headers["X-Touchque-Reason"], "no reason, no header"
  end

  # The relay's POST /login for +user+ (behind the password step, so it offers the linking QR).
  def login_relay(user, per_user)
    Touchque::Rack::Relay.new(client: tq, get_user_id: ->(_) { user }, get_login_user: ->(_) { user }, rate_limit: { per_user: per_user, per_ip: 100 })
  end

  def relay_login(relay, token = nil)
    env = Rack::MockRequest.env_for("/login", method: "POST", input: "{}", "CONTENT_TYPE" => "application/json")
    env["HTTP_X_TOUCHQUE_TOKEN"] = token if token
    status, headers, body = relay.call(env)
    [status, headers, JSON.parse(body.join)]
  end

  def pushes_for(user) = api.calls.count { |c| c["path"] == "/login/request" && c["body"]["externalUsername"] == user }

  def test_relay_charges_enroll_token_replays_after_linking
    relay = login_relay("replayed@acme.com", 5)
    _, _, first = relay_login(relay)
    assert_equal "enroll", first["touchque"]["state"]
    api.link("replayed@acme.com")
    before = pushes_for("replayed@acme.com")
    # While the QR is up the old token is a poll; each start it makes is charged like a new attempt.
    replies = Array.new(12) { relay_login(relay, first["token"]) }
    assert_equal [202] * 4 + [429] * 8, replies.map(&:first)
    assert_equal "RATE_LIMITED", replies.last[2]["error"]
    assert replies.last[1]["retry-after"].to_i.positive?
    assert_equal 4, pushes_for("replayed@acme.com") - before, "the first attempt and 4 replays fill the budget of 5"
  end

  def test_relay_never_charges_polls_that_keep_the_qr
    relay = login_relay("keeper@acme.com", 2)
    token = relay_login(relay)[2]["token"]
    10.times do |i|
      status, _, body = relay_login(relay, token)
      assert_equal [202, nil], [status, body["touchque"]["enroll"]], "poll #{i}"
    end
    # The budget of 2 is still 1 used: the poll that pushes once the phone is linked passes.
    api.link("keeper@acme.com")
    status, _, body = relay_login(relay, token)
    assert_equal [202, "waiting"], [status, body["touchque"]["state"]]
  end

  def test_relay_charges_an_enroll_qr_renewal_at_the_margin
    api.opts(secretTtlMs: 10_000) # inside the 15 s margin from the start
    relay = login_relay("renewer@acme.com", 2)
    first = relay_login(relay)[2]
    status, _, renewed = relay_login(relay, first["token"])
    assert_equal [202, "data:image/png;base64,QR2-renewer@acme.com"], [status, renewed["touchque"]["enroll"]["qrCodeDataUrl"]]
    status, _, again = relay_login(relay, renewed["token"])
    assert_equal [429, "RATE_LIMITED"], [status, again["error"]]
  end

  def test_relay_guard_answers_carry_the_state_headers
    api.link("refused@acme.com")
    api.opts(blocked: "geo_policy")
    status, headers, = relay_login(login_relay("refused@acme.com", 5))
    assert_equal [403, "blocked", "geo_policy", "no-store"], [status, headers["x-touchque-state"], headers["x-touchque-reason"], headers["cache-control"]]
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
    header Touchque::Guard::TOKEN_HEADER, token
    post "/touchque/login", "{}", "CONTENT_TYPE" => "application/json"
    assert_equal [200, "success"], [last_response.status, json["status"]]
    assert_includes Array(last_response.headers["set-cookie"]).join("\n"), "app_session=cy@acme.com"
    header Touchque::Guard::TOKEN_HEADER, nil
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
    relay = Touchque::Rack::Relay.new(client: tq, get_user_id: ->(_) {}, rate_limit: { per_user: 2, per_ip: 100 })
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
    relay = Touchque::Rack::Relay.new(client: tq, get_user_id: ->(_) { "dee@acme.com" }, get_login_user: ->(_) {})
    env = Rack::MockRequest.env_for("/passkey/credentials/x", method: "DELETE")
    env["PATH_INFO"] = "/passkey/credentials/%zz"
    status, _, body = relay.call(env)
    assert_equal [400, { "error" => "invalid_credential_id" }], [status, JSON.parse(body.join)]
  end

  def test_rack_relay_loads_without_rails
    script = 'require "touchque"; abort "Rails is loaded" if defined?(Rails); print Touchque::Rack::Relay.name'
    out, status = Open3.capture2e(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), "-e", script)
    assert status.success?, out
    assert_equal "Touchque::Rack::Relay", out
  end

  def test_webhook_controller_verifies_and_skips_replays
    WEBHOOK_EVENTS.clear
    payload = { "event" => "APPROVAL_REVOKED", "requestId" => "r1", "timestamp" => Time.now.utc.iso8601(3), "jti" => "jti-77-#{SecureRandom.hex(4)}" }
    sig = Touchque::Util.hmac_hex("test_secret", Touchque::Resources::Webhook.canonicalize(JSON.generate(payload)))
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
    assert_equal "http://example.org/callback", Touchque::HostedLogin.params_of(authorize)["redirect_uri"]
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
