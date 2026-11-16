# frozen_string_literal: true

require "test_helper"
require "time"
require "touchque/testing"

# 2FA setup context: where a first-time QR was asked for.
module SetupContextSupport
  SAFARI_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) " \
                  "Version/18.1 Mobile/15E148 Safari/604.1"
  SAFARI_IPAD = "Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 " \
                "Mobile/15E148 Safari/604.1"
  FIREFOX_WINDOWS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
  FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
  CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 " \
               "Safari/537.36"
  EDGE_ANDROID = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 " \
                 "Mobile Safari/537.36 EdgA/131.0.0.0"
  ISO = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\z/
  BERLIN = { "city" => "Berlin", "country" => "Germany", "countryCode" => "DE" }.freeze
  NEW_YORK = { "city" => "New York", "country" => "United States", "countryCode" => "US" }.freeze

  def assert_nil_or_equal(expected, actual, message = nil)
    expected.nil? ? assert_nil(actual, message) : assert_equal(expected, actual, message)
  end
end

# setupContext on the validate answer, read leniently (no network).
class SetupContextParseTest < Minitest::Test
  include SetupContextSupport

  FIXTURE = TestSupport.fixture("setup-context.json")
  CASES = %w[full allNull missing null wrongTypes extraFields].freeze

  # auth.validate_secret over a transport that answers +answer+ (as decoded JSON); the body it sent.
  def validate(answer)
    sent = []
    http = Object.new
    http.define_singleton_method(:post) do |path, body|
      sent << [path, body]
      JSON.parse(JSON.generate(answer))
    end
    [Touchque::Resources::Auth.new(http).validate_secret("S1"), sent]
  end

  def test_the_shared_cases_read_as_expected
    assert_equal CASES, FIXTURE["expected"].keys
    CASES.each do |name|
      expected = FIXTURE["expected"][name]
      assert_nil_or_equal expected, Touchque::SetupContext.parse(FIXTURE[name]["setupContext"]), name

      res, sent = validate(FIXTURE[name])
      assert_equal [["/auth/secret/validate", { "secret" => "S1" }]], sent, name
      assert res.key?("setupContext"), "#{name}: always there, nil when absent"
      assert_nil_or_equal expected, res["setupContext"], name
      # The rest of the answer is the API's, unknown fields too ("nextStep").
      assert_equal FIXTURE[name].except("setupContext"), res.except("setupContext"), name
      next if expected.nil?

      ctx = res["setupContext"]
      assert_instance_of Touchque::SetupContext, ctx, name
      assert_equal %w[ip location device requestedAt farFromPhone], ctx.keys, name
      assert_instance_of Touchque::SetupLocation, ctx.location, name if ctx.location
      assert_instance_of Touchque::SetupDevice, ctx.device, name if ctx.device
      # JSON-ready: it encodes as the plain object it holds.
      assert_equal expected, JSON.parse(JSON.generate(res))["setupContext"], name
    end
  end

  def test_the_readers
    ctx = Touchque::SetupContext.parse(FIXTURE["full"]["setupContext"])
    assert_equal ["203.0.113.7", "2026-11-16T09:30:00.000Z", true], [ctx.ip, ctx.requested_at, ctx.far_from_phone]
    assert_equal %w[Berlin Germany DE], [ctx.location.city, ctx.location.country, ctx.location.country_code]
    assert_equal %w[Safari iOS iPhone], [ctx.device.browser, ctx.device.os, ctx.device.model]

    none = Touchque::SetupContext.parse(FIXTURE["allNull"]["setupContext"])
    assert_equal [nil, nil, nil, nil], [none.ip, none.location, none.device, none.far_from_phone]
    assert_equal "2026-11-16T09:29:00.000Z", none.requested_at

    wrong = Touchque::SetupContext.parse(FIXTURE["wrongTypes"]["setupContext"])
    assert_equal [nil, nil, nil], [wrong.ip, wrong.location, wrong.far_from_phone]
    assert_equal [nil, nil, nil], [wrong.device.browser, wrong.device.os, wrong.device.model]

    extra = Touchque::SetupContext.parse(FIXTURE["extraFields"]["setupContext"])
    assert_equal [nil, "US", false], [extra.location.city, extra.location.country_code, extra.far_from_phone]
    assert_equal %w[city country countryCode], extra.location.keys
    assert_equal %w[browser os model], extra.device.keys
  end

  def test_anything_else_is_nil_never_an_exception
    ["Berlin", 42, true, [], [{ "ip" => "203.0.113.7" }]].each do |raw|
      assert_nil Touchque::SetupContext.parse(raw), raw.inspect
      assert_nil validate({ "valid" => true, "setupContext" => raw })[0]["setupContext"], raw.inspect
    end
    odd = Touchque::SetupContext.parse({ "ip" => ["203.0.113.7"], "location" => [], "device" => "Safari",
                                         "requestedAt" => 1_763_285_400_000, "farFromPhone" => 1 })
    assert_equal({ "ip" => nil, "location" => nil, "device" => nil, "requestedAt" => nil, "farFromPhone" => nil }, odd)
    assert_equal({ "ip" => nil, "location" => nil, "device" => nil, "requestedAt" => nil, "farFromPhone" => nil },
                 Touchque::SetupContext.parse({}))
    assert_equal({ "city" => nil, "country" => "Germany", "countryCode" => nil },
                 Touchque::SetupLocation.parse({ "city" => 5, "country" => "Germany", "countryCode" => { "iso" => "DE" } }))
    assert_equal({ "browser" => "Safari", "os" => nil, "model" => nil }, Touchque::SetupDevice.parse({ "browser" => "Safari" }))
    assert_nil Touchque::SetupLocation.parse("Berlin")
    assert_nil Touchque::SetupDevice.parse(nil)
    # An answer that is not an object comes back as it is.
    assert_equal ["unexpected"], validate(["unexpected"])[0]
  end
end

# Against the shared fake API: the request bodies, the adapters that pass the browser on, and
# what validate answers for it.
class SetupContextApiTest < FakeApiTest
  include SetupContextSupport

  def bodies(path) = api.calls.select { |c| c["path"] == path }.map { |c| c["body"] }
  def browser_of(body) = body.slice("clientIp", "userAgent")

  def test_generate_and_reset_send_the_browser_only_when_given
    tq.auth.generate_secret("a@acme.com", client_ip: "203.0.113.7", user_agent: SAFARI_IPHONE)
    tq.auth.generate_secret("b@acme.com")
    tq.auth.generate_secret("c@acme.com", client_ip: "203.0.113.7")
    tq.auth.reset_secret("a@acme.com", client_ip: "198.51.100.23", user_agent: FIREFOX_WINDOWS)
    tq.auth.reset_secret("b@acme.com")
    tq.auth.reset_secret("c@acme.com", user_agent: "UA")
    assert_equal [{ "externalUsername" => "a@acme.com", "clientIp" => "203.0.113.7", "userAgent" => SAFARI_IPHONE },
                  { "externalUsername" => "b@acme.com" },
                  { "externalUsername" => "c@acme.com", "clientIp" => "203.0.113.7" }], bodies("/auth/generate-secret")
    assert_equal [{ "externalUsername" => "a@acme.com", "clientIp" => "198.51.100.23", "userAgent" => FIREFOX_WINDOWS },
                  { "externalUsername" => "b@acme.com" },
                  { "externalUsername" => "c@acme.com", "userAgent" => "UA" }], bodies("/auth/secret/reset")
  end

  # login.request sends clientIp and userAgent unless nil, as given (no trimming, no length cap):
  # generate_secret and reset_secret follow the same rules.
  def test_the_browser_fields_follow_the_login_requests_rules
    [nil, "", "  203.0.113.7  ", "x" * 5000, "UA\twith a tab", 42].each_with_index do |value, i|
      user = "rules#{i}@acme.com"
      # No phone linked: login.request is refused (404), after Touchque got its body.
      assert_raises(Touchque::APIError) { tq.login.request(user, client_ip: value, user_agent: value) }
      tq.auth.generate_secret(user, client_ip: value, user_agent: value)
      tq.auth.reset_secret(user, client_ip: value, user_agent: value)
      login = browser_of(bodies("/login/request").last)
      assert_equal login, browser_of(bodies("/auth/generate-secret").last), value.inspect
      assert_equal login, browser_of(bodies("/auth/secret/reset").last), value.inspect
      assert_equal(value.nil? ? {} : { "clientIp" => value, "userAgent" => value }, login, value.inspect)
    end
  end

  def test_the_guard_sends_the_browser_with_the_first_time_qr_and_its_renewal
    api.opts(secretTtlMs: 10_000) # inside the 15 s margin: the next poll renews the QR
    first = Touchque::Guard.run(tq, "qr@acme.com", "LOGIN", ip: "203.0.113.7", user_agent: SAFARI_IPHONE)
    assert_equal "enroll", first[:body]["touchque"]["state"]
    assert_equal({ "externalUsername" => "qr@acme.com", "clientIp" => "203.0.113.7", "userAgent" => SAFARI_IPHONE },
                 bodies("/auth/generate-secret").last)
    assert_equal browser_of(bodies("/login/request").last), browser_of(bodies("/auth/generate-secret").last)
    ctx = tq.auth.validate_secret("S")["setupContext"]
    assert_equal ["203.0.113.7", BERLIN, { "browser" => "Safari", "os" => "iOS", "model" => "iPhone" }], [ctx.ip, ctx.location, ctx.device]

    # The poll that renews the QR (generate 409, then reset) names its own browser.
    renewed = Touchque::Guard.run(tq, "qr@acme.com", "LOGIN", ip: "198.51.100.23", user_agent: FIREFOX_WINDOWS, token: first[:body]["token"])
    assert_equal "data:image/png;base64,QR2-qr@acme.com", renewed[:body]["touchque"]["enroll"]["qrCodeDataUrl"]
    assert_equal({ "externalUsername" => "qr@acme.com", "clientIp" => "198.51.100.23", "userAgent" => FIREFOX_WINDOWS },
                 bodies("/auth/secret/reset").last)
    assert_equal browser_of(bodies("/login/request").last), browser_of(bodies("/auth/secret/reset").last)
    ctx = tq.auth.validate_secret("S2")["setupContext"]
    assert_equal ["198.51.100.23", NEW_YORK, "Firefox", "Windows"], [ctx.ip, ctx.location, ctx.device.browser, ctx.device.os]
  end

  def test_without_a_browser_the_guard_sends_none_as_for_the_push
    Touchque::Guard.run(tq, "none@acme.com", "LOGIN")
    assert_equal({}, browser_of(bodies("/login/request").last))
    assert_equal [{ "externalUsername" => "none@acme.com" }], bodies("/auth/generate-secret")
    assert_nil tq.auth.validate_secret("S")["setupContext"]
  end

  def test_start_and_a_qr_already_up_send_the_browser_of_the_request
    step = tq.start("LOGIN", "start@acme.com", ip: "203.0.113.7", user_agent: SAFARI_IPHONE)
    assert_equal "enroll", step["state"]
    assert_equal({ "externalUsername" => "start@acme.com", "clientIp" => "203.0.113.7", "userAgent" => SAFARI_IPHONE },
                 bodies("/auth/generate-secret").last)
    # A QR is up (generate 409, the phone not linked): the reset names this request's browser.
    Touchque::Guard.run(tq, "start@acme.com", "LOGIN", ip: "198.51.100.23", user_agent: CHROME_MAC)
    assert_equal({ "externalUsername" => "start@acme.com", "clientIp" => "198.51.100.23", "userAgent" => CHROME_MAC },
                 bodies("/auth/secret/reset").last)
    # A pre-auth guard that may not show the QR asks for none.
    Touchque::Guard.run(tq, "nobody@acme.com", "LOGIN", ip: "203.0.113.7", user_agent: SAFARI_IPHONE, enroll: false)
    refute_includes bodies("/auth/generate-secret").map { |b| b["externalUsername"] }, "nobody@acme.com"
  end

  def test_the_relay_sends_the_browser_its_login_sends
    user = "relay@acme.com"
    relay = Touchque::RelayHandler.new(tq, get_user_id: ->(_) { user }, get_login_user: ->(_) { user }, rate_limit: false)
    post = ->(path, ip, ua) { relay.handle(method: "POST", path: path, ip: ip, user_agent: ua) }

    assert_equal 200, post.call("/enroll/start", "203.0.113.7", SAFARI_IPHONE).status
    assert_equal({ "externalUsername" => user, "clientIp" => "203.0.113.7", "userAgent" => SAFARI_IPHONE }, bodies("/auth/generate-secret").last)
    # The QR is up: a second /enroll/start resets it with its own browser.
    assert_equal 200, post.call("/enroll/start", "198.51.100.23", FIREFOX_WINDOWS).status
    assert_equal({ "externalUsername" => user, "clientIp" => "198.51.100.23", "userAgent" => FIREFOX_WINDOWS }, bodies("/auth/secret/reset").last)
    # POST /login for the user behind the password step: the push and the QR name the same browser.
    assert_equal 202, post.call("/login", "198.51.100.23", CHROME_MAC).status
    assert_equal({ "clientIp" => "198.51.100.23", "userAgent" => CHROME_MAC }, browser_of(bodies("/login/request").last))
    assert_equal browser_of(bodies("/login/request").last), browser_of(bodies("/auth/secret/reset").last)
    # No address known (""): none sent, as POST /login sends none.
    assert_equal 200, post.call("/enroll/start", "", nil).status
    assert_equal({ "externalUsername" => user }, bodies("/auth/secret/reset").last)
    assert_equal 202, post.call("/login", "", nil).status
    assert_equal({}, browser_of(bodies("/login/request").last))
    assert_equal({}, browser_of(bodies("/auth/secret/reset").last))
    # A linked phone is never replaced from /enroll/start.
    api.link(user)
    resets = bodies("/auth/secret/reset").size
    assert_equal 409, post.call("/enroll/start", "203.0.113.7", SAFARI_IPHONE).status
    assert_equal resets, bodies("/auth/secret/reset").size
  end

  def test_end_to_end_the_phone_sees_where_the_qr_was_asked_for
    before = Time.now
    gen = tq.auth.generate_secret("e2e@acme.com", client_ip: "203.0.113.7", user_agent: SAFARI_IPHONE)
    res = tq.auth.validate_secret(gen["secret"])
    assert_equal({ "secret" => "S" }, api.last_call["body"])
    assert_equal [true, "e2e@acme.com", "Fake workspace"], [res["valid"], res["externalUsername"], res["integration"]["companyName"]]
    ctx = res["setupContext"]
    assert_instance_of Touchque::SetupContext, ctx
    assert_match ISO, ctx.requested_at
    assert_in_delta before.to_f, Time.iso8601(ctx.requested_at).to_f, 10
    assert_equal({ "ip" => "203.0.113.7", "location" => BERLIN, "device" => { "browser" => "Safari", "os" => "iOS", "model" => "iPhone" },
                   "requestedAt" => ctx.requested_at, "farFromPhone" => nil }, ctx)

    # A reset: the new QR carries its own browser (a private address is not shown); the old one is gone.
    tq.auth.reset_secret("e2e@acme.com", client_ip: "10.0.0.8", user_agent: CHROME_MAC)
    ctx = tq.auth.validate_secret("S2")["setupContext"]
    assert_equal [nil, nil, { "browser" => "Chrome", "os" => "macOS", "model" => nil }], [ctx.ip, ctx.location, ctx.device]
    gone = assert_raises(Touchque::APIError) { tq.auth.validate_secret("S") }
    assert_equal [404, "not_found"], [gone.status, gone.reason]
    api.link("e2e@acme.com")
    used = assert_raises(Touchque::APIError) { tq.auth.validate_secret("S2") }
    assert_equal [409, "already_used"], [used.status, used.reason]
  end

  def test_older_qrs_and_servers_answer_no_setup_context
    tq.auth.generate_secret("old@acme.com")
    res = tq.auth.validate_secret("S")
    assert_equal [true, true], [res["valid"], res.key?("setupContext")]
    assert_nil res["setupContext"]
    tq.auth.reset_secret("old@acme.com", client_ip: "203.0.113.7", user_agent: SAFARI_IPHONE)
    api.opts(setupContextNull: true)
    assert_nil tq.auth.validate_secret("S2")["setupContext"]
  end

  # Where FakeTouchque and the shared fake each keep and show a browser.
  BROWSERS = [
    ["203.0.113.7", SAFARI_IPHONE], ["198.51.100.23", FIREFOX_WINDOWS], [" 203.0.113.7:8443 ", EDGE_ANDROID],
    ["[2001:db8::1]:443", SAFARI_IPAD], ["::ffff:198.51.100.23", nil], ["10.0.0.5", CHROME_MAC], ["100.64.1.1", nil],
    ["fe80::1", nil], ["127.0.0.1", nil], ["::1", "curl/8.4.0"], ["not an ip", FIREFOX_LINUX], [nil, "x" * 600],
    ["", "Mozilla/5.0"], [nil, " \tUA with a tab\x01 "], [nil, nil], [42, ["Safari"]],
    # Firefox/ past the 512th character; a tab before Mozilla/ and a control character inside Firefox/.
    [nil, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) #{"x" * 600} Firefox/133.0"],
    [nil, " \tMozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Fire\x01fox/133.0 "]
  ].freeze

  def test_fake_touchque_answers_validate_like_the_shared_fake
    fake = Touchque::Testing::FakeTouchque.new(linked: false)
    without_time = ->(ctx) { ctx&.except("requestedAt") }
    BROWSERS.each_with_index do |(ip, ua), i|
      user = "parity#{i}@acme.com"
      shared = tq.auth.validate_secret(tq.auth.generate_secret(user, client_ip: ip, user_agent: ua)["secret"])
      mine = fake.auth.validate_secret(fake.auth.generate_secret(user, client_ip: ip, user_agent: ua)["secret"])
      assert_equal shared.except("setupContext"), mine.except("setupContext"), [ip, ua].inspect
      assert_nil_or_equal without_time.call(shared["setupContext"]), without_time.call(mine["setupContext"]), [ip, ua].inspect
      assert_match ISO, mine["setupContext"].requested_at if mine["setupContext"]
    end
    # FakeTouchque lists what your app sent (a String, else nil), one QR each.
    assert_equal BROWSERS.each_index.map { |i| "parity#{i}@acme.com" }, fake.setups.map { |s| s["user"] }
    assert_equal BROWSERS.map { |sent| sent.map { |v| v.is_a?(String) ? v : nil } },
                 fake.setups.map { |s| s.values_at("clientIp", "userAgent") }
    # validate makes "setupContext" from it as the API keeps and shows a browser: [ip, browser, os].
    shown = lambda do |i|
      ctx = fake.auth.validate_secret(fake.setups[i]["secret"])["setupContext"]
      ctx && [ctx.ip, ctx.device&.browser, ctx.device&.os]
    end
    assert_equal ["203.0.113.7", "Edge", "Android"], shown.call(2), "trimmed, the port dropped"
    assert_equal ["2001:db8::1", "Safari", "iPadOS"], shown.call(3), "the brackets and the port dropped"
    assert_equal ["198.51.100.23", nil, nil], shown.call(4), "::ffff: dropped"
    assert_equal [nil, "Chrome", "macOS"], shown.call(5), "kept, though the phone does not show it"
    assert_nil shown.call(8), "no loopback address, no User-Agent: none"
    assert_equal [nil, nil, nil], shown.call(9), "no loopback address; curl is no browser"
    assert_equal [nil, nil, nil], shown.call(13), "no control characters, trimmed: kept, no browser"
    assert_nil shown.call(14), "nothing sent"
    assert_nil shown.call(15), "neither a String"
    assert_equal [nil, nil, "Windows"], shown.call(16), "at most 512 characters: Firefox/ is cut off"
    assert_equal [nil, "Firefox", "Linux"], shown.call(17), "no control characters, trimmed"

    # The refusals: no secret, an unknown one, a used one, an expired one.
    refusal = ->(client, secret) { assert_raises(Touchque::APIError) { client.auth.validate_secret(secret) } }
    [nil, "", "nope"].each do |secret|
      a = refusal.call(tq, secret)
      b = refusal.call(fake, secret)
      assert_equal [a.status, a.data], [b.status, b.data], secret.inspect
    end
    last = "parity#{BROWSERS.size - 1}@acme.com" # the shared fake's newest "S"
    api.link(last)
    fake.link(last)
    a = refusal.call(tq, "S")
    b = refusal.call(fake, fake.setups.find { |s| s["user"] == last }["secret"])
    assert_equal [409, "already_used", "This secret has already been used"], [a.status, a.reason, a.message]
    assert_equal [a.status, a.data.except("usedAt")], [b.status, b.data.except("usedAt")]
    assert_match ISO, b.data["usedAt"]
    api.opts(secretTtlMs: -1000)
    fake.secret_ttl_ms = -1000
    tq.auth.generate_secret("late@acme.com", client_ip: "203.0.113.7")
    a = refusal.call(tq, "S")
    b = refusal.call(fake, fake.auth.generate_secret("late@acme.com", client_ip: "203.0.113.7")["secret"])
    assert_equal [410, "expired"], [a.status, a.reason]
    assert_equal [a.status, a.data.except("expiredAt")], [b.status, b.data.except("expiredAt")]
    assert_equal fake.setups.last["expiresAt"], b.data["expiredAt"]
  end
end
