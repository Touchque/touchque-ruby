# frozen_string_literal: true

require "test_helper"

# Shared Signals SETs: the cross-SDK vectors (fixtures/security-event-vectors.json),
# discovery through /.well-known/ssf-configuration, and a poll (RFC 8936).
class SecurityEventsTest < Minitest::Test
  V = TestSupport.fixture("security-event-vectors.json")

  def verifier
    TouchQue::SecurityEventVerifier.new(issuer: V["issuer"], audience: V["audience"], jwks: V["jwks"])
  end

  # A transmitter on 127.0.0.1: its ssf-configuration, its JWKS, and a poll endpoint that
  # records what it was sent and answers the first valid vector.
  def with_transmitter
    server = TCPServer.new("127.0.0.1", 0)
    base = "http://127.0.0.1:#{server.addr[1]}"
    seen = { "paths" => [] }
    thread = Thread.new do
      loop do
        conn = server.accept
        path = conn.gets.to_s.split[1]
        headers = {}
        while (line = conn.gets) && line != "\r\n"
          name, value = line.split(":", 2)
          headers[name.strip.downcase] = value.to_s.strip
        end
        body = conn.read(headers["content-length"].to_i)
        seen["paths"] << path
        out = case path
              when "/.well-known/ssf-configuration" then { "issuer" => base, "jwks_uri" => "#{base}/jwks" }
              when "/jwks" then V["jwks"]
              else
                seen["poll"] = { "auth" => headers["authorization"], "accept" => headers["accept"], "body" => JSON.parse(body.to_s.empty? ? "{}" : body) }
                { "sets" => { V["valid"][0]["expect"]["jti"] => V["valid"][0]["token"] }, "moreAvailable" => false }
              end
        text = JSON.generate(out)
        conn.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{text.bytesize}\r\nConnection: close\r\n\r\n#{text}")
        conn.close
      end
    end
    yield base, seen
  ensure
    thread&.kill
    server&.close
  end

  def test_reads_every_valid_vector
    V["valid"].each do |v|
      x = v["expect"]
      want = { "jti" => x["jti"], "issuer" => x["issuer"], "audience" => x["audience"], "issued_at" => x["issuedAt"], "txn" => x["txn"],
               "subject" => x["subject"], "type" => x["type"], "name" => x["name"], "claims" => x["claims"] }
      assert_equal want, verifier.verify(v["token"]), v["name"]
    end
  end

  def test_refuses_every_invalid_vector
    V["invalid"].each do |v|
      e = assert_raises(TouchQue::SecurityEventError, v["name"]) { verifier.verify(v["token"]) }
      assert_equal v["error"], e.error, v["name"]
    end
  end

  def test_short_names
    assert TouchQue::SecurityEvents::TYPES["session-revoked"].end_with?("/caep/event-type/session-revoked")
  end

  def test_discovers_the_jwks_and_checks_the_issuer_the_set_names
    with_transmitter do |base, seen|
      e = assert_raises(TouchQue::SecurityEventError) { TouchQue::SecurityEventVerifier.new(issuer: base, audience: V["audience"]).verify(V["valid"][0]["token"]) }
      # The vectors' issuer is not this one: the signature verifies, the issuer does not.
      assert_equal "invalid_issuer", e.error
      assert_equal ["/.well-known/ssf-configuration", "/jwks"], seen["paths"]
    end
  end

  def test_poll_acknowledges_and_returns_the_waiting_sets
    with_transmitter do |base, seen|
      out = TouchQue::SecurityEvents.poll(url: "#{base}/ssf/poll/s1", token: "tqssf_x", ack: ["a"], max_events: 5)
      assert_equal({ "sets" => { V["valid"][0]["expect"]["jti"] => V["valid"][0]["token"] }, "more_available" => false }, out)
      assert_equal({ "auth" => "Bearer tqssf_x", "accept" => "application/json", "body" => { "ack" => ["a"], "maxEvents" => 5 } }, seen["poll"])
      assert_raises(TouchQue::ConfigError) { TouchQue::SecurityEvents.poll(url: "http://example.com/poll", token: "tqssf_x") }
      assert_raises(TouchQue::ConfigError) { TouchQue::SecurityEvents.poll(url: "#{base}/ssf/poll/s1", token: "") }
    end
  end
end
