# frozen_string_literal: true

require "test_helper"

# Cross App Access (ID-JAG) and A2A agent card signatures against the fake API: an app
# trades a member's ID token for an ID-JAG at the identity provider and redeems it; an
# authorization server checks one (issuer, audience, client, expiry, typ, once); a card
# signed in RFC 8785 form by the fake (JavaScript) verifies here with keys from its own
# host and fails when changed or pointed elsewhere.
class CrossAppAccessTest < FakeApiTest
  def verifier
    Touchque::IdJagVerifier.new(issuer: "#{api.base_url}/idp", audience: "https://rs.example")
  end

  def reason
    yield
    "accepted"
  rescue Touchque::IdJagError => e
    e.message
  end

  def test_request_redeem_and_verify
    idp = "#{api.base_url}/idp"
    jag = Touchque::CrossAppAccess.request_id_jag(issuer: idp, client_id: "tqapp_test", client_secret: "tqs_test", id_token: "idtoken:ada",
                                                  audience: "https://rs.example", resource: "https://rs.example/files")
    assert_equal "files:read", jag["scope"]
    err = assert_raises(Touchque::IdJagError) do
      Touchque::CrossAppAccess.request_id_jag(issuer: idp, client_id: "tqapp_test", client_secret: "wrong", id_token: "idtoken:ada", audience: "https://rs.example")
    end
    assert_equal ["invalid_client", 401], [err.error, err.status]
    v = verifier
    claims = v.verify(jag["assertion"], client_id: "acme-at-rs")
    assert_equal ["ada", "acme-at-rs", ["files:read"], "https://rs.example/files"], claims.values_at("sub", "client_id", "scopes", "resource")
    assert_equal "already used", reason { v.verify(jag["assertion"], client_id: "acme-at-rs") }
    tokens = Touchque::CrossAppAccess.redeem_id_jag(token_endpoint: "#{api.base_url}/rs/token", client_id: "acme-at-rs", assertion: jag["assertion"])
    assert_equal "Bearer", tokens["token_type"]
  end

  def test_refusals
    v = verifier
    mint = ->(claims = {}, typ = nil) { api.post("/__test/id-jag", { claims: claims }.merge(typ ? { typ: typ } : {}))["assertion"] }
    assert_equal "issued to another client", reason { v.verify(mint.call, client_id: "someone-else") }
    assert_equal "not for this authorization server", reason { v.verify(mint.call({ aud: "https://evil.example" }), client_id: "acme-at-rs") }
    assert_equal "not for this authorization server", reason { v.verify(mint.call({ aud: ["https://rs.example", "https://b.example"] }), client_id: "acme-at-rs") }
    assert_equal "another issuer", reason { v.verify(mint.call({ iss: "https://evil.example" }), client_id: "acme-at-rs") }
    assert_equal "not an ID-JAG (typ oauth-id-jag+jwt)", reason { v.verify(mint.call({}, "at+jwt"), client_id: "acme-at-rs") }
    assert_equal "expired", reason { v.verify(mint.call({ exp: Time.now.to_i - 600 }), client_id: "acme-at-rs") }
    h, b, s = mint.call.split(".")
    forged = Touchque::Util.b64url(JSON.generate(JSON.parse(Touchque::Util.b64url_decode(b)).merge("sub" => "mallory")))
    assert_equal "signature does not verify", reason { v.verify("#{h}.#{forged}.#{s}", client_id: "acme-at-rs") }
  end

  def code
    yield
    "verified"
  rescue Touchque::AgentCardError => e
    e.error
  end

  def test_agent_cards
    url = "#{api.base_url}/.well-known/agent-card.json"
    card = Net::HTTP.get(URI(url)).force_encoding("UTF-8")
    assert_equal({ "kid" => "a2a-1", "alg" => "ES256", "key_source" => "jku" }, Touchque::AgentCard.verify(card, card_url: url))
    tampered = Net::HTTP.get(URI("#{url}?tamper=1")).force_encoding("UTF-8")
    assert_equal "invalid_signature", code { Touchque::AgentCard.verify(tampered, card_url: url) }
    assert_equal "untrusted_key", code { Touchque::AgentCard.verify(card, card_url: "https://agent.example/.well-known/agent-card.json") }
    assert_equal "unsigned", code { Touchque::AgentCard.verify('{"name":"x"}') }

    keys = Touchque::AgentKeys.generate("EdDSA")
    signed = Touchque::AgentCard.sign('{"name":"Mine","url":"https://mine.example/a2a","skills":[]}', keys["privateJwk"], kid: "k1")
    jwk = keys["publicJwk"].merge("kid" => "k1")
    assert_equal({ "kid" => "k1", "alg" => "EdDSA", "key_source" => "keys" }, Touchque::AgentCard.verify(signed, keys: [jwk]))
    assert_equal "invalid_signature", code { Touchque::AgentCard.verify(signed.sub("mine.example", "evil.example"), keys: [jwk]) }

    value = JSON.parse('{"€":"Euro","\r":"CR","😀":"smile","1":"one","a":[1e21,1e-7,0.5,-0,"tab\there",1e-5,100.0]}')
    assert_equal '{"\r":"CR","1":"one","a":[1e+21,1e-7,0.5,0,"tab\there",0.00001,100],"€":"Euro","😀":"smile"}', Touchque::AgentCard.canonical_json(value)
  end
end
