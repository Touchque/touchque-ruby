# frozen_string_literal: true

require "test_helper"

# Touchque Actions and AI agents: management calls send what the shared vectors say, and
# Touchque::Agent / OrgAgent sign in with their own keys against the fake API, which
# checks the private_key_jwt assertions and DPoP proofs like the real API.
class AgentsTest < FakeApiTest
  def vectors
    @vectors ||= TestSupport.fixture("agent-vectors.json")
  end

  def agent(id, key, kid: nil)
    Touchque::Agent.new(agent_id: id, private_key: key, kid: kid, base_url: api.base_url)
  end

  def create(name, public_key, types = ["LOGIN"])
    tq.agents.create(name, types, public_key: public_key)
  end

  def query_of(url)
    url.include?("?") ? URI.decode_www_form(url.split("?", 2)[1]).to_h : {}
  end

  def test_actions_api_vectors
    a = tq.actions
    TestSupport.fixture("actions-api-vectors.json")["calls"].each do |v|
      x = v["args"]
      result = case v["name"]
               when "deploy" then a.deploy(x["slug"], trigger: x["trigger"], code: x["code"], secrets: x["secrets"], name: x["name"])
               when "deployTemplate" then a.deploy(x["slug"], trigger: x["trigger"], template: x["template"], on_failure: x["onFailure"])
               when "deployLoosening" then a.deploy(x["slug"], trigger: x["trigger"], code: x["code"], capabilities: x["capabilities"], allowed_hosts: x["allowedHosts"])
               when "list" then a.list
               when "get" then a.get(x["slug"])
               when "version" then a.version(x["slug"], x["number"])
               when "update" then a.update(x["slug"], enabled: x["enabled"])
               when "rollback" then a.rollback(x["slug"], version: x["version"])
               when "rollbackPrevious" then a.rollback(x["slug"])
               when "test" then a.test(trigger: x["trigger"], code: x["code"], event_id: x["eventId"])
               when "testDeployed" then a.test(slug: x["slug"], event: x["event"])
               when "dryRun" then a.dry_run(trigger: x["trigger"], code: x["code"], replaces: x["replaces"], limit: x["limit"])
               when "events" then a.events(trigger: x["trigger"], limit: x["limit"])
               when "logs" then a.logs(x["slug"], limit: x["limit"])
               when "metrics" then a.metrics(x["slug"], window: x["window"])
               when "triggers" then a.triggers
               when "templates" then a.templates
               when "renderTemplate" then a.render_template(x["id"], x["trigger"], x["params"])
               when "setSecret" then a.secrets.set(x["name"], x["value"])
               when "listSecrets" then a.secrets.list
               when "deleteSecret" then a.secrets.delete(x["name"])
               when "delete" then a.delete(x["slug"])
               else flunk "no mapping for #{v["name"]}"
               end
      last = api.last_call
      want = v["request"]
      assert_equal [want["method"], want["path"]], [last["method"], last["path"]], v["name"]
      assert_equal want["query"] || {}, query_of(last["url"]), v["name"]
      assert_equal want["body"] || {}, last["body"], v["name"] unless %w[GET DELETE].include?(want["method"])
      (v["expect"] || {}).each { |path, value| assert_equal value, result.dig(*path.split(".")), "#{v["name"]} #{path}" }
    end
  end

  def test_loosening_version_waits_for_the_phone_and_bad_input_never_leaves
    res = tq.actions.deploy("silent-office", trigger: "risk.check", code: "exports.onExecute = (e, api) => api.allowSilent(\"office\");", capabilities: ["allow_silent"])
    assert_equal [false, true], [res["deployed"], res.dig("approval", "required")]
    api.approve_version("silent-office", 1)
    assert_equal 1, tq.actions.get("silent-office").dig("action", "activeVersion")
    api.reset
    assert_raises(Touchque::ConfigError) { tq.actions.deploy("Bad Slug", trigger: "login.request", code: "x") }
    assert_raises(Touchque::ConfigError) { tq.actions.deploy("no-code", trigger: "login.request") }
    assert_raises(Touchque::ConfigError) { tq.actions.secrets.set("lowercase", "v") }
    assert_raises(Touchque::ConfigError) { tq.actions.render_template("Bad-Id", "login.request") }
    assert_empty api.calls
  end

  def test_generate_keys
    ec = Touchque::AgentKeys.generate
    assert_equal ["ES256", Touchque::AgentKeys.thumbprint(ec["publicJwk"])], [ec["publicJwk"]["alg"], ec["publicJwk"]["kid"]]
    refute ec["publicJwk"].key?("d")
    assert_equal "Ed25519", Touchque::AgentKeys.generate("EdDSA")["publicJwk"]["crv"]
    assert_raises(Touchque::ConfigError) { Touchque::AgentKeys.generate("RS256") }
  end

  def test_management_call_vectors
    k1 = Touchque::AgentKeys.generate
    k2 = Touchque::AgentKeys.generate("EdDSA")
    id = ""
    ag = tq.agents
    vectors["calls"].each do |v|
      x = v["args"]
      case v["name"]
      when "create" then id = ag.create(x["name"], x["allowedTypes"], public_key: k1["publicJwk"], owner_email: x["ownerEmail"], platform: x["platform"], review_in_days: x["reviewInDays"])["id"]
      when "list" then ag.list(status: x["status"])
      when "get" then ag.get(id)
      when "update" then ag.update(id, review_in_days: x["reviewInDays"], description: x["description"])
      when "addKey" then ag.add_key(id, k2["publicJwk"])
      when "removeKey" then ag.remove_key(id, k2["publicJwk"]["kid"])
      when "suspend" then ag.suspend(id, reason: x["reason"])
      when "resume" then ag.resume(id)
      when "setPolicy" then ag.set_policy(id, x["policy"])
      when "getWorkspacePolicy" then ag.workspace_policy
      when "listEvents" then ag.list_events(after: x["after"], limit: x["limit"])
      when "setWorkspacePolicy" then ag.set_workspace_policy(x["policy"])
      when "listBlocks" then ag.list_blocks(id)
      when "killSwitch" then ag.set_kill_switch(x["engaged"], reason: x["reason"])
      when "killSwitchOff" then ag.set_kill_switch(x["engaged"])
      when "revoke" then ag.revoke(id)
      else flunk v["name"]
      end
      call = api.last_call
      want = JSON.parse(JSON.generate(v).gsub('"{publicKey}"', JSON.generate(k1["publicJwk"])).gsub('"{publicKey2}"', JSON.generate(k2["publicJwk"]))
                                         .gsub("{id}", id).gsub("{kid}", Touchque::Util.seg(k2["publicJwk"]["kid"])))
      assert_equal [want["method"], want["path"]], [call["method"], call["path"]], v["name"]
      assert_equal "#{want["path"]}?#{want["query"]}", call["url"] if want["query"]
      assert_equal want["body"], call["body"], v["name"] if want["body"]
    end
    assert_raises(Touchque::ConfigError) { create("x", k1["privateJwk"]) }
  end

  def test_workspace_policy_under_both_names
    policy = { "amountPerRequest" => { "TRY" => "5000.00" } }
    assert_equal policy, tq.agents.set_workspace_policy(policy)
    assert_equal policy, tq.agents.get_workspace_policy
    assert_equal %w[GET /agents/workspace-policy], [api.last_call["method"], api.last_call["path"]]
    assert_equal policy, tq.agents.workspace_policy
  end

  def test_agent_signs_in_with_its_own_key
    %w[ES256 EdDSA].each do |alg|
      keys = Touchque::AgentKeys.generate(alg)
      created = create("agent #{alg}", keys["publicJwk"])
      [keys["privateJwk"], JSON.generate(keys["privateJwk"])].each do |key|
        me = agent(created["id"], key).me
        assert_equal [created["id"], "agent:read approvals:request approvals:read vault:read"], [me["agent"]["id"], me["scope"]]
      end
    end
    ec = OpenSSL::PKey::EC.generate("prime256v1")
    point = ec.public_key.to_octet_string(:uncompressed)
    pub = { "kty" => "EC", "crv" => "P-256", "x" => Touchque::Util.b64url(point[1, 32]), "y" => Touchque::Util.b64url(point[33, 32]) }
    pem = create("pem", pub)
    assert_equal pem["id"], agent(pem["id"], ec.to_pem).me["agent"]["id"]
  end

  def test_token_is_reused_and_refusals_carry_the_reason
    keys = Touchque::AgentKeys.generate
    created = create("refused", keys["publicJwk"])
    bot = agent(created["id"], keys["privateJwk"])
    bot.me
    bot.me
    assert_equal 1, paths.count("/agents/token")
    tq.agents.suspend(created["id"], reason: "looping")
    e = assert_raises(Touchque::APIError) { bot.me }
    assert_equal [403, "agent_blocked", "suspended"], [e.status, e.code, e.reason]
    e = assert_raises(Touchque::APIError) { agent(created["id"], keys["privateJwk"]).me }
    assert_equal %w[unauthorized_client suspended], [e.code, e.reason]
    tq.agents.resume(created["id"])
    e = assert_raises(Touchque::APIError) { agent(created["id"], Touchque::AgentKeys.generate["privateJwk"], kid: keys["publicJwk"]["kid"]).me }
    assert_equal [401, "invalid_client"], [e.status, e.code]
    tq.agents.set_kill_switch(true, reason: "incident")
    assert_equal "workspace_paused", assert_raises(Touchque::APIError) { bot.me }.reason
    tq.agents.set_kill_switch(false)
    assert_equal created["id"], bot.me["agent"]["id"]
  end

  def test_configuration_errors
    key = Touchque::AgentKeys.generate["privateJwk"]
    assert_raises(Touchque::ConfigError) { agent("nope", key) }
    assert_raises(Touchque::ConfigError) { agent("agt_abcdefghijkmnpqrstuv", "not a key") }
    assert_raises(Touchque::ConfigError) { Touchque::Agent.new(agent_id: "agt_abcdefghijkmnpqrstuv", private_key: key, base_url: "http://api.example.com") }
    assert_raises(Touchque::ConfigError) { agent("agt_abcdefghijkmnpqrstuv", Touchque::AgentKeys.generate["publicJwk"]) }
  end

  def test_token_vault
    keys = Touchque::AgentKeys.generate
    created = create("calendar", keys["publicJwk"])
    bot = agent(created["id"], keys["privateJwk"])
    conn = tq.agents.vault.put_connection("google", provider: "google", client_id: "acme.apps.googleusercontent.com", client_secret: "g-secret", agent_ids: [created["id"]])
    assert conn["hasClientSecret"]
    tq.agents.vault.deposit("google", "jane@example.com", access_token: "ya29.jane", refresh_token: "1//jane", expires_in: 3599, scope: "calendar.readonly")
    refute_includes JSON.generate(tq.agents.vault.list_accounts("jane@example.com")), "ya29"
    assert_equal({ "access_token" => "ya29.jane", "token_type" => "Bearer", "expires_in" => 3599, "scope" => "calendar.readonly", "connection" => "google" },
                 bot.get_connection_token("jane@example.com", "google"))
    assert_equal "not_connected", assert_raises(Touchque::APIError) { bot.get_connection_token("john@example.com", "google") }.code
    tq.agents.vault.remove_account("google", "jane@example.com")
    assert_equal({ "removed" => true, "tokensDeleted" => 0 }, tq.agents.vault.remove_connection("google"))
  end

  def test_ask_wait_verify_redeem
    user = "agent-approvals@example.com"
    api.link(user)
    tq.action_types.define("PAY_INVOICE", critical: false)
    keys = Touchque::AgentKeys.generate
    created = create("Invoice bot", keys["publicJwk"], ["PAY_INVOICE"])
    bot = agent(created["id"], keys["privateJwk"])
    payment = vectors["approvalToken"]["claims"]["authorization_details"][0]
    ask = bot.request_approval(user, "PAY_INVOICE", [payment], reason: "October rent")
    assert_equal %w[pending 47], [ask["status"], ask["challengeCode"]]
    api.approve(ask["approvalId"])
    token = bot.wait_for_approval(ask["approvalId"], timeout: 10, interval: 0.5)["approvalToken"]
    shown = nil
    required = bot.require_approval(user, "PAY_INVOICE", [payment], timeout: 10) do |s|
      shown = s["challengeCode"]
      api.approve(s["approvalId"])
    end
    assert_equal "47", shown
    refute_nil required["approvalToken"]
    # The workspace's own audience comes from GET /agents/approval-audience; another one is refused.
    assert_equal "touchque:workspace:fake-workspace", tq.agents.approval_audience
    claims = tq.agents.verify_approval_token(token, user: user, authorization_details: payment)
    assert_equal created["id"], claims["act"]["sub"]
    other = assert_raises(Touchque::ApprovalMismatchError) { tq.agents.verify_approval_token(token, audience: "touchque:workspace:other") }
    assert_match(/another workspace/, other.message)
    mismatch = assert_raises(Touchque::ApprovalMismatchError) do
      tq.agents.redeem_approval(token, authorization_details: payment.merge("instructedAmount" => { "currency" => "TRY", "amount" => "5000.00" }))
    end
    assert_match(/differ/, mismatch.message)
    approval = tq.agents.redeem_approval(token, user: user, type: "PAY_INVOICE",
                                                authorization_details: { type: "payment_initiation", instructedAmount: { currency: "try", amount: "500" } })
    assert_equal ask["approvalId"], approval["id"]
    assert_equal "already_redeemed", assert_raises(Touchque::APIError) { tq.agents.redeem_approval(token) }.code
    ask2 = bot.request_approval(user, "PAY_INVOICE", [payment], presence: "background")
    assert_nil ask2["challengeCode"]
    api.reject(ask2["approvalId"])
    assert_equal "rejected", assert_raises(Touchque::ApprovalError) { bot.wait_for_approval(ask2["approvalId"], timeout: 10, interval: 0.5) }.status
  end

  def test_blocks_and_mandates
    a = create("blocked", Touchque::AgentKeys.generate["publicJwk"])
    api.post("/__test/agent-block", { agentId: a["id"], user: "jane@example.com" })
    assert_equal "not_me", tq.agents.list_blocks(a["id"])[0]["reason"]
    tq.agents.lift_block(a["id"], "jane@example.com")
    assert_equal "/agents/#{a["id"]}/blocks/jane%40example.com", api.last_call["path"]
    assert_empty tq.agents.list_blocks(a["id"])

    user = "agent-mandates@example.com"
    api.link(user)
    tq.action_types.define("PAY_INVOICE", critical: false)
    keys = Touchque::AgentKeys.generate
    created = create("Mandate bot", keys["publicJwk"], ["PAY_INVOICE"])
    bot = agent(created["id"], keys["privateJwk"])
    payment = vectors["approvalToken"]["claims"]["authorization_details"][0]
    mandate = bot.request_mandate(user, "PAY_INVOICE", 2, { currency: "TRY", amount: "1000" }, valid_for: 3600)
    assert_equal "pending", mandate["status"]
    api.approve(api.get("/__test/requests").last["id"])
    assert_equal "active", bot.get_mandate(mandate["mandateId"])["status"]
    used = bot.request_approval(user, "PAY_INVOICE", [payment], mandate_id: mandate["mandateId"])
    assert_equal ["approved", 1], [used["status"], used["mandate"]["usedCount"]]
    assert_equal mandate["mandateId"], tq.agents.list_mandates(created["id"], user: user)[0]["mandateId"]
    assert_equal "revoked", tq.agents.revoke_mandate(created["id"], mandate["mandateId"])["status"]
    assert_equal "mandate_revoked", assert_raises(Touchque::APIError) { bot.request_approval(user, "PAY_INVOICE", [payment], mandate_id: mandate["mandateId"]) }.code
  end
end
