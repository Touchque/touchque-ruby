# frozen_string_literal: true

module Touchque
  module Resources
    # AI agents as identities of their own: register an agent with its PUBLIC key, give
    # it an accountable owner and the action types it may ask approvals for, suspend,
    # revoke or stop every agent at once. The agent itself never gets your API key: it
    # signs in with its own key (Touchque::Agent).
    #
    #   keys = Touchque::AgentKeys.generate                     # where the agent runs
    #   agent = tq.agents.create("Invoice bot", ["PAY_INVOICE"], public_key: keys["publicJwk"])
    class Agents
      attr_reader :vault

      def initialize(http)
        @http = http
        @vault = AgentVault.new(http)
        @jwks = nil
        @jwks_at = 0
        @audience = nil
        @lock = Mutex.new
      end

      # Uses an agent's approval exactly once, right before you execute: checks the
      # expectation against the token first (nothing is used on a mismatch), then
      # Touchque checks the token and marks it used, and the answer is checked again.
      def redeem_approval(token, user: nil, type: nil, authorization_details: nil)
        expect = { user: user, type: type, authorization_details: authorization_details }
        ApprovalToken.assert_matches!(ApprovalToken.decode(token)["claims"], **expect)
        approval = @http.post("/agents/approvals/redeem", { "token" => token })["approval"] || {}
        ApprovalToken.assert_matches!({ "sub" => approval["externalUsername"], "type" => approval["type"],
                                        "authorization_details" => approval["authorizationDetails"] }, **expect)
        approval
      end

      # The aud of this workspace's approval tokens (touchque:workspace:<id>), from
      # GET /agents/approval-audience; asked once, then kept.
      def approval_audience
        @lock.synchronize do
          unless @audience
            audience = (@http.get("/agents/approval-audience") || {})["audience"]
            raise ApprovalMismatchError, "Touchque did not name this workspace's approval audience" if !audience.is_a?(String) || audience.empty?

            @audience = audience
          end
          @audience
        end
      end

      # Verifies an approval token offline (Touchque's published keys, expiry, aud, the
      # expectation). aud must be this workspace's: audience defaults to approval_audience,
      # and a token without aud or for another workspace is refused. It does not make
      # the token single-use: redeem_approval does.
      def verify_approval_token(token, audience: nil, user: nil, type: nil, authorization_details: nil)
        audience = approval_audience if audience.nil? || audience.to_s.empty?
        expect = { audience: audience, user: user, type: type, authorization_details: authorization_details }
        ApprovalToken.verify_with(token, jwks(false), **expect)
      rescue ApprovalMismatchError => e
        raise unless e.message.include?("unknown key")

        ApprovalToken.verify_with(token, jwks(true), **expect)
      end

      # Registers an agent (needs the agents:write scope). owner_email: the accountable
      # member (default the API key's creator; the agent stops when they leave).
      def create(name, allowed_types, public_key: nil, public_keys: nil, description: nil, owner_email: nil, platform: nil, review_in_days: nil)
        body = { "name" => name, "allowedTypes" => allowed_types.to_a }
        body["description"] = description unless description.nil?
        body["ownerEmail"] = owner_email unless owner_email.nil?
        body["platform"] = platform unless platform.nil?
        body["reviewInDays"] = review_in_days unless review_in_days.nil?
        body["publicKey"] = public_only(public_key) unless public_key.nil?
        body["publicKeys"] = public_keys.map { |k| public_only(k) } unless public_keys.nil?
        @http.post("/agents", body)["agent"]
      end

      # {"agents" => [...], "killSwitch" => {...}}.
      def list(status: nil)
        @http.get("/agents", { "status" => status })
      end

      def get(agent_id)
        @http.get(path(agent_id))["agent"]
      end

      # Changes, hands over (owner_email) or renews (review_in_days) an agent.
      def update(agent_id, name: nil, description: nil, owner_email: nil, platform: nil, allowed_types: nil, review_in_days: nil)
        body = { "name" => name, "description" => description, "ownerEmail" => owner_email, "platform" => platform,
                 "allowedTypes" => allowed_types, "reviewInDays" => review_in_days }.reject { |_, v| v.nil? }
        @http.patch(path(agent_id), body)["agent"]
      end

      # Adds a key (rotation: add the new one, move the agent to it, then remove the old one).
      def add_key(agent_id, public_key)
        @http.post("#{path(agent_id)}/keys", { "publicKey" => public_only(public_key) })["agent"]
      end

      # Removes a key; tokens the agent got with it stop at once.
      def remove_key(agent_id, kid)
        @http.delete("#{path(agent_id)}/keys/#{Util.seg(kid)}")["agent"]
      end

      # Stops an agent at once (its tokens too) until resumed.
      def suspend(agent_id, reason: nil)
        @http.post("#{path(agent_id)}/suspend", Util.compact({ "reason" => reason }))["agent"]
      end

      def resume(agent_id)
        @http.post("#{path(agent_id)}/resume", {})["agent"]
      end

      # Revokes an agent for good (the record stays for the audit trail).
      def revoke(agent_id)
        @http.delete(path(agent_id))["agent"]
      end

      # Sets the agent's budgets, amounts, recipients and background rule (a full
      # replacement): requestsPer10Min, requestsPerUserPer10Min, amountPerRequest /
      # amountPerDay ({"TRY" => "1000.00"}), background (non_critical | never),
      # newRecipients (ask | deny), recipientAllowlist, fourEyes, requirePasskeyAbove
      # ({"TRY" => "10000.00"}: over it the person approves with a passkey on your page,
      # never on the phone or with a mandate).
      def set_policy(agent_id, policy)
        @http.put("#{path(agent_id)}/policy", { "policy" => Util.stringify(policy) })["agent"]
      end

      # The workspace's agent events for a SIEM, oldest first: { "events", "next", "hasMore" }.
      # Keep "next" and pass it as +after+; the first call reads from +since+ (ISO 8601;
      # default the last 24 hours).
      def list_events(after: nil, since: nil, limit: nil)
        query = { "after" => after, "since" => since, "limit" => limit }.compact
        @http.get("/agents/events", query.empty? ? nil : query)
      end

      # The workspace's policy: every agent's floor (an agent's own policy can only make it stricter).
      def workspace_policy
        @http.get("/agents/workspace-policy")["policy"]
      end

      # The name every other Touchque SDK uses (getWorkspacePolicy); workspace_policy stays.
      alias get_workspace_policy workspace_policy

      # Sets the workspace's policy (a full replacement; a field left out sets no floor).
      def set_workspace_policy(policy)
        @http.put("/agents/workspace-policy", { "policy" => Util.stringify(policy) })["policy"]
      end

      # The people who stopped this agent asking them (reason not_me, coached or rejections).
      def list_blocks(agent_id)
        @http.get("#{path(agent_id)}/blocks")["blocks"] || []
      end

      # Lets the agent ask this person again (check with them first).
      def lift_block(agent_id, user)
        @http.delete("#{path(agent_id)}/blocks/#{Util.seg(user)}")
        nil
      end

      # An agent's mandates, optionally one person's.
      def list_mandates(agent_id, user: nil)
        @http.get("#{path(agent_id)}/mandates", { "externalUsername" => user })["mandates"] || []
      end

      # Ends an agent's mandate at once.
      def revoke_mandate(agent_id, mandate_id)
        @http.post("#{path(agent_id)}/mandates/#{Util.seg(mandate_id)}/revoke", {})
      end

      # Stops (true) or restarts (false) every agent of the workspace at once.
      def set_kill_switch(engaged, reason: nil)
        body = { "engaged" => engaged }
        body["reason"] = reason if reason
        @http.put("/agents/kill-switch", body)["killSwitch"]
      end

      private

      def path(agent_id)
        "/agents/#{Util.seg(agent_id)}"
      end

      # Refuses a private key before it leaves this process.
      def public_only(jwk)
        jwk = Util.stringify(jwk)
        if jwk.key?("d")
          raise ConfigError, "Pass the agent's PUBLIC key: this one has private parts (d). The private key must stay where the agent runs."
        end

        jwk
      end

      def jwks(force)
        @lock.synchronize do
          if force || @jwks.nil? || Util.now - @jwks_at > 300
            @jwks = @http.get("/agents/jwks.json")
            @jwks_at = Util.now
          end
          @jwks
        end
      end
    end

    # The token vault for your agents (tq.agents.vault): after your own OAuth flow with a
    # person, deposit their tokens; Touchque keeps them sealed and refreshes them, and the
    # agents a connection names get a short-lived access token
    # (Touchque::Agent#get_connection_token), never the refresh token.
    class AgentVault
      def initialize(http)
        @http = http
      end

      def list_connections
        @http.get("/agents/vault/connections")["connections"] || []
      end

      # Adds or replaces a connection; client_secret is kept when left out of a replacement.
      # provider: google, microsoft, github, facebook, linkedin, x or oidc.
      def put_connection(name, provider:, client_id:, client_secret: nil, tenant: nil, issuer: nil, agent_ids: nil)
        body = { "provider" => provider, "clientId" => client_id }
        body.merge!(Util.compact({ "clientSecret" => client_secret, "tenant" => tenant, "issuer" => issuer }))
        body["agentIds"] = agent_ids.to_a unless agent_ids.nil?
        @http.put("/agents/vault/connections/#{Util.seg(name)}", body)["connection"]
      end

      # Removes it, and every person's tokens kept for it.
      def remove_connection(name)
        @http.delete("/agents/vault/connections/#{Util.seg(name)}")
      end

      # Keeps a person's tokens (replacing earlier ones) after your own OAuth flow with them.
      def deposit(connection, user, access_token:, refresh_token: nil, expires_in: nil, scope: nil)
        body = { "accessToken" => access_token }
        body["refreshToken"] = refresh_token unless refresh_token.nil?
        body["expiresIn"] = expires_in unless expires_in.nil?
        body["scope"] = scope unless scope.nil?
        @http.put("/agents/vault/accounts/#{Util.seg(connection)}/#{Util.seg(user)}", body)["account"]
      end

      # A person's accounts in the vault (never a token).
      def list_accounts(user)
        @http.get("/agents/vault/accounts", { "externalUsername" => user })["accounts"] || []
      end

      # Deletes a person's tokens: agents get nothing more for them there.
      def remove_account(connection, user)
        @http.delete("/agents/vault/accounts/#{Util.seg(connection)}/#{Util.seg(user)}")
        nil
      end
    end
  end
end
