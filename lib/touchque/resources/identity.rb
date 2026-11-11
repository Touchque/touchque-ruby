# frozen_string_literal: true

module Touchque
  module Resources
    # Touchque Login Management API (tq.identity): your customers' accounts, roles,
    # business-customer organizations, apps, APIs, connections and the tenant itself,
    # from your server with your workspace key. Bodies and queries are Hashes with the
    # API's camelCase fields (symbol or string keys); answers are the API's JSON.
    #
    #   tq.identity.users.list(q: "ayse")
    #   tq.identity.users.block(user_id, reason: "chargeback")
    #   tq.identity.imports.start(users: [{ email: e, passwordHash: "$2b$10$..." }])
    class Identity
      attr_reader :users, :imports, :exports, :roles, :organizations, :clients, :apis, :connections, :custom_domains

      def initialize(http)
        @http = http
        @users = IdentityUsers.new(http)
        @imports = IdentityJobs.new(http, "imports")
        @exports = IdentityJobs.new(http, "exports")
        @roles = IdentityCrud.new(http, "/identity/roles", "roles")
        @organizations = IdentityOrganizations.new(http)
        @clients = IdentityClients.new(http)
        @apis = IdentityCrud.new(http, "/identity/apis", "apis")
        @connections = IdentityCrud.new(http, "/identity/connections", "connections")
        @custom_domains = IdentityCrud.new(http, "/identity/custom-domains", "domains")
      end

      # The tenant (404 not_enabled until it is set up).
      def get_tenant
        @http.get("/identity/tenant")
      end

      # Turns Touchque Login on (slug, displayName) or changes its settings.
      def update_tenant(body)
        @http.put("/identity/tenant", body)
      end

      def rotate_signing_key
        @http.post("/identity/tenant/signing-keys/rotate", {})
      end

      # The phone app the hosted pages tell customers to approve on ("Approve on the Acme app").
      # nil: your brand name when the Mobile SDK is set up, else Touchque (approverApp in the tenant shows which).
      def set_approver_app_name(name)
        @http.put("/identity/tenant", { "branding" => { "approverAppName" => name } })
      end

      # Serve sign-in only on the primary custom domain: {slug}.login.touchque.com redirects page loads there and
      # refuses other calls. Turning it on needs a verified primary domain with a working certificate.
      def set_custom_domain_only(on)
        @http.put("/identity/tenant", { "customDomainOnly" => on })
      end

      # Checks a verified custom domain's certificate at the sign-in edge now (certificate: pending | active | error).
      def check_domain_certificate(domain_id)
        @http.post("/identity/custom-domains/#{Util.seg(domain_id)}/check-certificate", {})
      end

      # The delivery log. Message text only in the local dev inbox.
      def outbox(params = {})
        @http.get("/identity/outbox", params)
      end

      # Wrong passwords, suspicious addresses, bot challenge, breached passwords, new-browser notices, the risk engine.
      def get_attack_protection
        @http.get("/identity/attack-protection")
      end

      # Partial; the bot challenge's secret is write-only.
      def set_attack_protection(settings)
        @http.put("/identity/attack-protection", settings)
      end

      # What attack protection caught lately.
      def attack_events(params = {})
        @http.get("/identity/attack-protection/events", params)
      end

      # The email and SMS providers; secrets never come back (secretsSet).
      def get_delivery
        @http.get("/identity/delivery")
      end

      # Your own provider: email smtp, ses, postmark, sendgrid; sms twilio, netgsm, e.g.
      # { provider: "postmark", from: "login@acme.com", serverToken: "..." }. A secret left
      # out keeps its stored value.
      def set_delivery(channel, provider)
        @http.put("/identity/delivery/#{Util.seg(channel)}", provider)
      end

      # Back to Touchque's transport.
      def remove_delivery(channel)
        @http.delete("/identity/delivery/#{Util.seg(channel)}")
      end

      # One test message through the provider in use.
      def test_delivery(channel, to)
        @http.post("/identity/delivery/#{Util.seg(channel)}/test", { "to" => to })
      end
    end

    # List, get, create, update and delete for one kind of Touchque Login object.
    class IdentityCrud
      def initialize(http, base, list_key)
        @http = http
        @base = base
        @list_key = list_key
      end

      def list(params = {})
        @http.get(@base, params)[@list_key] || []
      end

      def get(id)
        @http.get("#{@base}/#{Util.seg(id)}")
      end

      def create(body)
        @http.post(@base, body)
      end

      def update(id, body)
        @http.patch("#{@base}/#{Util.seg(id)}", body)
      end

      def delete(id)
        @http.delete("#{@base}/#{Util.seg(id)}")
      end
    end

    # Your customers' apps (OpenID Connect clients).
    class IdentityClients < IdentityCrud
      def initialize(http)
        super(http, "/identity/clients", "clients")
      end

      # A new client secret: it is in the answer, this once.
      def rotate_secret(client_id)
        @http.post("#{@base}/#{Util.seg(client_id)}/rotate-secret", {})
      end
    end

    # Business customers, their members and invitations.
    class IdentityOrganizations < IdentityCrud
      def initialize(http)
        super(http, "/identity/organizations", "organizations")
      end

      def members(org_id)
        @http.get("#{org(org_id)}/members")
      end

      def add_members(org_id, user_ids)
        @http.post("#{org(org_id)}/members", { "userIds" => user_ids.to_a })
      end

      def remove_member(org_id, user_id)
        @http.delete("#{org(org_id)}/members/#{Util.seg(user_id)}")
      end

      def set_connections(org_id, connections)
        @http.put("#{org(org_id)}/connections", { "connections" => connections })
      end

      def invitations(org_id)
        @http.get("#{org(org_id)}/invitations")
      end

      # The link opens the app's sign-in route (initiateLoginUri) with organization and invitation.
      def invite(org_id, invitation)
        @http.post("#{org(org_id)}/invitations", invitation)
      end

      def revoke_invitation(org_id, invitation_id)
        @http.delete("#{org(org_id)}/invitations/#{Util.seg(invitation_id)}")
      end

      private

      def org(org_id)
        "#{@base}/#{Util.seg(org_id)}"
      end
    end

    # Bulk user imports and exports, running in the background.
    class IdentityJobs
      def initialize(http, kind)
        @http = http
        @kind = kind
      end

      # Imports: { users: [...], upsert: true }; exports: { format: "csv" | "json" }.
      def start(body)
        @http.post("/identity/users-#{@kind}", body)
      end

      def get(job_id)
        @http.get("/identity/users-#{@kind}/#{Util.seg(job_id)}")
      end

      # Exports: the finished file (CSV or JSON text).
      def file(job_id)
        @http.get_text("/identity/users-#{@kind}/#{Util.seg(job_id)}/file")
      end

      # Polls until the job is done or failed (or the timeout passes: the last state).
      def wait(job_id, interval: 1.0, timeout: 600.0)
        deadline = Time.now + timeout
        loop do
          job = get(job_id)
          return job if job["status"] != "running" || Time.now > deadline

          sleep interval
        end
      end
    end

    # A tenant's customer accounts.
    class IdentityUsers
      def initialize(http)
        @http = http
      end

      # Query: q, blocked, emailVerified, connection, organization, limit, cursor.
      def list(params = {})
        @http.get("/identity/users", params)
      end

      def get(user_id)
        @http.get(u(user_id))
      end

      # email and: password, passwordHash (bcrypt/argon2), customPasswordHash, emailVerified,
      # name, givenName, familyName, phone, locale, userMetadata, appMetadata, sendVerificationEmail.
      def create(user)
        @http.post("/identity/users", user)
      end

      # Metadata is merged; a key set to nil is removed.
      def update(user_id, changes)
        @http.patch(u(user_id), changes)
      end

      # Erasure (KVKK/GDPR): the account and every workspace row that names it.
      def delete(user_id)
        @http.delete(u(user_id))
      end

      def block(user_id, reason: nil)
        @http.post("#{u(user_id)}/block", Util.compact({ "reason" => reason }))
      end

      def unblock(user_id)
        @http.post("#{u(user_id)}/unblock", {})
      end

      # Everything about the person (KVKK/GDPR access request); never hashes.
      def export(user_id)
        @http.get("#{u(user_id)}/export")
      end

      def sessions(user_id)
        @http.get("#{u(user_id)}/sessions")
      end

      # Ends one of the user's sessions.
      def end_session(user_id, session_id)
        @http.delete("#{u(user_id)}/sessions/#{Util.seg(session_id)}")
      end

      def sign_out_everywhere(user_id)
        @http.delete("#{u(user_id)}/sessions")
      end

      # Removes passkeys, unlinks the Touchque app, turns email codes off, signs out everywhere.
      def reset_mfa(user_id)
        @http.delete("#{u(user_id)}/mfa")
      end

      # Accounts at providers whose tokens the vault keeps for the user (connections with tokenVault on).
      def connected_accounts(user_id)
        @http.get("#{u(user_id)}/connected-accounts")
      end

      # Deletes the stored tokens: apps stop using the account for the user; signing in with it stays.
      def disconnect_account(user_id, account_id)
        @http.delete("#{u(user_id)}/connected-accounts/#{Util.seg(account_id)}")
      end

      def unlink_identity(user_id, identity_id, force: false)
        @http.delete("#{u(user_id)}/identities/#{Util.seg(identity_id)}#{force ? "?force=true" : ""}")
      end

      def send_verification_email(user_id, return_to: nil)
        @http.post("#{u(user_id)}/verification-email", Util.compact({ "returnTo" => return_to }))
      end

      # send_email: false: the link comes back for you to deliver.
      def password_reset(user_id, send_email: true, ttl_sec: nil)
        body = { "sendEmail" => send_email }
        body["ttlSec"] = ttl_sec unless ttl_sec.nil?
        @http.post("#{u(user_id)}/password-reset", body)
      end

      def roles(user_id)
        @http.get("#{u(user_id)}/roles")
      end

      def add_roles(user_id, role_ids, organization_id: nil)
        body = { "roleIds" => role_ids.to_a }
        body["organizationId"] = organization_id unless organization_id.nil?
        @http.post("#{u(user_id)}/roles", body)
      end

      def remove_role(user_id, role_id, organization_id: nil)
        @http.delete("#{u(user_id)}/roles/#{Util.seg(role_id)}#{organization_id ? "?organizationId=#{Util.seg(organization_id)}" : ""}")
      end

      def logs(user_id, limit: nil)
        @http.get("#{u(user_id)}/logs", { "limit" => limit })
      end

      private

      def u(user_id)
        "/identity/users/#{Util.seg(user_id)}"
      end
    end
  end
end
