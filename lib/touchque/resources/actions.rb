# frozen_string_literal: true

module TouchQue
  module Resources
    # Action types (LOGIN, SEND_MONEY...): what a user is asked to approve. Define them
    # from code at start-up instead of clicking them into the dashboard.
    class ActionTypes
      # The Second Thought questions an action type can ask (at most two).
      SECOND_THOUGHT_QUESTIONS = %w[someone_guiding safe_account remote_access asked_for_code support_call
                                    met_online promised_return know_recipient sim_in_hand].freeze

      def initialize(http)
        @http = http
      end

      # Creates the action type, or updates its name, description, critical flag and
      # Second Thought questions ({questions: [...], locale: "tr" | "en"}; questions: []
      # turns them off; nil keeps what the dashboard has). Never re-enables a type an
      # admin disabled.
      def define(type, name: nil, description: nil, critical: nil, second_thought: nil)
        body = { "type" => type, "name" => name || type }
        body["description"] = description unless description.nil?
        body["critical"] = critical unless critical.nil?
        body["secondThought"] = Util.stringify(second_thought) unless second_thought.nil?
        @http.post("/action-types", body)
      end

      def list
        @http.get("/action-types")
      end
    end

    # TouchQue Actions: your own code at points of the approval pipeline (before the push
    # is sent, the silent sign-in decision, after an approval, fraud reports, device and
    # recovery events). TouchQue runs it in a sandbox; this resource deploys, tests,
    # replays and observes it.
    #
    #   tq.actions.deploy("night-alert", trigger: "approval.decided",
    #                     template: { id: "alert", params: { channel: "slack", when: { countries: ["TR"] } } })
    #
    # Action code itself is JavaScript (exports.onExecute = async (event, api) => {...}),
    # whatever language your server is written in.
    class Actions
      SLUG = /\A[a-z0-9][a-z0-9-]{1,62}\z/.freeze
      TEMPLATE = /\A[a-z_]{1,64}\z/.freeze

      attr_reader :secrets

      def initialize(http)
        @http = http
        @secrets = ActionSecrets.new(http)
      end

      # Creates the Action or adds a version and makes it live (idempotent). A version
      # asking for a loosening capability (skip_number_match, override_block,
      # allow_silent) waits for an admin's phone approval: then "deployed" is false and
      # "approval" => {"required" => true}.
      def deploy(slug, trigger: nil, code: nil, template: nil, name: nil, secrets: nil, allowed_hosts: nil,
                 capabilities: nil, on_failure: nil, order: nil, enabled: nil, activate: nil)
        path = slug_path(slug)
        raise ConfigError, "actions.deploy() needs code or template" if code.nil? && template.nil?

        body = draft(trigger: trigger, code: code, template: template, secrets: secrets, allowed_hosts: allowed_hosts, capabilities: capabilities)
        body["name"] = name unless name.nil?
        body["onFailure"] = on_failure unless on_failure.nil?
        body["order"] = order unless order.nil?
        body["enabled"] = enabled unless enabled.nil?
        body["activate"] = activate unless activate.nil?
        @http.put(path, body)
      end

      def list
        @http.get("/actions")["actions"] || []
      end

      # The Action, the active version's code and its versions.
      def get(slug)
        @http.get(slug_path(slug))
      end

      def version(slug, number)
        @http.get("#{slug_path(slug)}/versions/#{Integer(number)}")
      end

      # Rename, turn on or off, reorder, change on_failure.
      def update(slug, name: nil, enabled: nil, order: nil, on_failure: nil)
        body = { "name" => name, "enabled" => enabled, "order" => order, "onFailure" => on_failure }.reject { |_, v| v.nil? }
        res = @http.patch(slug_path(slug), body)
        res["action"] || res
      end

      def delete(slug)
        @http.delete(slug_path(slug))
      end

      # Back to +version+, or to the newest runnable version before the active one.
      def rollback(slug, version: nil)
        @http.post("#{slug_path(slug)}/rollback", version.nil? ? {} : { "version" => version })
      end

      # Runs a draft (or the deployed Action +slug+) once on a recorded event, your own
      # event or the trigger's sample. Sends nothing.
      def test(trigger: nil, code: nil, template: nil, slug: nil, secrets: nil, allowed_hosts: nil, capabilities: nil,
               event_id: nil, event: nil, network: nil)
        body = draft(trigger: trigger, code: code, template: template, slug: slug, secrets: secrets, allowed_hosts: allowed_hosts, capabilities: capabilities)
        body["eventId"] = event_id unless event_id.nil?
        body["event"] = Util.stringify(event) unless event.nil?
        body["network"] = network unless network.nil?
        @http.post("/actions/test", body)
      end

      # Replays a draft against recent real decisions: how many it would have changed
      # ("changed", "transitions" such as "push→number_match" => 12), notifications,
      # errors and timing. +replaces+: the deployed Action it would replace.
      def dry_run(trigger: nil, code: nil, template: nil, slug: nil, secrets: nil, allowed_hosts: nil, capabilities: nil,
                  replaces: nil, on_failure: nil, limit: nil, since: nil)
        body = draft(trigger: trigger, code: code, template: template, slug: slug, secrets: secrets, allowed_hosts: allowed_hosts, capabilities: capabilities)
        body["replaces"] = replaces unless replaces.nil?
        body["onFailure"] = on_failure unless on_failure.nil?
        body["limit"] = limit unless limit.nil?
        body["since"] = since.respond_to?(:iso8601) ? since.iso8601 : since unless since.nil?
        @http.post("/actions/dry-run", body)
      end

      # Recorded events (newest first, kept 30 days); use an id with test(event_id:).
      def events(trigger: nil, limit: nil)
        @http.get("/actions/events", { "trigger" => trigger, "limit" => limit })["events"] || []
      end

      # Live runs: decision, notifications, console output, errors.
      def logs(slug, limit: nil, before: nil)
        before = before.iso8601 if before.respond_to?(:iso8601)
        @http.get("#{slug_path(slug)}/logs", { "limit" => limit, "before" => before })["logs"] || []
      end

      # +window+: 1h, 24h (default), 7d or 30d.
      def metrics(slug, window: nil)
        @http.get("#{slug_path(slug)}/metrics", { "window" => window })
      end

      # Every trigger with its decisions, capabilities, notification types and a sample event.
      def triggers
        @http.get("/actions/triggers")
      end

      def templates
        @http.get("/actions/templates")["templates"] || []
      end

      # A template as plain code (to read, or to start a code Action from).
      def render_template(id, trigger, params = {})
        raise ConfigError, "Unknown template id" unless id.to_s.match?(TEMPLATE)

        @http.post("/actions/templates/#{id}/render", { "trigger" => trigger, "params" => Util.stringify(params || {}) })
      end

      private

      def slug_path(slug)
        raise ConfigError, "An Action slug is 2-63 lowercase letters, digits or - (e.g. \"night-alert\")" unless slug.to_s.match?(SLUG)

        "/actions/#{slug}"
      end

      def draft(trigger: nil, code: nil, template: nil, slug: nil, secrets: nil, allowed_hosts: nil, capabilities: nil)
        body = {}
        body["trigger"] = trigger unless trigger.nil?
        body["slug"] = slug unless slug.nil?
        body["code"] = code unless code.nil?
        body["template"] = Util.stringify(template) unless template.nil?
        body["secrets"] = secrets unless secrets.nil?
        body["allowedHosts"] = allowed_hosts unless allowed_hosts.nil?
        body["capabilities"] = capabilities unless capabilities.nil?
        body
      end
    end

    # Secrets your Actions read (event.secrets.NAME) or notify with. A value is encrypted
    # and never readable again through the API.
    class ActionSecrets
      NAME = /\A[A-Z][A-Z0-9_]{0,63}\z/.freeze

      def initialize(http)
        @http = http
      end

      def set(name, value)
        path = path(name)
        raise ConfigError, "A secret value is a non-empty string" if value.to_s.empty?

        @http.put(path, { "value" => value })
      end

      # Names only.
      def list
        @http.get("/actions/secrets")["secrets"] || []
      end

      def delete(name)
        @http.delete(path(name))
      end

      private

      def path(name)
        raise ConfigError, "A secret name is capital letters, digits or _ (e.g. SLACK_WEBHOOK_URL)" unless name.to_s.match?(NAME)

        "/actions/secrets/#{name}"
      end
    end
  end
end
