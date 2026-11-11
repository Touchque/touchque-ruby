# frozen_string_literal: true

module Touchque
  module Resources
    # Device risk (a paid add-on, off until your workspace turns it on): a visitor ID for
    # every browser on your sign-up, password-reset, sign-in or approval page. The page
    # identifies with @touchque/web (deviceRisk.identify({ siteKey, purpose }) gives
    # { visitorId, requestId, confidence }) and sends you the requestId. Never trust the
    # page's copy: read the identification here (get_event) or check it for an account
    # (check). Touchque keeps keyed hashes only, with a key of your workspace alone, and its
    # risk engine decides.
    #
    # Every signal only ever asks for more: "stepUp" means an extra check on this page (an
    # emailed code, a passkey, a number-matched approval), never a refusal. For sign-ins,
    # pass the requestId to login.request / risk.check as device_risk_request_id: instead.
    # Collect it only on these pages and name it in your privacy notice.
    #
    # With the script tag (device.js), the form arrives with touchque_request_id:
    #
    #   r = tq.device_risk.check(params[:touchque_request_id], event: "sign_in", external_username: email)
    #
    # Pass it as it came. Missing, empty, made up or expired, it is still a verdict
    # ("report" missing, unknown, expired; the signal device_identification_missing), never an
    # exception: a page without the tag, or with it blocked, only gets the visitor a step-up.
    class DeviceRisk
      # The pages a device report may come from.
      EVENTS = %w[sign_in sign_up password_reset approval].freeze
      # What the page had sent: ok, replayed, or no usable identification.
      REPORTS = %w[ok replayed missing unknown expired invalid].freeze
      REQUEST_ID = /\Adre_[A-Za-z0-9_-]{22}\z/

      def initialize(http)
        @http = http
      end

      # Reads an answer, failing toward asking: "stepUp" is true unless it says exactly
      # false; junk signals are dropped.
      def self.parse_check(raw)
        body = raw.is_a?(Hash) ? raw : {}
        signals = (body["signals"].is_a?(Array) ? body["signals"] : []).filter_map do |s|
          next unless s.is_a?(Hash) && s["code"].is_a?(String)

          item = { "code" => s["code"], "text" => s["text"].is_a?(String) ? s["text"] : "",
                   "strength" => %w[passkey none].include?(s["strength"]) ? s["strength"] : "number_match" }
          item["enforced"] = s["enforced"] if [true, false].include?(s["enforced"])
          item["evidence"] = s["evidence"] if s["evidence"].is_a?(Hash)
          item
        end
        out = {
          "report" => REPORTS.include?(body["report"]) ? body["report"] : "invalid",
          "requestId" => body["requestId"].is_a?(String) ? body["requestId"] : nil,
          "visitorId" => body["visitorId"].is_a?(String) ? body["visitorId"] : nil,
          "confidence" => body["confidence"].is_a?(Numeric) ? body["confidence"] : nil,
          "visitor" => body["visitor"].is_a?(Hash) ? body["visitor"] : nil,
          "counts" => body["counts"].is_a?(Hash) ? body["counts"] : nil,
          # The address (never coordinates), the visitor's counts, one answer to "a bot?" (detected | suspected | not_detected).
          "network" => body["network"].is_a?(Hash) ? body["network"] : nil,
          "velocity" => body["velocity"].is_a?(Hash) ? body["velocity"] : nil,
          "bot" => body["bot"].is_a?(Hash) ? body["bot"] : nil,
          "signals" => signals,
          "stepUp" => body["stepUp"] != false,
          "wouldStepUp" => body["wouldStepUp"] == true,
          "requires" => %w[number_match passkey].include?(body["requires"]) ? body["requires"] : "none",
          "mode" => body["mode"] == "enforce" ? "enforce" : "shadow",
          # The engine's state for this check; "unavailable" when the risk engine could not be reached and the verdict is a safe default.
          "engine" => body["engine"].is_a?(String) ? body["engine"] : nil
        }
        out["caseCode"] = body["caseCode"] if body["caseCode"].is_a?(String)
        out
      end

      # Checks the page's identification for an account: binds it (one account per
      # identification, 15 minutes) and asks the risk engine. Pass the form field as it came:
      # nil, empty or made up is still a verdict ("report" missing, unknown), never an
      # exception. 409 device_risk_off until your workspace turns Device risk on.
      # device_risk: instead of request_id, the page's report (deviceRisk.collect).
      #
      #   r = tq.device_risk.check(params[:touchque_request_id], event: "sign_up", external_username: email, client_ip: request.remote_ip)
      #   ask_for_email_code if r["stepUp"]   # never refuse on it alone
      def check(request_id = nil, event: "sign_in", external_username: nil, client_ip: nil, device_risk: nil)
        raise ConfigError, "device_risk.check(): event must be one of #{EVENTS.join(", ")}" unless EVENTS.include?(event)

        body = {}
        if request_id.is_a?(String) && !request_id.empty?
          body["requestId"] = request_id[0, 64]
        elsif !device_risk.to_s.empty?
          body["deviceRisk"] = device_risk
        end
        body["event"] = event
        body["externalUsername"] = external_username unless external_username.to_s.empty?
        body["clientIp"] = client_ip unless client_ip.to_s.empty?
        self.class.parse_check(@http.post("/device-risk/check", body))
      end

      SEARCH_FILTERS = { from: "from", to: "to", signal: "signal", kind: "kind", origin: "origin", ip: "ip", account: "account",
                         visitor_id: "visitorId", request_id: "requestId", cursor: "cursor" }.freeze

      # Your workspace's identifications, newest first, one page at a time
      # (GET /device-risk/events): a date range (from:/to: YYYY-MM-DD or ISO times; 7 days by
      # default, at most 90, within your retention) and any of the filters. ip: is an address
      # or a CIDR range and is never returned. Pass "nextCursor" back as cursor: until it is
      # nil; do not page by moving the dates. A search that would read too much is a 422
      # search_too_broad: narrow the range or add a filter.
      # { "events" => [...], "nextCursor" => String | nil, "from" => String, "to" => String }.
      def search_events(step_up: nil, limit: nil, **filters)
        unknown = filters.keys - SEARCH_FILTERS.keys
        raise ConfigError, "device_risk.search_events() does not know #{unknown.join(', ')}" unless unknown.empty?
        raise ConfigError, "device_risk.search_events() limit must be 1 to 100" unless limit.nil? || (limit.is_a?(Integer) && limit.between?(1, 100))

        params = {}
        filters.each { |k, v| params[SEARCH_FILTERS[k]] = v if v.is_a?(String) && !v.empty? }
        params["stepUp"] = step_up ? "true" : "false" if [true, false].include?(step_up)
        params["limit"] = limit.to_s if limit
        raw = @http.get("/device-risk/events", params) || {}
        cursor = raw["nextCursor"]
        { "events" => raw["events"].is_a?(Array) ? raw["events"] : [],
          "nextCursor" => cursor.is_a?(String) && !cursor.empty? ? cursor : nil,
          "from" => raw["from"].to_s, "to" => raw["to"].to_s }
      end

      # The trusted identification behind a request_id: the visitor, how sure, what the page
      # showed, the risk engine's verdict. Read-only.
      def get_event(request_id)
        raise ConfigError, "device_risk.get_event() needs a request_id (dre_...)" unless request_id.is_a?(String) && REQUEST_ID.match?(request_id)

        @http.get("/device-risk/events/#{request_id}")
      end
    end
  end
end
