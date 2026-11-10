# frozen_string_literal: true

module TouchQue
  module Resources
    # TouchQue Mobile SDK, your backend's side: your own iOS/Android app is the approver
    # of your users (white-label); they never install the TouchQue app.
    #
    # 1. A user signed in to your app turns approvals on: create_enrollment gives a
    #    one-time token; your app hands it to the SDK (TouchQue.enroll).
    # 2. Ask for approvals as always (login.request, start, the guards).
    # 3. Without your APNs/FCM keys in update_settings, TouchQue sends you a signed
    #    MOBILE_PUSH webhook per request: verify it, then Mobile.push_from_webhook gives
    #    the APNs payload / FCM data to send with your own credentials.
    class Mobile
      SETTINGS = {
        "ios_app_ids" => "iosAppIds", "android_packages" => "androidPackages", "android_certs" => "androidCerts",
        "attestation" => "attestation", "enroll_ttl_seconds" => "enrollTtlSeconds", "apns" => "apns", "fcm" => "fcm"
      }.freeze

      def initialize(http)
        @http = http
      end

      # A one-time enrollment token for a user you signed in. Whoever spends it becomes
      # the user's approver, so authenticate the user first. APIError already_enrolled
      # (pass replace: true) or account_frozen.
      def create_enrollment(external_username, replace: false, ttl_seconds: nil)
        raise ConfigError, "mobile.create_enrollment() needs the user (external_username)" if external_username.to_s.empty?

        body = { "externalUsername" => external_username }
        body["replace"] = true if replace
        body["ttlSeconds"] = Integer(ttl_seconds) unless ttl_seconds.nil?
        @http.post("/mobile/enrollments", body)
      end

      # The devices inside your app (default: active ones), newest first: {"devices", "nextCursor"}.
      # status: active, revoked or all.
      def list_devices(external_username: nil, status: nil, limit: nil, cursor: nil)
        @http.get("/mobile/devices", Util.compact({ "externalUsername" => external_username, "status" => status, "limit" => limit, "cursor" => cursor }))
      end

      def get_device(device_id)
        raise ConfigError, "mobile.get_device() needs the device id" if device_id.to_s.empty?

        @http.get("/mobile/devices/#{Util.seg(device_id)}")["device"]
      end

      # Stops a device from approving (the user has no approver until you enrol again).
      def remove_device(device_id)
        raise ConfigError, "mobile.remove_device() needs the device id" if device_id.to_s.empty?

        @http.delete("/mobile/devices/#{Util.seg(device_id)}")
      end

      # A harmless push to the device, the way a request would reach it: "via" touchque
      # (your key for its platform) or webhook (MOBILE_PUSH, kind test); "ok": APNs / FCM took it.
      def test_push(device_id)
        raise ConfigError, "mobile.test_push() needs the device id" if device_id.to_s.empty?

        @http.post("/mobile/devices/#{Util.seg(device_id)}/test-push", {})
      end

      def settings
        @http.get("/mobile/settings")["settings"]
      end

      # Which apps may enrol, whether they must prove themselves, and your push keys. Only
      # the keys given change: ios_app_ids, android_packages, android_certs ({package =>
      # [SHA-256 of its signing certificate]}), attestation (off | optional | required),
      # enroll_ttl_seconds, apns ({keyId:, teamId:, topic:, key: the .p8 text, production:}:
      # TouchQue then sends the iOS push itself), fcm ({serviceAccount: the JSON}: the
      # Android push); nil removes a key. The keys are never shown back.
      def update_settings(**changes)
        unknown = changes.keys.map(&:to_s) - SETTINGS.keys
        raise ConfigError, "mobile.update_settings(): unknown setting #{unknown.join(", ")}" unless unknown.empty?

        @http.put("/mobile/settings", changes.to_h { |k, v| [SETTINGS[k.to_s], v] })["settings"]
      end

      # The push to send for a verified MOBILE_PUSH webhook, or nil for any other event:
      # deviceId, externalUsername, platform, pushToken (nil: send by your own user → device
      # mapping), requestId, expiresAt, kind, alert (English, translate it), apns (the APNs
      # payload: alert + the custom key "touchque") and fcmData. No secret, no details, no number.
      def self.push_from_webhook(event)
        event = Util.stringify(event) if event
        return nil unless event.is_a?(Hash) && event["event"] == "MOBILE_PUSH"

        data = event["data"].is_a?(Hash) ? event["data"] : {}
        touchque = data["touchque"].is_a?(String) ? data["touchque"] : Util.json(data["touchque"] || {})
        alert = event["alert"]
        aps = { "sound" => "default", "interruption-level" => "time-sensitive" }
        aps["alert"] = alert if alert
        {
          "deviceId" => event["deviceId"],
          "externalUsername" => event["externalUsername"],
          "platform" => event["platform"] == "android" ? "android" : "ios",
          "pushToken" => event["pushToken"].is_a?(String) ? event["pushToken"] : nil,
          "requestId" => event["requestId"],
          "expiresAt" => event["expiresAt"],
          # test: a test push sent from the dashboard
          "kind" => %w[notice test].include?(event["kind"]) ? event["kind"] : "approval",
          "alert" => alert,
          "apns" => { "aps" => aps, "touchque" => touchque },
          "fcmData" => { "touchque" => touchque }
        }
      end

      # True once a push is past its request's expiry (don't send it any more).
      def self.push_expired?(push, now = Time.now)
        at = Util.parse_time(push["expiresAt"])
        !at.nil? && at <= now.to_f
      end
    end
  end
end
