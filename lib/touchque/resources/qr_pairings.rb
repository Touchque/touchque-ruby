# frozen_string_literal: true

module Touchque
  module Resources
    # Pairing a browser by QR code: your page shows a QR code, the person scans it with
    # the Touchque app, and the phone that scanned is the one asked to approve.
    #
    # 1. Your page gets the thumbprint of its browser key (@touchque/web
    #    browserKey.thumbprint()) and sends it to your server.
    # 2. create(key_thumbprint, client_ip:, user_agent:) registers a pairing and returns
    #    "uri" (touchque://pair-browser?...): show it as a QR code. It can be scanned once,
    #    for ttl_seconds (default 120). The nonce in it never leaves your server and the
    #    QR: Touchque keeps only its hash.
    # 3. Poll get(pairing_id): "scanned" once a phone holding one of your users' accounts
    #    read it ("externalUsername", "proximity"), "confirmed" once the person went on,
    #    "reported" when they said someone told them to scan it (their 2FA freezes).
    # 4. login.request(user, qr_pairing: pairing_id) asks that phone, once, with number
    #    matching; the browser key's fingerprint is one of the rows the phone signs. When
    #    your own checks say no, refuse(pairing_id, reason:, message:) and the phone
    #    shows why.
    class QrPairings
      # What refuse may tell the phone.
      REFUSAL_REASONS = %w[policy device_not_approved too_many_browsers rate_limited no_account other].freeze

      B64URL_43 = /\A[A-Za-z0-9_-]{43}\z/

      # What the QR code says: touchque://pair-browser?v=1&p=<pairing>&n=<nonce>&k=<key thumbprint>.
      def self.uri(pairing_id, nonce, key_thumbprint)
        "touchque://pair-browser?v=1&p=#{Util.seg(pairing_id)}&n=#{Util.seg(nonce)}&k=#{Util.seg(key_thumbprint)}"
      end

      def initialize(http)
        @http = http
      end

      # Registers a pairing for one browser: {"pairingId", "expiresAt", "nonce", "uri"};
      # show "uri" as a QR code. +browser+ ("Chrome 155") and +os+ ("macOS 15") are shown
      # on the phone; +ttl_seconds+ is 30 to 300.
      def create(key_thumbprint, client_ip: nil, user_agent: nil, browser: nil, os: nil, ttl_seconds: nil)
        unless key_thumbprint.is_a?(String) && key_thumbprint.match?(B64URL_43)
          raise ConfigError, "qr_pairings.create needs key_thumbprint: the RFC 7638 thumbprint of the browser key, base64url (43 characters)"
        end
        if !ttl_seconds.nil? && !(ttl_seconds.is_a?(Integer) && ttl_seconds.between?(30, 300))
          raise ConfigError, "qr_pairings.create: ttl_seconds must be 30 to 300"
        end

        nonce = Util.b64url(SecureRandom.random_bytes(32))
        body = { "nonceHash" => Util.b64url(Util.sha256(nonce)), "keyThumbprint" => key_thumbprint }
        { "clientIp" => client_ip, "userAgent" => user_agent, "browser" => browser, "os" => os, "ttlSeconds" => ttl_seconds }.each do |k, v|
          body[k] = v unless v.nil? || v == ""
        end
        created = @http.post("/qr-pairings", body)
        created.merge("nonce" => nonce, "uri" => self.class.uri(created["pairingId"], nonce, key_thumbprint))
      end

      # Where a pairing stands; once scanned, who scanned it and how near the phone was.
      def get(pairing_id)
        @http.get(path(pairing_id, "get"))
      end

      # Your own checks refused a scanned pairing; the phone shows +message+. Only a
      # "scanned" or "confirmed" pairing can be refused (409 not_open otherwise).
      def refuse(pairing_id, reason:, message:, case_code: nil, device_code: nil)
        raise ConfigError, "qr_pairings.refuse: reason must be one of #{REFUSAL_REASONS.join(", ")}" unless REFUSAL_REASONS.include?(reason.to_s)
        raise ConfigError, "qr_pairings.refuse needs message: what the phone shows (up to 300 characters)" if message.to_s.strip.empty?

        body = { "reason" => reason.to_s, "message" => message }
        body["caseCode"] = case_code unless case_code.to_s.empty?
        body["deviceCode"] = device_code unless device_code.to_s.empty?
        @http.post(path(pairing_id, "refuse", "/outcome"), body)
      end

      private

      def path(pairing_id, method, rest = "")
        raise ConfigError, "qr_pairings.#{method} needs the pairing id" if pairing_id.to_s.empty?

        "/qr-pairings/#{Util.seg(pairing_id)}#{rest}"
      end
    end
  end
end
