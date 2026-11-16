# frozen_string_literal: true

module Touchque
  # 2FA setup context: where a first-time linking QR was asked for, as auth.validate_secret
  # answers it in "setupContext". Touchque records it from the request that made the QR,
  # generate_secret or reset_secret (the browser's address and its place, the browser and
  # device, the time), and keeps it on its servers, never in the QR. The phone shows it before
  # it links, so a person tricked into scanning someone else's QR sees that person's city and
  # device.
  #
  # A Hash with the API's keys ("ip", "location", "device", "requestedAt", "farFromPhone"),
  # each nil when Touchque does not know it, with a reader for each:
  #
  #   # validate_secret is the phone's call, with the secret it scanned (here: from a server)
  #   ctx = tq.auth.validate_secret(secret)["setupContext"] # nil: none recorded
  #   ctx.ip              # "203.0.113.7", or nil when Touchque has none to show
  #   ctx.location&.city  # "Berlin"
  #   ctx.device&.browser # "Safari"
  #   ctx.requested_at    # "2026-11-16T09:30:00.000Z", ISO 8601 text as Touchque sent it
  #   ctx.far_from_phone  # measured from the caller: this server's address here, not the phone's
  class SetupContext < Hash
    # The "setupContext" of a validate answer (the decoded JSON), or nil when it is missing,
    # null or not an object. Lenient: a field that is missing, null or of the wrong type is nil,
    # and fields Touchque adds later are left out.
    def self.parse(raw)
      return nil unless raw.is_a?(Hash)

      new.update("ip" => text(raw, "ip"), "location" => SetupLocation.parse(raw["location"]),
                 "device" => SetupDevice.parse(raw["device"]), "requestedAt" => text(raw, "requestedAt"),
                 "farFromPhone" => [true, false].include?(raw["farFromPhone"]) ? raw["farFromPhone"] : nil)
    end

    # @api private: raw[key] when it is a String, else nil.
    def self.text(raw, key)
      raw[key].is_a?(String) ? raw[key] : nil
    end

    # The address the QR was asked from, or nil.
    def ip
      self["ip"]
    end

    # Its place (a SetupLocation), or nil.
    def location
      self["location"]
    end

    # The browser that asked (a SetupDevice), or nil.
    def device
      self["device"]
    end

    # When the QR was asked for: ISO 8601 text, or nil.
    def requested_at
      self["requestedAt"]
    end

    # Whether that place is far from whoever called validate_secret (the phone, when the
    # Touchque app asks; your server, when it does): true, false, or nil when Touchque cannot tell.
    def far_from_phone
      self["farFromPhone"]
    end
  end

  # Where a first-time QR was asked from: "city" ("Berlin"), "country" ("Germany") and
  # "countryCode" ("DE"), each a String or nil.
  class SetupLocation < Hash
    # A SetupLocation, or nil when +raw+ is not an object (fields as SetupContext.parse reads them).
    def self.parse(raw)
      return nil unless raw.is_a?(Hash)

      new.update("city" => SetupContext.text(raw, "city"), "country" => SetupContext.text(raw, "country"),
                 "countryCode" => SetupContext.text(raw, "countryCode"))
    end

    def city
      self["city"]
    end

    def country
      self["country"]
    end

    def country_code
      self["countryCode"]
    end
  end

  # The browser that asked for a first-time QR, from its User-Agent: "browser" ("Safari"),
  # "os" ("iOS") and "model" ("iPhone"), each a String or nil.
  class SetupDevice < Hash
    # A SetupDevice, or nil when +raw+ is not an object (fields as SetupContext.parse reads them).
    def self.parse(raw)
      return nil unless raw.is_a?(Hash)

      new.update("browser" => SetupContext.text(raw, "browser"), "os" => SetupContext.text(raw, "os"),
                 "model" => SetupContext.text(raw, "model"))
    end

    def browser
      self["browser"]
    end

    def os
      self["os"]
    end

    def model
      self["model"]
    end
  end
end
