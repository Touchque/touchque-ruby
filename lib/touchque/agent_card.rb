# frozen_string_literal: true

module Touchque
  # An A2A agent card that did not verify. +error+ is unsigned, malformed,
  # untrusted_key, invalid_signature or keys_unavailable.
  class AgentCardError < Error
    attr_reader :error

    def initialize(error, message)
      @error = error
      super(message)
    end
  end

  # A2A agent card signatures (A2A 1.0 §8.4): before your agent trusts another agent's
  # card (its name, URL, skills), check that whoever controls its keys signed exactly
  # this card. Each entry of +signatures+ is a JWS (RFC 7515) over the card in RFC 8785
  # canonical form without +signatures+; the protected header names alg, kid and
  # optionally jku (where the keys are). Keys come from +keys+ or from the header's
  # jku, but jku is only followed on the card's own host (or a host in
  # +trusted_jku_hosts+): a card that points at keys on a host of its choosing proves
  # nothing. Signers must leave out fields at their default values (A2A §8.4.1); the
  # card is checked as received.
  #
  #   json = Net::HTTP.get(URI("https://agent.example/.well-known/agent-card.json"))
  #   Touchque::AgentCard.verify(json, card_url: "https://agent.example/.well-known/agent-card.json")
  module AgentCard
    ALGS = %w[RS256 ES256 EdDSA].freeze

    module_function

    # A number as ECMAScript's Number::toString writes it (RFC 8785 §3.2.2.3).
    def es_number(value)
      return value.to_s if value.is_a?(Integer)
      raise AgentCardError.new("malformed", "a number is not finite") unless value.finite?
      return "0" if value.zero?

      sign = value.negative? ? "-" : ""
      mantissa, exp = value.abs.to_s.split(/e/i)
      int_part, frac = mantissa.split(".")
      digits = int_part + frac.to_s
      n = int_part.length + exp.to_i
      trimmed = digits.sub(/\A0+/, "")
      n -= digits.length - trimmed.length
      digits = trimmed.sub(/0+\z/, "")
      k = digits.length
      out = if k <= n && n <= 21
              digits + ("0" * (n - k))
            elsif n.positive? && n <= 21
              "#{digits[0, n]}.#{digits[n..]}"
            elsif n > -6 && n <= 0
              "0.#{"0" * -n}#{digits}"
            else
              x = n - 1
              "#{digits[0]}#{k > 1 ? ".#{digits[1..]}" : ""}e#{x >= 0 ? "+" : "-"}#{x.abs}"
            end
      sign + out
    end

    # RFC 8785 (JSON Canonicalization Scheme): sorted keys (UTF-16 order), no whitespace, ECMAScript numbers.
    def canonical_json(value)
      case value
      when nil then "null"
      when true then "true"
      when false then "false"
      when String then Util.js_string(value)
      when Integer, Float then es_number(value)
      when Array then "[#{value.map { |v| canonical_json(v) }.join(",")}]"
      when Hash
        keys = value.keys.map(&:to_s).sort_by { |k| k.encode("UTF-16BE").b }
        h = Util.stringify(value)
        "{#{keys.map { |k| "#{Util.js_string(k)}:#{canonical_json(h[k])}" }.join(",")}}"
      else
        raise AgentCardError.new("malformed", "cannot canonicalize #{value.class}")
      end
    end

    def decode(card)
      c = card.is_a?(String) ? Util.parse_json(card) : Util.stringify(card)
      raise AgentCardError.new("malformed", "the card is not a JSON object") unless c.is_a?(Hash)

      c
    end

    def payload(card)
      Util.b64url(canonical_json(card.reject { |k, _| k == "signatures" }))
    end

    def host_of(url)
      return nil unless url && CrossAppAccess.safe_url?(url)

      u = URI.parse(url)
      u.port == u.default_port ? u.host : "#{u.host}:#{u.port}"
    end

    # Checks the card's signatures: { "kid", "alg", "key_source" => "keys" | "jku" } or AgentCardError.
    def verify(card, card_url: nil, keys: nil, trusted_jku_hosts: [], fetch: nil)
      c = decode(card)
      sigs = c["signatures"]
      raise AgentCardError.new("unsigned", "the card has no signatures") unless sigs.is_a?(Array) && !sigs.empty?

      given = Util.stringify(keys.is_a?(Hash) ? (keys["keys"] || keys[:keys] || []) : (keys || []))
      card_host = host_of(card_url)
      fetch ||= CrossAppAccess.method(:get_json)
      body = payload(c)
      last = AgentCardError.new("invalid_signature", "no signature verifies")
      sigs.each do |s|
        next unless s.is_a?(Hash) && s["protected"].is_a?(String) && s["signature"].is_a?(String)

        head = Util.parse_json(Util.b64url_decode(s["protected"]).force_encoding("UTF-8"))
        next unless head.is_a?(Hash)

        alg = head["alg"]
        next unless ALGS.include?(alg) && head["kid"].is_a?(String) && !head.key?("crit")
        next if head.key?("typ") && head["typ"] != "JOSE"

        jwk = given.find { |k| k["kid"] == head["kid"] }
        source = "keys"
        if jwk.nil? && head["jku"].is_a?(String)
          jku_host = host_of(head["jku"])
          unless jku_host && (jku_host == card_host || Array(trusted_jku_hosts).include?(jku_host))
            last = AgentCardError.new("untrusted_key", "jku #{head["jku"]} is not on the card's host")
            next
          end
          begin
            jwk = (fetch.call(head["jku"])["keys"] || []).find { |k| k["kid"] == head["kid"] }
          rescue StandardError => e
            last = AgentCardError.new("keys_unavailable", "the keys at #{head["jku"]} could not be read: #{e.message}")
            next
          end
          source = "jku"
        end
        if jwk.nil?
          last = AgentCardError.new("untrusted_key", "no trusted key #{head["kid"]}") if last.error == "invalid_signature"
          next
        end
        return { "kid" => head["kid"], "alg" => alg, "key_source" => source } if JWS.verify(alg, jwk, "#{s["protected"]}.#{body}", Util.b64url_decode(s["signature"]))

        last = AgentCardError.new("invalid_signature", "the signature does not match the card")
      rescue ArgumentError
        next
      end
      raise last
    end

    # Signs a card you publish: the card JSON with one more entry in +signatures+.
    # The key is an ES256 or EdDSA private JWK (Hash or JSON) or an EC P-256 PEM.
    def sign(card, private_key, kid:, jku: nil)
      c = decode(card)
      key = SigningKey.load(private_key, "AgentCard.sign")
      header = { "alg" => key.alg, "typ" => "JOSE", "kid" => kid }
      header["jku"] = jku if jku
      protected_header = Util.b64url(Util.json(header))
      sig = key.sign("#{protected_header}.#{payload(c)}")
      c["signatures"] = Array(c["signatures"]) + [{ "protected" => protected_header, "signature" => Util.b64url(sig) }]
      Util.json(c)
    end
  end
end
