# frozen_string_literal: true

module TouchQue
  # Transaction details the way the API normalizes and digests them.
  module Details
    # What JavaScript's trim removes, as the API trims: ASCII and Unicode spaces (U+00A0,
    # U+202F...), line separators and the BOM. String#strip knows only the ASCII ones.
    SPACE = "[\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]"
    TRIM = /\A#{SPACE}+|#{SPACE}+\z/

    module_function

    # A Hash ({"Amount" => "250 EUR"}) or a list of {label:, value:} as
    # [{"label", "value"}] with trimmed strings.
    def normalize(details)
      return [] if details.nil? || details.empty?

      pairs = if details.is_a?(Hash)
                details.map { |label, value| [label.to_s, value.to_s] }
              else
                details.map do |d|
                  d = Util.stringify(d)
                  [d["label"].to_s, d["value"].to_s]
                end
              end
      pairs.map { |label, value| { "label" => trim(label), "value" => trim(value) } }
    end

    def trim(text)
      text.ascii_only? || text.encoding == Encoding::UTF_8 ? text.gsub(TRIM, "") : text.strip
    end

    # SHA-256 (hex) over the normalized details joined as label US value RS label...;
    # "" for no details. The phone signs this digest (ApprovalProof).
    def digest(details)
      pairs = normalize(details)
      return "" if pairs.empty?

      Util.sha256_hex(pairs.map { |p| "#{p["label"]}\u001f#{p["value"]}" }.join("\u001e"))
    end
  end

  # Verifies the device-signed proof of an approval ("what you see is what you sign").
  # When the phone holds a hardware key (Secure Enclave / Android Keystore), every
  # approval is signed over the request id, the action type, the number-match code and
  # a digest of the details the user was shown. The proof arrives in the SUCCESS webhook
  # ("approvalProof") and in the consumed approval. Verifying it does not require
  # trusting TouchQue.
  module ApprovalProof
    PREFIX = "touchque-approve:v2"

    module_function

    # True only if +proof+ was signed by the device key over exactly the request, action
    # type, challenge code and details you expect. Pin the device with
    # +expected_public_key+ (the base64 key you stored for this user), or pass
    # allow_unpinned_key: true for trust on first use. Never raises.
    def verify(proof, request_id:, type:, details: nil, challenge_code: nil, expected_public_key: nil, allow_unpinned_key: false)
      return false unless proof.is_a?(Hash)

      proof = Util.stringify(proof)
      return false unless proof["version"] == "v2" && proof["algorithm"] == "ECDSA-P256-SHA256"

      public_key = proof["publicKey"]
      message = proof["message"]
      signature = proof["signature"]
      return false unless [public_key, message, signature].all?(String)

      if expected_public_key && !expected_public_key.empty?
        return false unless Util.secure_compare(expected_public_key, public_key)
      elsif allow_unpinned_key != true
        return false
      end
      expected = [PREFIX, request_id.to_s, type.to_s, challenge_code.to_s, Details.digest(details)].join("\n")
      return false unless Util.secure_compare(expected, message)

      raw = public_key.unpack1("m0")
      return false unless raw.bytesize == 65 && raw.getbyte(0) == 4

      sig = signature.unpack1("m0")
      return false if sig.empty?

      key = OpenSSL::PKey.read(AgentKeys::P256_SPKI + raw)
      key.verify(OpenSSL::Digest.new("SHA256"), sig, message)
    rescue StandardError
      false
    end
  end

  # What a partner's server checks before executing what an AI agent asked for: the
  # approval token's claims match the transaction (person, action type, authorization
  # details) and, offline, its ES256 signature against TouchQue's keys
  # (GET /agents/jwks.json). Amounts compare as decimals ("500" = "500.00"), IBANs
  # without spaces in any case, currencies in any case; a Hash matches a token with
  # exactly one entry, an Array matches entry by entry.
  module ApprovalToken
    module_function

    # {"header", "claims"} WITHOUT checking the signature.
    def decode(token)
      parts = JWS.split(token)
      raise ApprovalMismatchError, "not an approval token" unless parts

      { "header" => parts[0], "claims" => parts[1] }
    end

    # Does +details+ (a token's authorization_details) say what +expected+ says?
    def matches?(details, expected)
      return false unless details.is_a?(Array)

      expected = Util.stringify(expected)
      if expected.is_a?(Array)
        return false unless details.length == expected.length

        return expected.each_with_index.all? { |e, i| partial(details[i], e) }
      end
      details.length == 1 && partial(details[0], expected)
    end

    # Raises ApprovalMismatchError unless the claims say what you expect.
    def assert_matches!(claims, user: nil, type: nil, authorization_details: nil)
      if user && claims["sub"] != user
        raise ApprovalMismatchError, "the approval is for another person"
      end
      if type && claims["type"] != type
        raise ApprovalMismatchError, "the approval is for another action type (#{claims["type"]})"
      end
      if authorization_details && !matches?(claims["authorization_details"], authorization_details)
        raise ApprovalMismatchError, "the approved details differ from what you are about to execute"
      end

      true
    end

    # Verifies an approval token offline: typ touchque-approval+jwt, ES256 by a key of
    # +jwks+, not expired (30 s leeway), aud equal to +audience+, then the expectation.
    # +audience+ is required: /agents/jwks.json is one key set for every Touchque
    # workspace, so without it a token Touchque signed for another workspace would pass.
    # Pass your own (tq.agents.approval_audience, touchque:workspace:<id>), or use
    # tq.agents.verify_approval_token, which fills it in.
    # Does NOT make it single-use: agents.redeem_approval does.
    def verify_with(token, jwks, audience: nil, user: nil, type: nil, authorization_details: nil, now: nil)
      if !audience.is_a?(String) || audience.empty?
        raise ApprovalMismatchError, "audience is required: your workspace's touchque:workspace:<id> (tq.agents.approval_audience)"
      end
      parts = JWS.split(token)
      raise ApprovalMismatchError, "not an approval token" unless parts

      header, claims, input, sig = parts
      unless header["typ"] == "touchque-approval+jwt" && header["alg"] == "ES256"
        raise ApprovalMismatchError, "not an approval token (typ/alg)"
      end

      jwk = (Util.stringify(jwks)["keys"] || []).reverse.find do |k|
        k["kid"] == header["kid"] && k["kty"] == "EC" && k["crv"] == "P-256"
      end
      raise ApprovalMismatchError, "signed by an unknown key" unless jwk
      raise ApprovalMismatchError, "the signature does not verify" unless JWS.verify("ES256", jwk, input, sig)

      exp = claims["exp"]
      raise ApprovalMismatchError, "the approval token expired" unless exp.is_a?(Numeric) && exp + 30 >= (now || Util.now)
      aud = claims["aud"]
      raise ApprovalMismatchError, "the approval token names no workspace" if !aud.is_a?(String) || aud.empty?
      raise ApprovalMismatchError, "the approval token is for another workspace" if aud != audience

      assert_matches!(claims, user: user, type: type, authorization_details: authorization_details)
      claims
    end

    def decimal(value)
      text = value.to_s.strip
      return nil unless text.match?(/\A\d+(\.\d+)?\z/)

      whole, frac = text.split(".", 2)
      whole = whole.sub(/\A0+/, "")
      whole = "0" if whole.empty?
      frac = (frac || "").sub(/0+\z/, "")
      frac.empty? ? whole : "#{whole}.#{frac}"
    end

    def same(key, actual, expected)
      return partial(actual, expected) if expected.is_a?(Hash) || expected.is_a?(Array)

      case key
      when "amount"
        !decimal(actual).nil? && decimal(actual) == decimal(expected)
      when "iban", "currency"
        actual.is_a?(String) && actual.gsub(/\s+/, "").upcase == expected.to_s.gsub(/\s+/, "").upcase
      else
        scalar_equal(actual, expected)
      end
    end

    def partial(actual, expected)
      if expected.is_a?(Array)
        return false unless actual.is_a?(Array) && actual.length == expected.length

        return expected.each_with_index.all? do |e, i|
          e.is_a?(Hash) || e.is_a?(Array) ? partial(actual[i], e) : scalar_equal(actual[i], e)
        end
      end
      return scalar_equal(actual, expected) unless expected.is_a?(Hash)
      return false unless actual.is_a?(Hash)

      expected.all? { |k, v| actual.key?(k) && same(k, actual[k], v) }
    end

    def scalar_equal(a, b)
      return a == b unless a.is_a?(Numeric) && b.is_a?(Numeric)

      a.to_r == b.to_r
    end
  end
end
