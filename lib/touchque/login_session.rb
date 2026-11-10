# frozen_string_literal: true

module TouchQue
  # Encrypted cookies for apps that use TouchQue Login without a session store: the
  # sign-in in progress (state, nonce, PKCE verifier, where to go back) and the
  # signed-in session (user claims, tokens). AES-256-GCM with a key derived from your
  # secret; values too big for one cookie are split across several (name.0, name.1...).
  # The same format as the Node SDK's sealSession, so both can read each other's cookies.
  module LoginSession
    CHUNK = 3800
    MAX_CHUNKS = 5

    module_function

    def key_of(secret, purpose)
      raise Error, "The cookie secret must be at least 32 characters" unless secret.is_a?(String) && secret.length >= 32

      Util.sha256("touchque-login:#{purpose}:#{secret}")
    end

    def seal(value, secret, purpose, max_age_seconds)
      cipher = OpenSSL::Cipher.new("aes-256-gcm").encrypt
      cipher.key = key_of(secret, purpose)
      iv = cipher.random_iv
      cipher.auth_data = ""
      enc = cipher.update(Util.json({ "v" => value, "exp" => Util.now + max_age_seconds })) + cipher.final
      Util.b64url(iv + cipher.auth_tag + enc)
    end

    # The value, or nil when it is missing, tampered with or expired.
    def unseal(sealed, secret, purpose)
      return nil if sealed.nil? || sealed.empty?

      raw = Util.b64url_decode(sealed)
      return nil if raw.bytesize < 28

      decipher = OpenSSL::Cipher.new("aes-256-gcm").decrypt
      decipher.key = key_of(secret, purpose)
      decipher.iv = raw[0, 12]
      decipher.auth_tag = raw[12, 16]
      decipher.auth_data = ""
      body = Util.parse_json((decipher.update(raw[28..]) + decipher.final).force_encoding("UTF-8"))
      return nil unless body.is_a?(Hash) && body["exp"].is_a?(Numeric) && body["exp"] >= Util.now

      body["v"]
    rescue OpenSSL::Cipher::CipherError, ArgumentError
      nil
    end

    # Cookie name => value pairs storing +sealed+ under +name+ (split when long); nil
    # values delete. +existing+: the names of the cookies the browser sent.
    def cookie_values(name, sealed, existing)
      old = existing.select { |k| k == name || k.start_with?("#{name}.") }
      return old.to_h { |k| [k, nil] } if sealed.nil?
      return { name => sealed }.merge((old - [name]).to_h { |k| [k, nil] }) if sealed.length <= CHUNK

      chunks = (sealed.length.to_f / CHUNK).ceil
      raise Error, "The session is too large for cookies" if chunks > MAX_CHUNKS

      out = (0...chunks).to_h { |i| ["#{name}.#{i}", sealed[i * CHUNK, CHUNK]] }
      (old - out.keys).each { |k| out[k] = nil }
      out
    end

    # The sealed value stored under +name+, joined back from its chunks.
    def read(name, cookies)
      return cookies[name] if cookies[name] && !cookies[name].empty?

      joined = +""
      MAX_CHUNKS.times do |i|
        part = cookies["#{name}.#{i}"]
        break if part.nil? || part.empty?

        joined << part
      end
      joined.empty? ? nil : joined
    end

    # A path inside this app to return to after sign-in (never another site).
    def safe_return_to(value, fallback = "/")
      return fallback unless value.is_a?(String) && value.start_with?("/") && !value.start_with?("//", "/\\") && value.length <= 2000

      value
    end
  end
end
