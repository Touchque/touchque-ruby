# frozen_string_literal: true

require "openssl"

module Touchque
  # Key helpers for AI agents (Touchque::Agent): new key pairs and RFC 7638 thumbprints.
  module AgentKeys
    # DER prefixes of the key formats OpenSSL reads (the key bytes follow them).
    ED25519_PKCS8 = ["302e020100300506032b657004220420"].pack("H*")
    ED25519_SPKI = ["302a300506032b6570032100"].pack("H*")
    P256_SPKI = ["3059301306072a8648ce3d020106082a8648ce3d030107034200"].pack("H*")

    module_function

    # A new key pair: ES256 (P-256, default) or EdDSA (Ed25519), kid = the RFC 7638
    # thumbprint. Register "publicJwk"; keep "privateJwk" where the agent runs.
    def generate(alg = "ES256")
      case alg
      when "EdDSA"
        key = OpenSSL::PKey.generate_key("ED25519")
        public_jwk = { "kty" => "OKP", "crv" => "Ed25519", "x" => Util.b64url(key.public_to_der[-32, 32]) }
        d = key.private_to_der[-32, 32]
      when "ES256"
        key = OpenSSL::PKey::EC.generate("prime256v1")
        point = key.public_key.to_octet_string(:uncompressed)
        public_jwk = { "kty" => "EC", "crv" => "P-256", "x" => Util.b64url(point[1, 32]), "y" => Util.b64url(point[33, 32]) }
        d = pad32(key.private_key.to_s(2))
      else
        raise ConfigError, "alg must be ES256 or EdDSA"
      end
      kid = thumbprint(public_jwk)
      {
        "privateJwk" => public_jwk.merge("d" => Util.b64url(d), "kid" => kid, "alg" => alg),
        "publicJwk" => public_jwk.merge("kid" => kid, "alg" => alg)
      }
    end

    # RFC 7638 thumbprint of a P-256 or Ed25519 public key (the default kid).
    def thumbprint(jwk)
      jwk = Util.stringify(jwk)
      canonical = if jwk["kty"] == "EC"
                    "{\"crv\":#{Util.js_string(jwk["crv"])},\"kty\":\"EC\",\"x\":#{Util.js_string(jwk["x"])},\"y\":#{Util.js_string(jwk["y"])}}"
                  else
                    "{\"crv\":#{Util.js_string(jwk["crv"])},\"kty\":#{Util.js_string(jwk["kty"])},\"x\":#{Util.js_string(jwk["x"])}}"
                  end
      Util.b64url(Util.sha256(canonical))
    end

    # base64url SHA-256 of an access token, as a DPoP proof carries it ("ath").
    def access_token_hash(token)
      Util.b64url(Util.sha256(token))
    end

    def pad32(bytes)
      bytes = bytes.b
      bytes.bytesize >= 32 ? bytes : ("\0" * (32 - bytes.bytesize)).b + bytes
    end

    # An EC P-256 public key from its JWK coordinates.
    def ec_public_key(x, y)
      OpenSSL::PKey.read(P256_SPKI + "\x04".b + pad32(Util.b64url_decode(x)) + pad32(Util.b64url_decode(y)))
    end

    # An EC P-256 private key (SEC1 DER) from its JWK parts.
    def ec_private_key(d, x, y)
      der = ["30770201010420"].pack("H*") + pad32(Util.b64url_decode(d)) +
            ["a00a06082a8648ce3d030107a144034200"].pack("H*") + "\x04".b +
            pad32(Util.b64url_decode(x)) + pad32(Util.b64url_decode(y))
      OpenSSL::PKey.read(der)
    end

    def ed25519_private_key(seed)
      OpenSSL::PKey.read(ED25519_PKCS8 + seed.b)
    end

    def ed25519_public_key(raw)
      OpenSSL::PKey.read(ED25519_SPKI + raw.b)
    end

    # An RSA public key from its JWK modulus and exponent.
    def rsa_public_key(n, e)
      int = ->(b64) { OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(Util.b64url_decode(b64), 2)) }
      rsa = OpenSSL::ASN1::Sequence.new([int.call(n), int.call(e)]).to_der
      spki = OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new("rsaEncryption"), OpenSSL::ASN1::Null.new(nil)]),
        OpenSSL::ASN1::BitString.new(rsa)
      ]).to_der
      OpenSSL::PKey.read(spki)
    end

    # JOSE's raw r||s as an ECDSA DER signature.
    def raw_to_der(raw)
      r = OpenSSL::BN.new(raw[0, 32], 2)
      s = OpenSSL::BN.new(raw[32, 32], 2)
      OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Integer.new(r), OpenSSL::ASN1::Integer.new(s)]).to_der
    end

    # An ECDSA DER signature as JOSE's raw r||s (64 bytes).
    def der_to_raw(der)
      seq = OpenSSL::ASN1.decode(der)
      seq.value.map { |i| pad32(i.value.to_s(2)) }.join.b
    end
  end

  # An ES256 or EdDSA private key that signs compact JWS (agent assertions, DPoP proofs).
  class SigningKey
    attr_reader :alg, :public_jwk

    # A JWK (Hash or its JSON text) or an EC P-256 PEM.
    def self.load(key, who)
      jwk = if key.is_a?(Hash)
              Util.stringify(key)
            elsif key.is_a?(String) && key.lstrip.start_with?("{")
              Util.parse_json(key)
            end
      return from_jwk(jwk) if jwk.is_a?(Hash)
      return from_pem(key, who) if key.is_a?(String)

      raise ConfigError, "#{who}: the private key must be a JWK (Hash or JSON) or an EC PEM"
    end

    def self.new_es256
      key = OpenSSL::PKey::EC.generate("prime256v1")
      point = key.public_key.to_octet_string(:uncompressed)
      new("ES256", key, { "kty" => "EC", "crv" => "P-256", "x" => Util.b64url(point[1, 32]), "y" => Util.b64url(point[33, 32]) })
    end

    def self.from_jwk(jwk)
      raise ConfigError, "The agent key must be the PRIVATE key (it has no d)" if jwk["d"].to_s.empty?

      d = Util.b64url_decode(jwk["d"])
      if jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && d.bytesize == 32
        key = AgentKeys.ed25519_private_key(d)
        return new("EdDSA", key, { "kty" => "OKP", "crv" => "Ed25519", "x" => Util.b64url(key.public_to_der[-32, 32]) })
      end
      if jwk["kty"] == "EC" && jwk["crv"] == "P-256" && jwk["x"] && jwk["y"]
        key = AgentKeys.ec_private_key(jwk["d"], jwk["x"], jwk["y"])
        return new("ES256", key, { "kty" => "EC", "crv" => "P-256", "x" => jwk["x"], "y" => jwk["y"] })
      end
      raise ConfigError, "The agent key must be EC P-256 or Ed25519"
    rescue OpenSSL::PKey::PKeyError, ArgumentError
      raise ConfigError, "The agent key could not be read"
    end

    def self.from_pem(pem, who)
      key = OpenSSL::PKey.read(pem)
      raise ConfigError, "An EC agent key must be on P-256" unless key.is_a?(OpenSSL::PKey::EC) && key.group.curve_name == "prime256v1"

      point = key.public_key.to_octet_string(:uncompressed)
      new("ES256", key, { "kty" => "EC", "crv" => "P-256", "x" => Util.b64url(point[1, 32]), "y" => Util.b64url(point[33, 32]) })
    rescue OpenSSL::PKey::PKeyError, ArgumentError
      raise ConfigError, "#{who}: the private key must be a JWK (Hash or JSON) or an EC P-256 PEM"
    end

    def initialize(alg, key, public_jwk)
      @alg = alg
      @key = key
      @public_jwk = public_jwk
    end

    def sign(input)
      return @key.sign(nil, input) if @alg == "EdDSA"

      AgentKeys.der_to_raw(@key.sign(OpenSSL::Digest.new("SHA256"), input))
    end

    # A compact JWS; "alg" is added to the header.
    def jws(header, payload)
      input = "#{Util.b64url(Util.json(header.merge("alg" => @alg)))}.#{Util.b64url(Util.json(payload))}"
      "#{input}.#{Util.b64url(sign(input))}"
    end
  end

  # JWS signature checks for the algorithms Touchque uses.
  module JWS
    module_function

    # [header, claims, signing input, signature] of a compact JWS, or nil.
    def split(token)
      parts = token.to_s.split(".", -1)
      return nil unless parts.length == 3

      header = Util.parse_json(Util.b64url_decode(parts[0]).force_encoding("UTF-8"))
      claims = Util.parse_json(Util.b64url_decode(parts[1]).force_encoding("UTF-8"))
      return nil unless header.is_a?(Hash) && claims.is_a?(Hash)

      [header, claims, "#{parts[0]}.#{parts[1]}", Util.b64url_decode(parts[2])]
    rescue ArgumentError
      nil
    end

    def verify(alg, jwk, input, signature)
      jwk = Util.stringify(jwk)
      case alg
      when "ES256"
        return false unless jwk["kty"] == "EC" && jwk["crv"] == "P-256" && signature.bytesize == 64

        AgentKeys.ec_public_key(jwk["x"], jwk["y"]).verify(OpenSSL::Digest.new("SHA256"), AgentKeys.raw_to_der(signature), input)
      when "RS256"
        return false unless jwk["kty"] == "RSA"

        AgentKeys.rsa_public_key(jwk["n"], jwk["e"]).verify(OpenSSL::Digest.new("SHA256"), signature, input)
      when "EdDSA"
        return false unless jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && signature.bytesize == 64

        raw = Util.b64url_decode(jwk["x"])
        raw.bytesize == 32 && AgentKeys.ed25519_public_key(raw).verify(nil, signature, input)
      else
        false
      end
    rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error, ArgumentError
      false
    end
  end
end
