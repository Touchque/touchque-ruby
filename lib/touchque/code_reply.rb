# frozen_string_literal: true

require "openssl"

module TouchQue
  # A code the person types back on the phone (tq.login.request(..., reply: {...})): a sign-in
  # code another service sent them (a text message, WhatsApp, e-mail). Each request gets a
  # one-time P-256 key pair; its public key goes with the request, the phone encrypts what was
  # typed to it, and only you can open it: TouchQue stores and hands back nothing but the
  # ciphertext (tq.login.status(request_id)["reply"]["ct"]).
  #
  # ECDH P-256, HKDF-SHA256 (salt: the request id, info "touchque-code-reply-v1"), AES-256-GCM
  # (additional data "touchque-code-reply:<request id>"), as
  # "v1.<the phone's one-time key, x9.63>.<nonce|ciphertext|tag>", base64url.
  module CodeReply
    INFO = "touchque-code-reply-v1"
    CT_RE = /\Av1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\z/
    CODE_RE = /\A[A-Za-z0-9 -]{4,20}\z/

    module_function

    # A one-time key pair for one request: send "publicKey" (the uncompressed P-256 point,
    # base64url) as reply[:key], keep "privateKey" (PKCS#8 DER, base64url) server-side.
    def new_key
      key = OpenSSL::PKey::EC.generate("prime256v1")
      { "publicKey" => Util.b64url(key.public_key.to_bn(:uncompressed).to_s(2)), "privateKey" => Util.b64url(key.private_to_der) }
    end

    # The code the person typed, or nil when ct does not open with this key for this request.
    def open(private_key, request_id, ct)
      m = CT_RE.match(ct.to_s)
      return nil unless m

      epk = Util.b64url_decode(m[1])
      box = Util.b64url_decode(m[2])
      return nil unless epk.bytesize == 65 && epk.getbyte(0) == 4 && box.bytesize >= 12 + 16 + 1

      priv = OpenSSL::PKey.read(Util.b64url_decode(private_key))
      peer = OpenSSL::PKey::EC::Point.new(priv.group, OpenSSL::BN.new(epk, 2))
      shared = priv.dh_compute_key(peer)
      key = OpenSSL::KDF.hkdf(shared, salt: request_id.to_s, info: INFO, length: 32, hash: "SHA256")
      d = OpenSSL::Cipher.new("aes-256-gcm").decrypt
      d.key = key
      d.iv = box.byteslice(0, 12)
      d.auth_tag = box.byteslice(box.bytesize - 16, 16)
      d.auth_data = "touchque-code-reply:#{request_id}"
      code = (d.update(box.byteslice(12, box.bytesize - 28)) + d.final).force_encoding("UTF-8").strip
      CODE_RE.match?(code) ? code : nil
    rescue OpenSSL::OpenSSLError, ArgumentError, EncodingError
      nil
    end
  end
end
