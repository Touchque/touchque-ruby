# frozen_string_literal: true

require "json"
require "net/http"
require "strscan"
require "uri"

module Touchque
  # A refused ID-JAG or exchange (Cross App Access). +error+ is the OAuth error: invalid_grant
  # for a bad ID-JAG. From a token endpoint: for any answer but 2xx (a redirect too: it is never
  # followed), the "error" of its JSON body when that is RFC 6749 error characters, else
  # server_error; invalid_response for a 2xx answer that is not what was asked for; and
  # temporarily_unavailable when it could not be reached or its answer read (no +status+;
  # +cause+ is the Touchque::NetworkError, or the error of a body that does not decompress).
  # +status+: the HTTP status of the answer. +dpop_nonce+: the latest valid DPoP-Nonce the
  # token endpoint sent during the call (RFC 9449 section 8): the retry answer's when it has
  # one, else the first answer's; nil when it sent no valid one. For a retry by hand:
  # CrossAppAccess.id_jag_dpop_proof(key, url, nonce: e.dpop_nonce).
  class IdJagError < Error
    attr_reader :error, :status, :dpop_nonce

    def initialize(error, message, status = nil, dpop_nonce: nil)
      @error = error
      @status = status
      @dpop_nonce = dpop_nonce
      super(message)
    end
  end

  # A DPoP key (RFC 9449, P-256) that binds an ID-JAG to its holder; keep it in this process.
  # Make one with Touchque::CrossAppAccess.create_id_jag_dpop_key.
  class IdJagDpopKey
    # +thumbprint+: the RFC 7638 thumbprint, the ID-JAG's cnf.jkt.
    attr_reader :public_jwk, :thumbprint

    def initialize(signing_key)
      @signing_key = signing_key
      @public_jwk = signing_key.public_jwk
      @thumbprint = AgentKeys.thumbprint(@public_jwk)
    end

    # A compact JWS signed with this key ("alg" ES256 is added to the header).
    def jws(header, payload)
      @signing_key.jws(header, payload)
    end

    def inspect
      "#<Touchque::IdJagDpopKey thumbprint=#{@thumbprint}>"
    end
  end

  # Cross App Access: Identity Assertion JWT Authorization Grants (ID-JAG,
  # draft-ietf-oauth-identity-assertion-authz-grant, an open standard). An
  # organization's identity provider (Touchque SSO) decides which of its apps may reach
  # which other service for its members; the app trades a member's ID token for an
  # ID-JAG there, then the ID-JAG for an access token at the other service's
  # authorization server, with no consent screen per member. Your own authorization
  # server takes them with IdJagVerifier.
  #
  #   jag = Touchque::CrossAppAccess.request_id_jag(issuer: "https://sso.touchque.com", client_id: id, client_secret: secret,
  #                                                 id_token: id_token, audience: "https://auth.files.example")
  #   tokens = Touchque::CrossAppAccess.redeem_id_jag(token_endpoint: "https://auth.files.example/token", client_id: "acme",
  #                                                   client_secret: files_secret, assertion: jag["assertion"])
  #
  # Sender-constrained with DPoP (RFC 9449), optional: give the same key to both calls. The
  # ID-JAG is then bound to it (cnf.jkt) and is useless to anyone who copies it without the key.
  # A token endpoint that asks for a nonce (use_dpop_nonce with a valid DPoP-Nonce header) gets
  # the same request once more, with a new proof that carries it. A DPoP-bound access token goes
  # to the resource with a proof for that method and URL that carries the token's hash (ath).
  #
  #   dpop_key = Touchque::CrossAppAccess.create_id_jag_dpop_key
  #   jag = Touchque::CrossAppAccess.request_id_jag(..., dpop_key: dpop_key)   # jag["dpop_bound"]
  #   tokens = Touchque::CrossAppAccess.redeem_id_jag(..., assertion: jag["assertion"], dpop_key: dpop_key)
  #   headers = { "Authorization" => "DPoP #{tokens["access_token"]}",
  #               "DPoP" => Touchque::CrossAppAccess.id_jag_dpop_proof(dpop_key, url, method: "GET", access_token: tokens["access_token"]) }
  module CrossAppAccess
    ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag"
    ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
    TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
    JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

    # RFC 9449 section 8.1: DPoP-Nonce = 1*NQCHAR (printable ASCII except space, " and \).
    NONCE_SYNTAX = /\A[\x21\x23-\x5B\x5D-\x7E]++\z/
    # A proof's method: an RFC 9110 token (1*tchar, section 5.6.2), or nothing, with only ASCII
    # whitespace around it (space, tab, LF, VT, FF, CR; not NUL). Possessive: one pass.
    METHOD_SYNTAX = /\A[\x20\x09-\x0D]*+([!#$%&'*+\-.^_`|~0-9A-Za-z]*+)[\x20\x09-\x0D]*+\z/
    # RFC 6749 section 5.2: an error code is 1*( %x20-21 / %x23-5B / %x5D-7E ); at most 128 here.
    ERROR_SYNTAX = /\A[\x20\x21\x23-\x5B\x5D-\x7E]{1,128}\z/
    # WWW-Authenticate pieces (RFC 9110 section 11.6.1), each matched once where the scanner stands,
    # with possessive quantifiers: they never backtrack, so a long header costs linear time.
    CHALLENGE_SPACE = /[ \t]++/
    CHALLENGE_TOKEN = /[!#$%&'*+\-.^_`|~0-9A-Za-z]++/
    CHALLENGE_QUOTED = /"((?:[^"\\]++|\\.)*+)"/m
    # The rest of a list element that is not read (token68, a malformed piece): up to the next
    # comma outside a quoted string.
    CHALLENGE_REST = /(?:[^",]++|"(?:[^"\\]++|\\.)*+"?)*+/m
    # What a token endpoint's POST raises when no answer came or none could be read: the
    # transport's NetworkError (refused, reset, DNS, timeout, a malformed answer, a body cut
    # short or over 10 MB), or a compressed body that does not decompress.
    UNREADABLE_ANSWER = [NetworkError, *(defined?(Zlib::Error) ? [Zlib::Error] : [])].freeze
    private_constant :NONCE_SYNTAX, :METHOD_SYNTAX, :ERROR_SYNTAX, :CHALLENGE_SPACE, :CHALLENGE_TOKEN, :CHALLENGE_QUOTED,
                     :CHALLENGE_REST, :UNREADABLE_ANSWER

    module_function

    # A fresh DPoP key for request_id_jag and redeem_id_jag.
    def create_id_jag_dpop_key
      IdJagDpopKey.new(SigningKey.new_es256)
    end

    # A DPoP proof (RFC 9449) for one request to +url+ with +key+: a POST to a token endpoint by
    # default. For a call to the resource, give its +method+ (the ASCII whitespace around it
    # trimmed, sent upper-case; empty means POST) and the DPoP-bound +access_token+ it carries
    # (ath, the token's SHA-256); +nonce+: the server's DPoP-Nonce, put in as given (the server
    # judges it). An empty +access_token+ or +nonce+ is left out. The header's jwk is the key's
    # public part only (kty, crv, x, y). htu is +url+ with scheme and host lowercased, the default
    # port dropped, "/" for an empty path, the path as given (dot segments and percent-encoding
    # are not changed), and no userinfo, query or fragment. ConfigError for a URL that is not
    # absolute http(s), a method that is not an HTTP token (RFC 9110) once trimmed, a nonce that
    # is not UTF-8 text, or a key that is not a P-256 key.
    def id_jag_dpop_proof(key, url, method: "POST", access_token: nil, nonce: nil)
      jwk = dpop_jwk(key)
      claims = { "htm" => dpop_htm(method), "htu" => dpop_htu(url), "iat" => Util.now, "jti" => Util.random_hex(16) }
      claims["ath"] = AgentKeys.access_token_hash(access_token.to_s) unless access_token.to_s.empty?
      value = nonce_claim(nonce)
      claims["nonce"] = value if value
      key.jws({ "typ" => "dpop+jwt", "jwk" => jwk }, claims)
    end

    # The proof header's jwk, rebuilt from +key+ as exactly kty, crv, x and y: no other member
    # of whatever key object it is (never d) goes along.
    def dpop_jwk(key)
      pub = key.respond_to?(:public_jwk) && key.respond_to?(:jws) ? Util.stringify(key.public_jwk) : nil
      unless pub.is_a?(Hash) && pub["kty"] == "EC" && pub["crv"] == "P-256" && [pub["x"], pub["y"]].all? { |v| v.is_a?(String) && !v.empty? }
        raise ConfigError, "a DPoP proof needs a P-256 key from Touchque::CrossAppAccess.create_id_jag_dpop_key"
      end

      { "kty" => "EC", "crv" => "P-256", "x" => pub["x"], "y" => pub["y"] }
    end

    # The proof's htm: +method+ without the ASCII whitespace around it (space, tab, LF, VT, FF,
    # CR; NUL and other characters stay, and are not an HTTP token), upper-cased; POST when that
    # leaves nothing.
    def dpop_htm(method)
      token = method.to_s.b[METHOD_SYNTAX, 1]
      raise ConfigError, "a DPoP proof's method must be an HTTP method such as GET or POST: #{method.inspect}" unless token
      return "POST" if token.empty?

      token.upcase.force_encoding(Encoding::UTF_8)
    end

    # A DPoP proof's htu for +url+: scheme://host[:port]/path with scheme and host lowercased,
    # the default port dropped, "/" for an empty path, the path as given (dot segments and
    # percent-encoding are not changed), and no userinfo, query or fragment.
    def dpop_htu(url)
      uri = URI.parse(url.to_s)
      raise URI::InvalidURIError unless %w[http https].include?(uri.scheme.to_s.downcase) && !uri.host.to_s.empty?

      "#{uri.scheme.downcase}://#{uri.host.downcase}#{uri.port == uri.default_port ? "" : ":#{uri.port}"}#{uri.path.empty? ? "/" : uri.path}"
    rescue URI::InvalidURIError, EncodingError
      shown = url.to_s
      raise ConfigError, "a DPoP proof needs an absolute http(s) URL: #{shown.encoding.ascii_compatible? ? shown : shown.inspect}"
    end

    # +value+ as a DPoP nonce (1*NQCHAR, RFC 9449 section 8.1) in UTF-8, or nil when it is not one:
    # the check on a server's DPoP-Nonce header before the SDK retries with it.
    def nonce_value(value)
      bytes = value.to_s.b
      bytes.match?(NONCE_SYNTAX) ? bytes.force_encoding(Encoding::UTF_8) : nil
    end

    # The nonce claim for a +nonce+ the caller gives: as given, not checked against the
    # DPoP-Nonce syntax; nil when empty. It must be UTF-8 text (JSON carries nothing else): a
    # binary String is read as UTF-8, another encoding converted.
    def nonce_claim(nonce)
      text = nonce.to_s
      return nil if text.empty?

      text = begin
        text.encoding == Encoding::BINARY ? text.dup.force_encoding(Encoding::UTF_8) : text.encode(Encoding::UTF_8)
      rescue EncodingError
        nil
      end
      raise ConfigError, "a DPoP nonce must be UTF-8 text" unless text&.valid_encoding?

      text
    end

    # https, or http on this machine (tests).
    def safe_url?(url)
      u = URI.parse(url.to_s)
      u.scheme == "https" || (u.scheme == "http" && %w[localhost 127.0.0.1 ::1 [::1]].include?(u.host))
    rescue URI::InvalidURIError
      false
    end

    def get_json(url)
      status, text, = Transport.call("GET", url, timeout: 5)
      raise "#{url} answered #{status}" if status >= 400

      Util.parse_json(text) || {}
    end

    # The identity provider's OpenID configuration, checked against its issuer.
    def discover(issuer, fetch = method(:get_json))
      meta = fetch.call("#{issuer.chomp("/")}/.well-known/openid-configuration")
      raise ConfigError, "the identity provider's metadata does not match its issuer" unless meta["issuer"] == issuer

      meta
    end

    # A form POST to a token endpoint: the JSON object of its 2xx answer, or IdJagError. With
    # +dpop_key+ every try carries a fresh proof, and a server that asks for a nonce (RFC 9449
    # section 8) gets the same request once more with a proof that carries it; never a third time.
    def post_form(url, fields, basic = nil, dpop_key = nil)
      token_request(url, fields, basic, dpop_key)[0]
    end

    # post_form, also giving the latest valid DPoP-Nonce the server sent: [answer, nonce or nil].
    # The retry happens only for one valid nonce; a missing, empty, invalid or conflicting
    # DPoP-Nonce header leaves the refusal as it is. Only a 2xx answer is a success, and only
    # with a JSON object (else invalid_response); no answer, or none that could be read, on either
    # try is temporarily_unavailable. Every IdJagError raised here carries the latest valid nonce
    # any answer of the call sent.
    def token_request(url, fields, basic, dpop_key)
      raise ConfigError, "#{url} must be an https URL" unless safe_url?(url)

      headers = { "Content-Type" => "application/x-www-form-urlencoded" }
      if basic
        raw = "#{URI.encode_www_form_component(basic[0]).gsub("+", "%20")}:#{URI.encode_www_form_component(basic[1]).gsub("+", "%20")}"
        headers["Authorization"] = "Basic #{[raw].pack("m0")}"
      end
      body = Transport.form(fields)
      nonce = nil
      attempt = lambda do |proof_nonce|
        headers["DPoP"] = id_jag_dpop_proof(dpop_key, url, nonce: proof_nonce) if dpop_key
        status, text, res = begin
          # A body shorter than its Content-Length is an error here, not what arrived.
          Transport.call("POST", url, headers: headers, body: body, timeout: 10, ignore_eof: false)
        rescue *UNREADABLE_ANSWER => e
          # Raised while rescuing, so +cause+ is e.
          raise IdJagError.new("temporarily_unavailable", "#{url} could not be reached or its answer read: #{e.message}", nil,
                               dpop_nonce: nonce)
        end
        nonce = dpop_nonce_of(res) || nonce
        [status, answer_json(text), res]
      end
      status, data, res = attempt.call(nil)
      status, data, = attempt.call(nonce) if dpop_key && nonce && use_dpop_nonce?(status, data, res)
      unless (200..299).cover?(status)
        answer = data.is_a?(Hash) ? data : {}
        raise IdJagError.new(error_code(answer), (answer["error_description"] || "#{url} answered #{status}").to_s, status, dpop_nonce: nonce)
      end
      raise IdJagError.new("invalid_response", "#{url} answered #{status} without a JSON object", status, dpop_nonce: nonce) unless data.is_a?(Hash)

      [data, nonce]
    end

    # A token endpoint's answer body as JSON: the value (any JSON type), or nil when it is not
    # JSON. Bytes that are not UTF-8 read as U+FFFD, so no body raises here.
    def answer_json(text)
      JSON.parse(text.to_s.dup.force_encoding(Encoding::UTF_8).scrub)
    rescue JSON::ParserError
      nil
    end

    # A refusal's OAuth error: the body's "error" when it is 1 to 128 RFC 6749 error characters
    # (printable ASCII except " and \), else server_error. Never taken from WWW-Authenticate.
    def error_code(data)
      code = data["error"]
      code.is_a?(String) && code.b.match?(ERROR_SYNTAX) ? code : "server_error"
    end

    # Every value of the answer's header +name+, one per field line.
    def header_values(res, name)
      res.respond_to?(:get_fields) ? Array(res.get_fields(name)) : []
    end

    # The answer's DPoP-Nonce (RFC 9449 section 8) when it is one valid value: nil when the header
    # is missing, empty, not 1*NQCHAR, or repeated with different values.
    def dpop_nonce_of(res)
      values = header_values(res, "DPoP-Nonce").uniq
      values.length == 1 ? nonce_value(values[0]) : nil
    end

    # Whether a token endpoint's answer asks for a nonce in the proof (RFC 9449 section 8): 400 or
    # 401 with error use_dpop_nonce in its JSON body, or 401 with it in a DPoP challenge.
    def use_dpop_nonce?(status, data, res)
      return false unless [400, 401].include?(status)
      return true if data.is_a?(Hash) && data["error"] == "use_dpop_nonce"

      status == 401 && header_values(res, "WWW-Authenticate").any? { |field| dpop_nonce_challenge?(field) }
    end

    # Whether one WWW-Authenticate field value holds a DPoP challenge with error use_dpop_nonce
    # (RFC 9449 section 9). Challenges and their auth-params as RFC 9110 section 11.6.1 writes
    # them; a parameter belongs to the challenge before it, and a malformed list element is
    # skipped. One pass over the bytes with patterns that never backtrack: linear time, and no
    # exception for any input.
    def dpop_nonce_challenge?(field)
      s = StringScanner.new(field.to_s.b)
      scheme = nil
      after_scheme = false # an auth-scheme and spaces just read: a token68 may follow
      until s.eos?
        next if s.skip(CHALLENGE_SPACE)

        if s.skip(/,/)
          after_scheme = false
          next
        end
        token = s.scan(CHALLENGE_TOKEN)
        unless token
          s.skip(CHALLENGE_REST)
          next
        end
        s.skip(CHALLENGE_SPACE)
        if s.skip(/=/)
          s.skip(CHALLENGE_SPACE)
          value = s.scan(CHALLENGE_QUOTED) ? s[1].gsub(/\\(.)/m, "\\1") : s.scan(CHALLENGE_TOKEN)
          s.skip(CHALLENGE_SPACE)
          if value && (s.eos? || s.check(/,/))
            return true if scheme&.casecmp?("DPoP") && token.casecmp?("error") && value == "use_dpop_nonce"
          else
            s.skip(CHALLENGE_REST)
          end
          after_scheme = false
        elsif after_scheme
          s.skip(CHALLENGE_REST)
          after_scheme = false
        else
          scheme = token
          after_scheme = true
        end
      end
      false
    end

    def scope_text(scope)
      scope.is_a?(Array) ? scope.join(" ") : scope
    end

    # Trades a member's ID token for an ID-JAG at the identity provider (token exchange,
    # client_secret_basic): { "assertion", "expires_in", "scope" }. With +dpop_key+ the ID-JAG is bound
    # to that key (redeem it with the same key) and "dpop_bound" says whether the returned ID-JAG
    # carries its thumbprint. IdJagError when the token endpoint refuses (any status but 2xx),
    # answers no ID-JAG (invalid_response) or cannot be reached (temporarily_unavailable).
    def request_id_jag(client_id:, client_secret:, id_token:, audience:, issuer: nil, token_endpoint: nil, resource: nil, scope: nil,
                       dpop_key: nil)
      unless token_endpoint
        raise ConfigError, "request_id_jag needs issuer or token_endpoint" if issuer.to_s.empty?

        token_endpoint = discover(issuer)["token_endpoint"]
        raise ConfigError, "the identity provider names no token_endpoint" unless token_endpoint.is_a?(String)
      end
      data, nonce = token_request(token_endpoint, {
                                    "grant_type" => TOKEN_EXCHANGE_GRANT, "requested_token_type" => ID_JAG_TOKEN_TYPE,
                                    "subject_token" => id_token, "subject_token_type" => ID_TOKEN_TYPE,
                                    "audience" => audience, "resource" => resource, "scope" => scope_text(scope)
                                  }, [client_id, client_secret], dpop_key)
      unless data["issued_token_type"] == ID_JAG_TOKEN_TYPE && data["access_token"].is_a?(String)
        raise IdJagError.new("invalid_response", "the identity provider did not answer with an ID-JAG", nil, dpop_nonce: nonce)
      end

      out = { "assertion" => data["access_token"], "expires_in" => data["expires_in"], "scope" => data["scope"] }
      if dpop_key
        # An identity provider without DPoP support ignores the proof: say so instead of guessing.
        cnf = JWS.split(data["access_token"])&.[](1)&.[]("cnf")
        out["dpop_bound"] = cnf.is_a?(Hash) && cnf["jkt"].is_a?(String) && cnf["jkt"] == dpop_key.thumbprint
      end
      out
    end

    # Trades an ID-JAG for an access token at the other service's authorization server (jwt-bearer):
    # the JSON object of its 2xx answer. With +dpop_key+ (the key the ID-JAG is bound to) a DPoP
    # proof goes along; the access token is then DPoP-bound too: send it as
    # "Authorization: DPoP <token>" with id_jag_dpop_proof(dpop_key, url, method:, access_token:) on
    # each call. IdJagError as for request_id_jag; a 2xx answer that is not a JSON object is
    # invalid_response.
    def redeem_id_jag(token_endpoint:, client_id:, assertion:, client_secret: nil, resource: nil, scope: nil, dpop_key: nil)
      fields = { "grant_type" => JWT_BEARER_GRANT, "assertion" => assertion, "resource" => resource, "scope" => scope_text(scope) }
      fields["client_id"] = client_id if client_secret.to_s.empty?
      post_form(token_endpoint, fields, client_secret.to_s.empty? ? nil : [client_id, client_secret], dpop_key)
    end

    # Helpers of id_jag_dpop_proof, request_id_jag and redeem_id_jag, not part of the API.
    private_class_method :dpop_jwk, :dpop_htm, :dpop_htu, :nonce_value, :nonce_claim, :token_request, :answer_json, :error_code,
                         :header_values, :dpop_nonce_of, :use_dpop_nonce?, :dpop_nonce_challenge?
  end

  # Your authorization server, taking ID-JAGs from an organization's identity provider:
  # checks the one an authenticated client presents (jwt-bearer grant) and uses it once. Build it
  # once, at boot, not per request: the jtis it took and the identity provider's keys live in it.
  #
  #   verifier = Touchque::IdJagVerifier.new(issuer: "https://sso.touchque.com", audience: "https://auth.files.example")
  #   claims = verifier.verify(params[:assertion], client_id: authenticated_client_id)
  #
  # An authorization server that checks DPoP proofs passes the proof key's thumbprint; a bound
  # ID-JAG without it is refused. Check the proof (typ dpop+jwt, signature, htm, htu, iat, jti,
  # and the nonce when you require one) before verify: verify uses up the ID-JAG's jti.
  #
  #   claims = verifier.verify(params[:assertion], client_id: authenticated_client_id, dpop_jkt: proof_jkt)
  #
  # +first_use+ (a callable jti, exp → true when new) lets several processes share a
  # store such as Redis SET NX; memory in this process by default.
  class IdJagVerifier
    def initialize(issuer:, audience:, jwks_uri: nil, clock_skew: 60, first_use: nil, fetch: nil)
      if issuer.to_s.empty? || audience.to_s.empty?
        raise ConfigError, "IdJagVerifier needs issuer (the identity provider) and audience (your authorization server's issuer)"
      end

      @issuer = issuer
      @audience = audience
      @jwks_uri = jwks_uri
      @skew = clock_skew
      @first_use = first_use || method(:remember_once)
      @fetch = fetch || CrossAppAccess.method(:get_json)
      @keys = {}
      @keys_at = 0
      @tried_at = 0
      @seen = {}
      @lock = Mutex.new
    end

    # The ID-JAG, checked and used once: its claims, or IdJagError (error invalid_grant).
    # +dpop_jkt+: the thumbprint of the DPoP proof you verified on this request, if any; an
    # ID-JAG bound to a key (cnf.jkt) is refused without a matching one.
    def verify(assertion, client_id:, dpop_jkt: nil)
      bad = ->(message) { IdJagError.new("invalid_grant", message) }
      parts = JWS.split(assertion)
      raise bad.call("assertion is not a JWT") unless parts

      head, c, input, sig = parts
      raise bad.call("not an ID-JAG (typ oauth-id-jag+jwt)") unless head["typ"] == "oauth-id-jag+jwt"
      raise bad.call("unsupported signature") unless %w[RS256 ES256 EdDSA].include?(head["alg"]) && head["kid"].is_a?(String)

      key = begin
        key_for(head["kid"])
      rescue StandardError => e
        raise IdJagError.new("temporarily_unavailable", "the identity provider's keys could not be read: #{e.message}")
      end
      raise bad.call("signature does not verify") unless key && JWS.verify(head["alg"], key, input, sig)

      now = Util.now
      auds = c["aud"].is_a?(Array) ? c["aud"] : [c["aud"]]
      raise bad.call("another issuer") unless c["iss"] == @issuer
      raise bad.call("not for this authorization server") unless auds.length == 1 && auds[0] == @audience
      raise bad.call("issued to another client") unless c["client_id"].is_a?(String) && c["client_id"] == client_id
      raise bad.call("expired") unless c["exp"].is_a?(Numeric) && c["exp"] + @skew >= now
      raise bad.call("issued in the future") unless c["iat"].is_a?(Numeric) && c["iat"] - @skew <= now
      raise bad.call("sub and jti are required") unless c["sub"].is_a?(String) && c["jti"].is_a?(String)
      # Before the jti is spent: a copy without the key cannot use the ID-JAG up.
      cnf_jkt = nil
      if c.key?("cnf")
        cnf = c["cnf"]
        raise bad.call("unsupported confirmation method (only DPoP cnf.jkt)") unless cnf.is_a?(Hash) && cnf["jkt"].is_a?(String)
        raise bad.call("bound to a DPoP key: a DPoP proof with that key is required") if dpop_jkt.to_s.empty?
        raise bad.call("the DPoP proof was made with another key") unless dpop_jkt == cnf["jkt"]

        cnf_jkt = cnf["jkt"]
      end
      raise bad.call("already used") unless @first_use.call(c["jti"], c["exp"].to_i)

      {
        "iss" => c["iss"], "sub" => c["sub"], "aud" => auds[0], "client_id" => c["client_id"], "jti" => c["jti"],
        "issued_at" => c["iat"].to_i, "expires_at" => c["exp"].to_i,
        "scopes" => c["scope"].is_a?(String) && !c["scope"].empty? ? c["scope"].split(" ") : [],
        "resource" => c["resource"], "tenant" => c["tenant"], "email" => c["email"], "auth_time" => c["auth_time"], "amr" => c["amr"],
        "cnf_jkt" => cnf_jkt, "claims" => c
      }
    end

    private

    def remember_once(jti, exp)
      @lock.synchronize do
        now = Util.now
        @seen.delete_if { |_, until_at| until_at < now }
        return false if @seen.key?(jti)

        @seen[jti] = exp + @skew
        true
      end
    end

    def load_keys
      unless @jwks_uri
        @jwks_uri = CrossAppAccess.discover(@issuer, @fetch)["jwks_uri"]
        raise "the identity provider names no jwks_uri" unless @jwks_uri.is_a?(String)
      end
      @keys = (@fetch.call(@jwks_uri)["keys"] || []).each_with_object({}) { |k, h| h[k["kid"]] = k if k["kid"] }
      @keys_at = Util.now
    end

    def key_for(kid)
      @lock.synchronize do
        load_keys if @keys_at.zero? || Util.now - @keys_at > 600
        if !@keys.key?(kid) && Util.now - @tried_at > 60
          @tried_at = Util.now
          load_keys
        end
        @keys[kid]
      end
    end
  end
end
