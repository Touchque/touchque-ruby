# frozen_string_literal: true

require "net/http"
require "openssl"
require "uri"

module TouchQue
  # Every partner API call: signed with HMAC-SHA256 over
  # "METHOD:pathWithQuery:timestamp:nonce:sha256(body)", sent once, never redirected.
  class HTTP
    MAX_RESPONSE_BYTES = 10 * 1024 * 1024
    # What a request that never got a usable answer raises (every Errno, a garbled
    # answer, TLS): NetworkError for the caller.
    NETWORK_ERRORS = [Timeout::Error, SystemCallError, SocketError, OpenSSL::SSL::SSLError, IOError,
                      Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].freeze

    attr_reader :base_url, :api_secret

    def initialize(api_key:, api_secret:, base_url:, timeout:)
      @api_key = api_key
      @api_secret = api_secret
      @base_url = base_url
      @timeout = timeout
      @uri = URI.parse(base_url)
    end

    # Never shows the API key or secret (logs, consoles, error reporters).
    def inspect
      "#<#{self.class.name} base_url=#{@base_url.inspect}>"
    end

    def get(path, params = nil)
      send_request("GET", path + self.class.build_query(params), nil)
    end

    def post(path, body = {})
      send_request("POST", path, body || {})
    end

    def put(path, body = {})
      send_request("PUT", path, body || {})
    end

    def patch(path, body = {})
      send_request("PATCH", path, body || {})
    end

    def delete(path)
      send_request("DELETE", path, nil)
    end

    # A signed GET whose answer is returned as text (an export file).
    def get_text(path)
      send_request("GET", path, nil, raw: true)
    end

    # Deterministic query string: keys sorted, values URL-encoded, "?"-prefixed (or "").
    def self.build_query(params)
      return "" if params.nil?

      pairs = params.map { |k, v| [k.to_s, v] }.reject { |_, v| v.nil? }.sort_by(&:first)
      return "" if pairs.empty?

      "?" + pairs.map { |k, v| "#{Util.seg(k)}=#{Util.seg(v.to_s)}" }.join("&")
    end

    def self.sign(secret, method, path_with_query, body, timestamp, nonce)
      message = "#{method.upcase}:#{path_with_query}:#{timestamp}:#{nonce}:#{Util.sha256_hex(body)}"
      Util.hmac_hex(secret, message)
    end

    private

    def send_request(method, path_with_query, body, raw: false)
      body_text = body.nil? ? "" : Util.json(Util.stringify(body))
      timestamp = Util.now_ms.to_s
      nonce = Util.random_hex(16)
      klass = { "GET" => Net::HTTP::Get, "POST" => Net::HTTP::Post, "PUT" => Net::HTTP::Put,
                "PATCH" => Net::HTTP::Patch, "DELETE" => Net::HTTP::Delete }.fetch(method)
      req = klass.new(@uri.path.chomp("/") + path_with_query)
      req["x-api-key"] = @api_key
      req["x-signature"] = self.class.sign(@api_secret, method, path_with_query, body_text, timestamp, nonce)
      req["x-timestamp"] = timestamp
      req["x-nonce"] = nonce
      req["Accept"] = "application/json"
      req["User-Agent"] = "touchque-ruby-sdk/#{VERSION}"
      unless body.nil?
        req["Content-Type"] = "application/json"
        req.body = body_text
      end
      res = perform(req)
      text = res.body.to_s.dup.force_encoding("UTF-8")
      status = res.code.to_i
      return text if raw && status < 300

      data = Util.parse_json(text)
      if status >= 300
        data = {} unless data.is_a?(Hash)
        if data["retryAfter"].nil? && res["Retry-After"].to_s.match?(/\A\d+\z/)
          data["retryAfter"] = res["Retry-After"].to_i
        end
        if status < 400
          # An API endpoint never redirects; one that does is not TouchQue's.
          raise APIError.new(status, data, "TouchQue: unexpected redirect (HTTP #{status}); redirects are never followed.")
        end
        raise APIError.for(status, data)
      end
      data.nil? ? {} : data
    end

    def perform(req)
      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = @uri.scheme == "https"
      http.open_timeout = @timeout
      http.read_timeout = @timeout
      http.write_timeout = @timeout if http.respond_to?(:write_timeout=)
      res = http.request(req)
      if res["Content-Length"].to_i > MAX_RESPONSE_BYTES || res.body.to_s.bytesize > MAX_RESPONSE_BYTES
        raise NetworkError, "the answer is larger than 10 MB"
      end

      res
    rescue *NETWORK_ERRORS => e
      raise NetworkError, e.message
    end
  end
end
