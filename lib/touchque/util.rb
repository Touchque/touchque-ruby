# frozen_string_literal: true

require "json"
require "openssl"
require "securerandom"
require "uri"

module Touchque
  # Small helpers shared by the SDK (no third-party gems).
  module Util
    module_function

    def b64url(bytes)
      [bytes].pack("m0").tr("+/", "-_").delete("=")
    end

    def b64url_decode(text)
      s = text.to_s.tr("-_", "+/")
      s += "=" * ((4 - s.length % 4) % 4)
      s.unpack1("m0")
    rescue ArgumentError
      raise ArgumentError, "malformed base64url"
    end

    def b64_decode(text)
      text.to_s.unpack1("m0")
    end

    def sha256(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def sha256_hex(data)
      OpenSSL::Digest::SHA256.hexdigest(data)
    end

    def hmac_hex(key, data)
      OpenSSL::HMAC.hexdigest("SHA256", key, data)
    end

    def hmac(key, data)
      OpenSSL::HMAC.digest("SHA256", key, data)
    end

    # Constant-time string comparison.
    def secure_compare(a, b)
      a = a.to_s.b
      b = b.to_s.b
      return false unless a.bytesize == b.bytesize

      OpenSSL.fixed_length_secure_compare(a, b)
    end

    def random_hex(bytes = 16)
      SecureRandom.hex(bytes)
    end

    # A path segment, percent-encoded (encodeURIComponent / rawurlencode).
    def seg(value)
      URI.encode_www_form_component(value.to_s).gsub("+", "%20")
    end

    # JSON text, compact, non-ASCII kept as is (like JSON.stringify).
    def json(value)
      JSON.generate(value)
    end

    def parse_json(text)
      return nil if text.nil? || text.strip.empty?

      JSON.parse(text)
    rescue JSON::ParserError
      nil
    end

    # Keys as strings, deeply (symbol keys from Ruby callers become the API's names).
    def stringify(value)
      case value
      when Hash then value.each_with_object({}) { |(k, v), h| h[k.to_s] = stringify(v) }
      when Array then value.map { |v| stringify(v) }
      when Symbol then value.to_s
      else value
      end
    end

    # A deep copy of JSON-like data: Hashes, Arrays and Strings copied, anything else as it is.
    def deep_copy(value)
      case value
      when Hash then value.to_h { |k, v| [k, deep_copy(v)] }
      when Array then value.map { |v| deep_copy(v) }
      when String then value.dup
      else value
      end
    end

    # A hash without nil values (and, for strings, without empty ones).
    def compact(hash)
      hash.reject { |_, v| v.nil? || (v.is_a?(String) && v.empty?) }
    end

    # The bytes JSON.stringify would write for a string (quotes included).
    def js_string(str)
      out = +'"'
      str.to_s.each_char do |c|
        out << case c
               when '"' then '\\"'
               when "\\" then "\\\\"
               when "\b" then "\\b"
               when "\f" then "\\f"
               when "\n" then "\\n"
               when "\r" then "\\r"
               when "\t" then "\\t"
               else
                 c.ord < 0x20 ? format("\\u%04x", c.ord) : c
               end
      end
      out << '"'
    end

    # JSON text without insignificant whitespace; strings and numbers kept byte for byte.
    def compact_json(text)
      out = +""
      in_string = false
      escaped = false
      text.each_char do |c|
        if in_string
          out << c
          if escaped
            escaped = false
          elsif c == "\\"
            escaped = true
          elsif c == '"'
            in_string = false
          end
        elsif c == '"'
          in_string = true
          out << c
        elsif !" \t\n\r".include?(c)
          out << c
        end
      end
      out
    end

    # The members of a top-level JSON object as [key, raw value text] pairs, in order.
    def top_level_members(text)
      s = text.strip
      raise JSON::ParserError, "not an object" unless s.start_with?("{")

      members = []
      i = 1
      loop do
        i = skip_ws(s, i)
        break if s[i] == "}"

        key_end = scan_string(s, i)
        key = JSON.parse("[#{s[i...key_end]}]")[0]
        i = skip_ws(s, key_end)
        raise JSON::ParserError, "expected :" unless s[i] == ":"

        i = skip_ws(s, i + 1)
        value_end = scan_value(s, i)
        members << [key, s[i...value_end]]
        i = skip_ws(s, value_end)
        if s[i] == ","
          i += 1
        elsif s[i] == "}"
          break
        else
          raise JSON::ParserError, "expected , or }"
        end
      end
      members
    end

    def skip_ws(s, i)
      i += 1 while i < s.length && " \t\n\r".include?(s[i])
      i
    end

    def scan_string(s, i)
      raise JSON::ParserError, "expected a string" unless s[i] == '"'

      i += 1
      while i < s.length
        case s[i]
        when "\\" then i += 2
        when '"' then return i + 1
        else i += 1
        end
      end
      raise JSON::ParserError, "unterminated string"
    end

    def scan_value(s, i)
      case s[i]
      when '"' then scan_string(s, i)
      when "{", "["
        depth = 0
        while i < s.length
          case s[i]
          when '"'
            i = scan_string(s, i)
            next
          when "{", "[" then depth += 1
          when "}", "]"
            depth -= 1
            return i + 1 if depth.zero?
          end
          i += 1
        end
        raise JSON::ParserError, "unterminated value"
      else
        j = i
        j += 1 while j < s.length && !",}".include?(s[j])
        j -= 1 while j > i && " \t\n\r".include?(s[j - 1])
        j
      end
    end

    # True for https, and for plaintext http only on this machine (localhost, 127.0.0.1,
    # ::1, *.localhost: local development).
    def https_or_loopback?(url)
      uri = URI.parse(url.to_s)
      return true if uri.scheme == "https"

      host = uri.hostname.to_s.downcase
      uri.scheme == "http" && (%w[localhost 127.0.0.1 ::1].include?(host) || host.end_with?(".localhost"))
    rescue URI::InvalidURIError
      false
    end

    # Allow plaintext http only for localhost / loopback (local development).
    def assert_safe_url!(url, name)
      uri = URI.parse(url.to_s)
      return if uri.scheme == "https"

      if uri.scheme == "http"
        return if %w[localhost 127.0.0.1 ::1 [::1]].include?(uri.host.to_s.downcase)

        raise ConfigError, "Refusing a plaintext http:// #{name} for \"#{uri.host}\". The API key and request signature would be sent in the clear: use https://."
      end
      raise ConfigError, "#{name} must be http(s): #{url}"
    rescue URI::InvalidURIError
      raise ConfigError, "#{name} is not a valid URL: #{url}"
    end

    def now
      Time.now.to_i
    end

    def now_ms
      (Time.now.to_f * 1000).to_i
    end

    # Unix seconds of an ISO 8601 timestamp, or nil.
    def parse_time(value)
      return nil unless value.is_a?(String) && !value.empty?

      require "time"
      Time.iso8601(value).to_f
    rescue ArgumentError
      begin
        Time.parse(value).to_f
      rescue ArgumentError
        nil
      end
    end
  end
end
