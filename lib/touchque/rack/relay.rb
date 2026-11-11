# frozen_string_literal: true

require "rack"

module Touchque
  module Rack
    # The relay as a Rack app: mount it wherever your frontend (@touchque/web) expects it.
    #
    #   # Rails, config/routes.rb
    #   mount Touchque::Rack::Relay.new(
    #     get_user_id: ->(req) { req.session["user_email"] },
    #     get_login_user: ->(req) { req.session["password_verified_user"] },
    #     on_authenticated: ->(req, response, info) { req.session["user_email"] = info["externalUsername"] }
    #   ) => "/touchque"
    #
    #   # Sinatra / plain Rack
    #   map("/touchque") { run Touchque::Rack::Relay.new(get_user_id: ->(req) { req.session["user"] }) }
    #
    # The callbacks get the Rack::Request (its session is the app's session). The client IP
    # is Rack::Request#ip: configure trusted proxies when you run behind a load balancer.
    # See Touchque::RelayHandler for the routes and options.
    class Relay
      MAX_BODY_BYTES = 64 * 1024

      def initialize(client: nil, **options)
        @client = client
        @options = options
        @handler = nil
        @lock = Mutex.new
      end

      def call(env)
        req = ::Rack::Request.new(env)
        body = {}
        if req.post? && req.media_type == "application/json"
          raw = req.body&.read(MAX_BODY_BYTES + 1).to_s
          return json(413, { "error" => "body_too_large" }) if raw.bytesize > MAX_BODY_BYTES

          parsed = raw.empty? ? {} : Util.parse_json(raw)
          return json(400, { "error" => "invalid_json" }) if parsed.nil?

          body = parsed.is_a?(Hash) ? parsed : {}
        end
        res = handler.handle(
          method: req.request_method, path: req.path_info, body: body, ip: req.ip.to_s, user_agent: req.user_agent,
          header: ->(name) { env["HTTP_#{name.upcase.tr("-", "_")}"] }, request: req
        )
        return json(404, { "error" => "not_found" }) unless res

        headers = {}
        res.headers.each do |(name, value)|
          key = name.downcase
          headers[key] = headers.key?(key) ? join(headers[key], value) : value
        end
        json(res.status, res.body, headers)
      end

      private

      # Built on the first request, so Touchque.client can be configured after the routes load.
      def handler
        @handler || @lock.synchronize { @handler ||= RelayHandler.new(@client || Touchque.client, **@options) }
      end

      def join(previous, value)
        # Rack 3 takes several values as an Array; Rack 2 as lines.
        ::Rack.release.to_f >= 3 ? Array(previous) + [value] : "#{previous}\n#{value}"
      end

      def json(status, body, headers = {})
        [status, { "content-type" => "application/json; charset=utf-8" }.merge(headers), [Util.json(body)]]
      end
    end
  end
end
