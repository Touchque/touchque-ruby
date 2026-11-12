# frozen_string_literal: true

module Touchque
  module Rails
    # One line per protected action:
    #
    #   class TransfersController < ApplicationController
    #     include Touchque::Rails::Guard
    #     require_touchque "SEND_MONEY", only: :create,
    #                      details: -> { { "Amount" => params.require(:amount), "To" => params.require(:to) } }
    #
    #     def create
    #       touchque_approval # the approval, once the user approved on their phone
    #     end
    #   end
    #
    # Until the user approves this answers 202 {"touchque": step, "token": "..."}; your page
    # shows the step and sends the same request again with header X-Touchque-Token (the
    # @touchque/web loop). Once approved the action runs ONCE. Refusals answer 403 / 408 /
    # 423 / 429 with Retry-After. Options: user: (default: current_user's email, id or
    # username; for your login action, whoever just passed your password check), details:,
    # reference_id:, context: (procs run in the controller, or method names),
    # silent_sign_in: (true or { max_age_seconds: }), enroll:, error_body:, and
    # before_action's only: / except: / if: / unless:.
    #
    # Every answer of 400 and above carries X-Touchque-State (and X-Touchque-Reason when the
    # step has a reason).
    #
    # error_body: your own error shape for every answer of 400 and above (never a 202 step,
    # never an approval): a proc run in the controller, or a method name, given the refusal
    # ({ status:, code:, message:, touchque: }, with a copy of the step). What it encodes to
    # decides: a JSON object (a Hash, Struct, Data...) is sent with "touchque" set to the
    # step; anything else as it is. Status and headers stay; one that raises, or a result
    # that cannot be encoded, is logged and the default body sent.
    #
    #   require_touchque "SEND_MONEY", error_body: ->(r) { { message: r[:message], code: r[:code] } }
    #
    # Touchque.client is built on the first request: without TQ_API_KEY / TQ_API_SECRET the
    # action answers 500 misconfigured (401 without a signed-in user) and never runs.
    # enroll: false: a user with no phone gets 202 {"touchque": {"state": "enroll",
    # "reason": "enrollment_off"}} instead of the linking QR.
    module Guard
      def self.included(base)
        base.extend(ClassMethods)
      end

      module ClassMethods
        def require_touchque(action, user: nil, details: nil, reference_id: nil, context: nil, silent_sign_in: false, enroll: true,
                             error_body: nil, **filter_options)
          Touchque::Guard.assert_silent_sign_in!(silent_sign_in, "require_touchque")
          unless error_body.nil? || error_body.is_a?(Symbol) || error_body.respond_to?(:call)
            raise ArgumentError, "require_touchque: error_body must be a proc, a method name or respond to call."
          end

          options = { user: user, details: details, reference_id: reference_id, context: context, silent_sign_in: silent_sign_in,
                      enroll: enroll, error_body: error_body }
          before_action(**filter_options) { touchque_guard!(action, options) }
        end
      end

      # The approval of this request (set by require_touchque), or nil.
      def touchque_approval
        request.env["touchque.approval"]
      end

      private

      def touchque_guard!(action, options)
        user = touchque_value(options[:user]) || touchque_default_user
        client = Touchque::Guard.default_client
        result = if client.nil?
                   # No client (TQ_API_KEY / TQ_API_SECRET missing): an answer, never an exception.
                   user.to_s.empty? ? Touchque::Guard.unauthenticated : Touchque::Guard.misconfigured
                 else
                   header = ->(name) { request.headers[name] }
                   input = Touchque::Guard.input_from_headers(header)
                   silent = options[:silent_sign_in]
                   Touchque::Guard.run(
                     client, user, action,
                     details: touchque_value(options[:details]), reference_id: touchque_value(options[:reference_id]),
                     ip: request.remote_ip, user_agent: request.user_agent, token: input[:token], offline: input[:offline],
                     code: input[:code], code_type: input[:code_type], enroll: options[:enroll],
                     browser_proof: Touchque::Guard.silent_on?(silent) ? header.call(Touchque::Guard::BROWSER_HEADER) : nil,
                     silent_sign_in: silent, context: touchque_value(options[:context])
                   )
                 end
        if result[:approved]
          request.env["touchque.approval"] = result[:approved]
          return
        end
        touchque_render(result, options[:error_body])
      end

      # Renders a guard result that is not an approval as Touchque::Guard.response gives it
      # (render sets the JSON content type).
      def touchque_render(result, error_body)
        status, headers, body = Touchque::Guard.response(result, error_body: touchque_error_body(error_body))
        headers.each { |name, value| response.headers[name] = value unless name == "content-type" }
        render json: body, status: status
      end

      # error_body as a callable for Touchque::Guard.response: a proc runs in the controller,
      # a Symbol names one of its methods.
      def touchque_error_body(error_body)
        return nil if error_body.nil?

        lambda do |refusal|
          case error_body
          when Proc then instance_exec(refusal, &error_body)
          when Symbol then send(error_body, refusal)
          else error_body.call(refusal)
          end
        end
      end

      def touchque_value(option)
        case option
        when Proc then instance_exec(&option)
        when Symbol then send(option)
        else option
        end
      end

      # The signed-in user: current_user's email, id or username.
      def touchque_default_user
        user = respond_to?(:current_user, true) ? send(:current_user) : nil
        return nil unless user

        %i[email id username].each do |m|
          value = user.respond_to?(m) ? user.public_send(m) : nil
          return value.to_s unless value.nil? || value.to_s.empty?
        end
        nil
      end
    end

    # Verified webhooks in a controller:
    #
    #   class TouchqueWebhooksController < ActionController::API
    #     include Touchque::Rails::Webhook
    #     verify_touchque_webhook
    #
    #     def create
    #       EndSession.call(touchque_webhook["requestId"]) if touchque_webhook["event"] == Touchque::Resources::Webhook::EVENT_APPROVAL_REVOKED
    #       head :ok
    #     end
    #   end
    #
    # A bad signature or an old timestamp answers 401 before your action; a replay of a
    # delivery already accepted answers 200 without running it again (Touchque.replay_cache:
    # in-process by default; set one over Redis when you run several processes).
    module Webhook
      def self.included(base)
        base.extend(ClassMethods)
        base.skip_forgery_protection if base.respond_to?(:skip_forgery_protection)
      end

      module ClassMethods
        def verify_touchque_webhook(tolerance_seconds: Touchque::Resources::Webhook::DEFAULT_TOLERANCE_SECONDS, **filter_options)
          before_action(**filter_options) { touchque_verify_webhook!(tolerance_seconds) }
        end
      end

      # The verified payload of this request.
      def touchque_webhook
        @touchque_webhook
      end

      private

      def touchque_verify_webhook!(tolerance_seconds)
        @touchque_webhook = Touchque.client.webhook.verify(request.raw_post, request.headers["x-signature"],
                                                           tolerance_seconds: tolerance_seconds, replay_cache: Touchque.replay_cache)
      rescue Touchque::WebhookReplayError
        render json: { received: true, duplicate: true }, status: :ok
      rescue Touchque::WebhookSignatureError
        render json: { error: "invalid_signature" }, status: :unauthorized
      end
    end
  end
end
