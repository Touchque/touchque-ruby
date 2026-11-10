# frozen_string_literal: true

module TouchQue
  module Rails
    # One line per protected action:
    #
    #   class TransfersController < ApplicationController
    #     include TouchQue::Rails::Guard
    #     require_touchque "SEND_MONEY", only: :create,
    #                      details: -> { { "Amount" => params.require(:amount), "To" => params.require(:to) } }
    #
    #     def create
    #       touchque_approval # the approval, once the user approved on their phone
    #     end
    #   end
    #
    # Until the user approves this answers 202 {"touchque": step, "token": "..."}; your page
    # shows the step and sends the same request again with header X-TouchQue-Token (the
    # @touchque/web loop). Once approved the action runs ONCE. Refusals answer 403 / 408 /
    # 423 / 429 with Retry-After. Options: user: (default: current_user's email, id or
    # username; for your login action, whoever just passed your password check), details:,
    # reference_id:, context: (procs run in the controller, or method names),
    # silent_sign_in: (true or { max_age_seconds: }), enroll:, and before_action's
    # only: / except: / if: / unless:.
    module Guard
      def self.included(base)
        base.extend(ClassMethods)
      end

      module ClassMethods
        def require_touchque(action, user: nil, details: nil, reference_id: nil, context: nil, silent_sign_in: false, enroll: true, **filter_options)
          TouchQue::Guard.assert_silent_sign_in!(silent_sign_in, "require_touchque")
          options = { user: user, details: details, reference_id: reference_id, context: context, silent_sign_in: silent_sign_in, enroll: enroll }
          before_action(**filter_options) { touchque_guard!(action, options) }
        end
      end

      # The approval of this request (set by require_touchque), or nil.
      def touchque_approval
        request.env["touchque.approval"]
      end

      private

      def touchque_guard!(action, options)
        header = ->(name) { request.headers[name] }
        input = TouchQue::Guard.input_from_headers(header)
        silent = options[:silent_sign_in]
        result = TouchQue::Guard.run(
          TouchQue.client, touchque_value(options[:user]) || touchque_default_user, action,
          details: touchque_value(options[:details]), reference_id: touchque_value(options[:reference_id]),
          ip: request.remote_ip, user_agent: request.user_agent, token: input[:token], offline: input[:offline],
          code: input[:code], code_type: input[:code_type], enroll: options[:enroll],
          browser_proof: TouchQue::Guard.silent_on?(silent) ? header.call(TouchQue::Guard::BROWSER_HEADER) : nil,
          silent_sign_in: silent, context: touchque_value(options[:context])
        )
        if result[:approved]
          request.env["touchque.approval"] = result[:approved]
          return
        end
        response.headers["Cache-Control"] = "no-store"
        retry_after = result[:body].dig("touchque", "retryAfter")
        response.headers["Retry-After"] = retry_after.to_s if retry_after
        render json: result[:body], status: result[:status]
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
    #     include TouchQue::Rails::Webhook
    #     verify_touchque_webhook
    #
    #     def create
    #       EndSession.call(touchque_webhook["requestId"]) if touchque_webhook["event"] == TouchQue::Resources::Webhook::EVENT_APPROVAL_REVOKED
    #       head :ok
    #     end
    #   end
    #
    # A bad signature or an old timestamp answers 401 before your action; a replay of a
    # delivery already accepted answers 200 without running it again (TouchQue.replay_cache:
    # in-process by default; set one over Redis when you run several processes).
    module Webhook
      def self.included(base)
        base.extend(ClassMethods)
        base.skip_forgery_protection if base.respond_to?(:skip_forgery_protection)
      end

      module ClassMethods
        def verify_touchque_webhook(tolerance_seconds: TouchQue::Resources::Webhook::DEFAULT_TOLERANCE_SECONDS, **filter_options)
          before_action(**filter_options) { touchque_verify_webhook!(tolerance_seconds) }
        end
      end

      # The verified payload of this request.
      def touchque_webhook
        @touchque_webhook
      end

      private

      def touchque_verify_webhook!(tolerance_seconds)
        @touchque_webhook = TouchQue.client.webhook.verify(request.raw_post, request.headers["x-signature"],
                                                           tolerance_seconds: tolerance_seconds, replay_cache: TouchQue.replay_cache)
      rescue TouchQue::WebhookReplayError
        render json: { received: true, duplicate: true }, status: :ok
      rescue TouchQue::WebhookSignatureError
        render json: { error: "invalid_signature" }, status: :unauthorized
      end
    end
  end
end
