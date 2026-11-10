# frozen_string_literal: true

module TouchQue
  # Base class of every error the SDK raises.
  class Error < StandardError; end

  # TouchQue answered with an error (status 400 or more). +status+ is the HTTP
  # status, +code+ the machine-readable code (+device_not_linked+,
  # +unknown_action+, +already_used+...) and +data+ the decoded JSON body.
  class APIError < Error
    attr_reader :status, :data

    def initialize(status, data = nil, message = nil)
      @status = status
      @data = data.is_a?(Hash) ? data : {}
      super(message || @data["message"] || @data["error"] || "TouchQue API error: HTTP #{status}")
    end

    # Machine-readable error code, e.g. "device_not_linked".
    def code
      @data["code"]
    end

    # The API's +error+ field.
    def error
      @data["error"]
    end

    # Why a request was refused (offline codes, blocked requests).
    def reason
      @data["reason"].is_a?(String) ? @data["reason"] : nil
    end

    # Offline sign: wrong codes left before the challenge locks.
    def attempts_left
      @data["attemptsLeft"]
    end

    # Seconds to wait before retrying (429 / 423).
    def retry_after
      @data["retryAfter"]
    end

    # "Why?" case code of a refusal (+K7P-2QX+): show it to the user ("Tell your
    # support team: K7P-2QX"); your team opens the decision by it in the dashboard.
    def case_code
      @data["caseCode"].is_a?(String) ? @data["caseCode"] : nil
    end

    # Where to send the person instead (help desk: +never_locked_out+).
    def route
      @data["route"]
    end

    # The error for an answer: a FeatureError subclass for the three feature
    # codes, else APIError.
    def self.for(status, data = nil, message = nil)
      klass = data.is_a?(Hash) ? FeatureError::BY_ERROR[data["error"]] : nil
      (klass || APIError).new(status, data, message)
    end
  end

  # The organization behind your workspace cannot use this feature here (HTTP
  # 403). +feature_reason+:
  # - +:not_in_plan+: not in its plan (+feature_not_in_plan+); an owner or admin
  #   adds it in the TouchQue dashboard;
  # - +:read_only+: being turned off (+feature_read_only+); reads still work for
  #   14 days, changes are refused;
  # - +:off+: switched off on this TouchQue deployment (+feature_off+).
  # +feature+ is the catalog id (+device_risk+, +ai_agents+, +mobile_sdk+,
  # +ciam+...). An APIError, so existing +rescue+ blocks still catch it; rescue
  # one of the three subclasses to tell them apart.
  class FeatureError < APIError
    REASON = nil

    # The catalog id of the feature, or nil.
    def feature
      @data["feature"].is_a?(String) ? @data["feature"] : nil
    end

    # +:not_in_plan+, +:read_only+ or +:off+.
    def feature_reason
      self.class::REASON
    end
  end

  # +feature_not_in_plan+: the feature is not in the organization's plan.
  class FeatureNotInPlanError < FeatureError
    REASON = :not_in_plan
  end

  # +feature_read_only+: the feature is being turned off; reads work, changes are refused.
  class FeatureReadOnlyError < FeatureError
    REASON = :read_only
  end

  # +feature_off+: the feature is switched off on this TouchQue deployment.
  class FeatureOffError < FeatureError
    REASON = :off
  end

  FeatureError::BY_ERROR = {
    "feature_not_in_plan" => FeatureNotInPlanError,
    "feature_read_only" => FeatureReadOnlyError,
    "feature_off" => FeatureOffError,
  }.freeze

  # The request never reached TouchQue (DNS, connection refused, timeout). Unlike
  # APIError, generally safe to retry.
  class NetworkError < Error
    def initialize(message)
      super("TouchQue: network request failed: #{message}")
    end
  end

  # The user did not answer in time, or the request expired.
  class TimeoutError < Error
    attr_reader :request_id

    def initialize(message, request_id = nil)
      @request_id = request_id
      super(message)
    end
  end

  # The user rejected the request on their phone.
  class RejectedError < Error
    attr_reader :request_id

    def initialize(request_id)
      @request_id = request_id
      super("TouchQue: request '#{request_id}' was rejected by the user.")
    end
  end

  # A webhook is not from TouchQue, was changed, or is too old.
  class WebhookSignatureError < Error
    def initialize(message)
      super("TouchQue: webhook rejected: #{message}")
    end
  end

  # A correctly signed webhook with this +jti+ was already accepted. Usually a
  # TouchQue retry of a delivery you processed: answer 200 so it stops, but do not
  # run your side effects again. A WebhookSignatureError, so existing rescues
  # still reject it.
  class WebhookReplayError < WebhookSignatureError
    attr_reader :jti

    def initialize(jti)
      @jti = jti
      super("this webhook (jti) was already accepted")
    end
  end

  # Missing or invalid configuration, an undefined action type, or a wrong argument.
  class ConfigError < Error
    def initialize(message)
      super("TouchQue config error: #{message}")
    end
  end

  # This request must be approved with a passkey. +reason+ is "policy" when a
  # phishing-resistant policy requires it (no push was sent), or "step_up" when
  # the user tapped Approve during a call (Vishing Shield) and the request, still
  # open, now waits for a passkey in the browser.
  class PasskeyRequiredError < Error
    attr_reader :request_id, :reason

    def initialize(request_id, reason = "policy")
      @request_id = request_id
      @reason = reason
      super(if reason == "step_up"
              "TouchQue: request '#{request_id}' must now be approved with a passkey: the user approved on the phone during a call."
            else
              "TouchQue: request '#{request_id}' must be approved with a passkey (phishing-resistant policy); no push was sent."
            end)
    end
  end

  # An AI agent's approval ended without a usable approval: +status+ is rejected,
  # blocked, revoked, expired, stale (approved too long ago) or redeemed (already used).
  class ApprovalError < Error
    attr_reader :approval_id, :status, :reason

    def initialize(approval_id, status, reason = nil)
      @approval_id = approval_id
      @status = status
      @reason = reason
      super("TouchQue: approval '#{approval_id}' is #{status}#{reason ? " (#{reason})" : ""}.")
    end
  end

  # An approval does not say what you are about to execute (another person,
  # action type, amount, recipient...), or it is not a valid token from TouchQue.
  # Do not execute.
  class ApprovalMismatchError < Error
    def initialize(message)
      super("TouchQue: #{message}")
    end
  end

  # McpAuth refused a request: answer with +status+ (401, 403) and the
  # WWW-Authenticate header in +www_authenticate+. +error+ is missing_token,
  # invalid_token, invalid_dpop_proof or insufficient_scope.
  class McpAuthError < Error
    attr_reader :status, :error, :www_authenticate

    def initialize(status, error, message, www_authenticate)
      @status = status
      @error = error
      @www_authenticate = www_authenticate
      super(message)
    end
  end

  # A TouchQue Login sign-in or token check failed; +error_code+ is machine-readable.
  class HostedLoginError < Error
    attr_reader :error_code, :description, :status

    def initialize(error_code, description = nil, status = nil)
      @error_code = error_code
      @description = description
      @status = status
      super(description ? "#{error_code}: #{description}" : error_code)
    end
  end

  # A My Account API call failed; step_up? means the sign-in is too old for it (RFC 9470).
  class MyAccountError < Error
    attr_reader :error_code, :status, :description, :max_age

    def initialize(error_code, status, description = nil, max_age = nil)
      @error_code = error_code
      @status = status
      @description = description
      @max_age = max_age
      super(description ? "#{error_code}: #{description}" : error_code)
    end

    # True when the person must sign in again (authorization_url with max_age: 0) before this change.
    def step_up?
      error_code == "insufficient_user_authentication"
    end
  end
end
