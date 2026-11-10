# frozen_string_literal: true

require "test_helper"

# A feature the workspace's organization cannot use comes back as a typed error
# with the feature's id, still an APIError. Same scenarios as the Node SDK,
# against the shared fake TouchQue API.
class FeatureErrorsTest < FakeApiTest
  def test_each_feature_refusal_has_its_own_error
    api.link("jane@acme.com")
    { "feature_not_in_plan" => [TouchQue::FeatureNotInPlanError, :not_in_plan],
      "feature_read_only" => [TouchQue::FeatureReadOnlyError, :read_only],
      "feature_off" => [TouchQue::FeatureOffError, :off] }.each do |code, (klass, reason)|
      api.opts({ featureRefused: code, feature: "device_risk" })
      err = assert_raises(klass) { tq.login.request("jane@acme.com") }
      assert_kind_of TouchQue::FeatureError, err
      assert_kind_of TouchQue::APIError, err
      assert_equal [403, "device_risk", reason], [err.status, err.feature, err.feature_reason]
    end
  end

  def test_other_refusals_stay_plain_api_errors
    api.link("jane@acme.com")
    api.opts({ blocked: "access_policy" })
    err = assert_raises(TouchQue::APIError) { tq.login.request("jane@acme.com") }
    refute_kind_of TouchQue::FeatureError, err
  end
end
