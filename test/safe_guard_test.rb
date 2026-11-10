# frozen_string_literal: true

require "test_helper"

# Safe Guard: the verifier against the shared vectors (fixtures/safe-guard-vectors.json, derived
# from the reference project and shared with every server SDK).
class SafeApprovalVectorsTest < Minitest::Test
  VECTORS = TestSupport.fixture("safe-guard-vectors.json")
  OPTIONS = { "purpose" => :purpose, "approverIndex" => :approver_index, "displayDigest" => :display_digest, "now" => :now }.freeze

  def vector(name) = VECTORS["vectors"].find { |v| v["name"] == name }

  def test_every_vector
    VECTORS["vectors"].each do |v|
      t = v["safeTx"]
      assert_equal v["safeTxHash"], TouchQue::SafeApproval.safe_tx_hash(t), v["name"]
      assert_equal v["governanceHash"], TouchQue::SafeApproval.governance_hash(t), v["name"]
      message = TouchQue::SafeApproval.message(purpose: v["purpose"], chain_id: t["chainId"], guard: t["guard"], safe: t["safe"],
                                               subject: v["subject"], expires_at: v["expiresAt"], display_digest: v["displayDigest"])
      assert_equal v["message"], message, v["name"]
      assert_equal v["rowsDigest"], TouchQue::SafeApproval.display_digest(v["rows"]), v["name"] if v["rows"]
      assert_equal({
                     "valid" => true, "reason" => nil, "purpose" => v["purpose"], "approverIndex" => t["approverIndex"], "expiresAt" => v["expiresAt"],
                     "displayDigest" => v["displayDigest"], "safeTxHash" => v["safeTxHash"], "governanceHash" => v["governanceHash"]
                   }, TouchQue::SafeApproval.verify(t, v["approval"], VECTORS["approverKey"], purpose: v["purpose"], now: VECTORS["now"],
                                                                                              approver_index: t["approverIndex"]), v["name"])
    end
  end

  def test_every_check
    VECTORS["checks"].each do |c|
      options = { now: VECTORS["now"] }.merge(c["options"].to_h { |k, val| [OPTIONS.fetch(k), val] })
      key = c["keyXY"] || c["key"] || VECTORS["approverKey"]
      got = TouchQue::SafeApproval.verify(vector(c["vector"])["safeTx"], c["approval"], key, **options)
      if c["reason"].nil?
        assert_nil got["reason"], c["name"]
      else
        assert_equal c["reason"], got["reason"], c["name"]
      end
      assert_equal c["reason"].nil?, got["valid"], c["name"]
      assert_equal c["purpose"], got["purpose"], c["name"] if c["purpose"]
    end
  end

  def test_trailer_and_schedule_call
    w = VECTORS["withApprovals"]
    assert_equal w["expected"], TouchQue::SafeApproval.with_approvals(w["ownerSignatures"], w["approvals"])
    s = VECTORS["scheduleCall"]
    assert_equal s["expected"], TouchQue::SafeApproval.schedule_call(s["safe"], s["governanceHash"], s["approvals"])
    t = VECTORS["vectors"][0]["safeTx"]
    assert_raises(TouchQue::ConfigError) { TouchQue::SafeApproval.safe_tx_hash(t.merge("tx" => t["tx"].merge("operation" => 2))) }
  end
end

# request / status / wait against the shared fake TouchQue API.
class SafeGuardTest < FakeApiTest
  def test_request_wait_and_check_the_approval_here
    v = SafeApprovalVectorsTest::VECTORS["vectors"].find { |x| x["name"] == "bybit_pattern" }
    key = SafeApprovalVectorsTest::VECTORS["approverKey"]
    api.link("treasurer@acme.com")
    api.opts({ safeTxView: { class: v["class"], flags: ["delegatecall"], safeTxHash: v["safeTxHash"], governanceHash: v["governanceHash"], purpose: v["purpose"] } })
    safe_tx = v["safeTx"].merge("chainId" => 1, "tx" => v["safeTx"]["tx"].merge("nonce" => 42))
    sent = tq.safe_guard.request("treasurer@acme.com", "safe_payment", safe_tx, reference_id: "tx-1")
    assert_equal v["governanceHash"], sent["safeTx"]["governanceHash"]
    call = api.last_call
    assert_equal "/safe-guard/approvals", call["path"]
    assert_equal "1", call["body"]["safeTx"]["chainId"]
    assert_equal "42", call["body"]["safeTx"]["tx"]["nonce"]
    assert_equal "tx-1", call["body"]["referenceId"]
    refute tq.safe_guard.status(sent["requestId"])["safeTx"].key?("approval")

    api.post("/__test/approve", { id: sent["requestId"], safeTx: { approval: v["approval"], expiresAt: v["expiresAt"] } })
    done = tq.safe_guard.wait_for_approval(sent["requestId"], timeout: 5, poll_interval: 0.01)
    assert_equal "CONFIRMED", done["status"]
    check = ->(**purpose) { TouchQue::SafeApproval.verify(safe_tx, done["safeTx"]["approval"], key, now: SafeApprovalVectorsTest::VECTORS["now"], approver_index: done["safeTx"]["approverIndex"], **purpose) }
    assert_equal [true, "schedule"], check.call(purpose: done["safeTx"]["purpose"]).values_at("valid", "purpose")
    # A schedule approval is never taken as permission to execute.
    assert_equal [false, "signature_invalid"], check.call.values_at("valid", "reason")

    again = tq.safe_guard.request("treasurer@acme.com", "safe_payment", v["safeTx"])
    api.reject(again["requestId"])
    assert_raises(TouchQue::RejectedError) { tq.safe_guard.wait_for_approval(again["requestId"], timeout: 5, poll_interval: 0.01) }
  end
end
