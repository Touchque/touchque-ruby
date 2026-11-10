# frozen_string_literal: true

require "test_helper"

# A code typed back on the phone against the shared fake TouchQue API, which seals it like the
# phone does: it opens only with the one-time key, for that request.
class CodeReplyTest < FakeApiTest
  def test_the_typed_code_opens_only_with_the_one_time_key_for_that_request
    api.link("ayse@acme.com")
    key = TouchQue::CodeReply.new_key
    sent = tq.login.request("ayse@acme.com", reply: { kind: "code", key: key["publicKey"], channel: "sms", target: "+**********26" })
    assert_nil tq.login.status(sent["requestId"])["reply"]
    api.post("/__test/approve", { id: sent["requestId"], replyCode: "482 913" })
    ct = tq.login.status(sent["requestId"])["reply"]["ct"]
    assert_equal "482 913", TouchQue::CodeReply.open(key["privateKey"], sent["requestId"], ct)
    assert_nil TouchQue::CodeReply.open(key["privateKey"], "another-request", ct)
    assert_nil TouchQue::CodeReply.open(TouchQue::CodeReply.new_key["privateKey"], sent["requestId"], ct)
    assert_nil TouchQue::CodeReply.open(key["privateKey"], sent["requestId"], "v1.bad.ct")
  end
end
