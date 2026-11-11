# frozen_string_literal: true

require "openssl"

module Touchque
  # Safe Guard approvals, checked without trusting Touchque. The approver's phone decodes the
  # raw Safe transaction itself and signs, with a P-256 key only its biometrics unlock, a
  # 105-byte approval that TouchqueSafeGuard checks on chain:
  #
  #   index (1) | expiresAt (8) | displayDigest (32) | r (32) | s (32)
  #
  # over the SHA-256 of the 149-byte message
  #
  #   "TQG1" | purpose (1) | chainId (32) | guard (20) | Safe (20) | subject (32) | expiresAt (8) | displayDigest (32)
  #
  # where subject is the Safe transaction hash (EIP-712, purpose 1 "approve") or, for a change
  # the guard schedules, the governance hash (purpose 2 "schedule"). verify makes the guard's
  # check off chain: both hashes are computed here from the raw fields, so a co-signer (or your
  # own server) refuses an approval of anything else, whoever relayed it.
  #
  # A target is { "chainId", "safe", "guard", "tx" => { "to", "value", "data", "operation",
  # "safeTxGas", "baseGas", "gasPrice", "gasToken", "refundReceiver", "nonce" } } (string or
  # symbol keys); integers as Integer or decimal strings.
  module SafeApproval
    MAGIC = "TQG1".b
    PURPOSES = { "approve" => 1, "schedule" => 2 }.freeze
    # The guard (MAX_APPROVAL_TTL) refuses an approval valid for longer than a day.
    MAX_APPROVAL_TTL = 86_400
    # OpenZeppelin P256 (the guard) refuses s above N/2.
    HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
    MAX_UINT256 = (1 << 256) - 1
    MAX_UINT64 = (1 << 64) - 1
    ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
    # SubjectPublicKeyInfo prefix of an uncompressed P-256 point.
    SPKI_P256 = ["3059301306072a8648ce3d020106082a8648ce3d030107034200"].pack("H*")
    MASK = (1 << 64) - 1
    RC = %w[
      0000000000000001 0000000000008082 800000000000808a 8000000080008000 000000000000808b 0000000080000001
      8000000080008081 8000000000008009 000000000000008a 0000000000000088 0000000080008009 000000008000000a
      000000008000808b 800000000000008b 8000000000008089 8000000000008003 8000000000008002 8000000000000080
      000000000000800a 800000008000000a 8000000080008081 8000000000008080 0000000080000001 8000000080008008
    ].map { |h| h.to_i(16) }.freeze
    # Rotation of lane x + 5y.
    ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14].freeze

    module_function

    # The Safe transaction hash (EIP-712, domain = chainId + the Safe): what the owners sign and
    # an ordinary approval covers.
    def safe_tx_hash(target)
      t = parse(target)
      domain = keccak256(TYPE_HASHES[:domain] + t[:chain_id] + t[:safe])
      struct = keccak256(
        TYPE_HASHES[:safe_tx] + t[:to] + t[:value] + keccak256(t[:data]) + t[:operation] + t[:safe_tx_gas] +
        t[:base_gas] + t[:gas_price] + t[:gas_token] + t[:refund_receiver] + t[:nonce]
      )
      hex(keccak256("\x19\x01".b + domain + struct))
    end

    # What the guard schedules a governance change under: the change itself, without the nonce
    # or gas fields.
    def governance_hash(target)
      t = parse(target)
      hex(keccak256(TYPE_HASHES[:governance] + t[:chain_id] + t[:safe] + t[:to] + t[:value] + keccak256(t[:data]) + t[:operation]))
    end

    # The 149-byte message the phone signs (its SHA-256 is what the guard verifies), as 0x hex.
    # +purpose+ is "approve" or "schedule"; +expires_at+ Unix seconds.
    def message(purpose:, chain_id:, guard:, safe:, subject:, expires_at:, display_digest:)
      code = PURPOSES[purpose.to_s] or raise ConfigError, "SafeApproval: purpose is \"approve\" or \"schedule\""
      hex(
        MAGIC + code.chr + uint(chain_id, "chainId", MAX_UINT64) + address(guard, "guard")[12, 20] + address(safe, "safe")[12, 20] +
        bytes(subject, "subject", 32) + uint(expires_at, "expiresAt", MAX_UINT64)[24, 8] + bytes(display_digest, "displayDigest", 32)
      )
    end

    # SHA-256 of the rows as "label\x1Fvalue" joined by "\x1E" (UTF-8), as 0x hex: the digest an
    # approval carries. Rows are { "label", "value" } (string or symbol keys).
    def display_digest(rows)
      canonical = rows.map { |r| "#{field(r, "label")}\u001F#{field(r, "value")}" }.join("\u001E")
      "0x#{OpenSSL::Digest::SHA256.hexdigest(canonical.encode("UTF-8"))}"
    end

    # Checks a phone's Safe Guard approval the way TouchqueSafeGuard does, without trusting the
    # server that relayed it: the Safe and governance hashes come from +target+, the key from
    # the guard's approver list on chain ("x || y", 128 hex characters, or { "x", "y" }).
    # +purpose+: what you are about to use the approval for, "approve" (the default: run this
    # very Safe transaction) or "schedule" (start this governance change's waiting time). A
    # schedule approval covers no nonce or gas fields, so it is accepted only when you name
    # "schedule". +approver_index+: the approval must name it.
    # +display_digest+ or +rows+: from your own decoding, the rows the phone must have shown.
    # +now+: a Time or Unix seconds.
    #
    # Returns { "valid", "reason", "purpose", "approverIndex", "expiresAt", "displayDigest",
    # "safeTxHash", "governanceHash" }; "reason" is nil when valid, else approval_malformed,
    # public_key_invalid, approver_index_mismatch, approval_expired, rows_differ, high_s or
    # signature_invalid. Raises ConfigError only when +target+ is not a Safe transaction.
    #
    #   status = tq.safe_guard.status(request_id)
    #   check = Touchque::SafeApproval.verify(my_tx, status["safeTx"]["approval"], approver_key_from_chain, approver_index: 0)
    #   raise "approval refused: #{check["reason"]}" unless check["valid"]
    def verify(target, approval, public_key, purpose: nil, approver_index: nil, display_digest: nil, rows: nil, now: nil)
      t = parse(target)
      hashes = { "safeTxHash" => safe_tx_hash(target), "governanceHash" => governance_hash(target) }
      parsed = { "approverIndex" => nil, "expiresAt" => nil, "displayDigest" => nil }
      refuse = ->(reason) { { "valid" => false, "reason" => reason, "purpose" => nil }.merge(parsed, hashes) }
      return refuse.call("approval_malformed") unless approval.is_a?(String) && approval.match?(/\A(0x)?[0-9a-fA-F]{210}\z/)

      b = [strip0x(approval)].pack("H*")
      expires_at = b[1, 8].unpack1("Q>")
      parsed = { "approverIndex" => b.getbyte(0), "expiresAt" => expires_at, "displayDigest" => hex(b[9, 32]) }
      key = ec_key(public_key)
      return refuse.call("public_key_invalid") if key.nil?
      return refuse.call("approver_index_mismatch") if !approver_index.nil? && approver_index != parsed["approverIndex"]

      seconds = now.nil? ? Time.now.to_i : now.to_i
      return refuse.call("approval_expired") if expires_at < seconds || expires_at > seconds + MAX_APPROVAL_TTL

      expected = display_digest || (rows && SafeApproval.display_digest(rows))
      return refuse.call("rows_differ") if expected && "0x#{strip0x(expected.downcase)}" != parsed["displayDigest"]

      r = b[41, 32].unpack1("H*").to_i(16)
      s = b[73, 32].unpack1("H*").to_i(16)
      return refuse.call("high_s") if s > HALF_N

      der = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(OpenSSL::BN.new(r)), OpenSSL::ASN1::Integer(OpenSSL::BN.new(s))]).to_der
      # Never falls back to "schedule": that one is valid at any nonce.
      p = (purpose || "approve").to_s
      msg = message(
        purpose: p, chain_id: t[:chain_id].unpack1("H*").to_i(16), guard: hex(t[:guard][12, 20]), safe: hex(t[:safe][12, 20]),
        subject: p == "approve" ? hashes["safeTxHash"] : hashes["governanceHash"], expires_at: expires_at, display_digest: parsed["displayDigest"]
      )
      ok = begin
        key.verify("SHA256", der, [strip0x(msg)].pack("H*"))
      rescue OpenSSL::PKey::PKeyError
        false
      end
      return refuse.call("signature_invalid") unless ok

      { "valid" => true, "reason" => nil, "purpose" => p }.merge(parsed, hashes)
    end

    # The owners' Safe signatures with the approvals appended (approvals by index | count |
    # "TQG1"): the signatures argument of execTransaction for an ordinary transaction.
    def with_approvals(owner_signatures, approvals)
      items = approval_bytes(approvals)
      hex(bytes(owner_signatures, "ownerSignatures") + items.join + items.size.chr + MAGIC)
    end

    # The call data of guard.schedule(safe, governanceHash, approvals), which starts a
    # governance change's waiting time.
    def schedule_call(safe, governance_hash, approvals)
      joined = approval_bytes(approvals).join
      hex(
        TYPE_HASHES[:schedule][0, 4] + address(safe, "safe") + bytes(governance_hash, "governanceHash", 32) + uint(96, "offset", MAX_UINT256) +
        uint(joined.bytesize, "length", MAX_UINT256) + joined + ("\0".b * ((32 - (joined.bytesize % 32)) % 32))
      )
    end

    # ── Keccak-256 (the Ethereum hash: Keccak padding, not SHA3-256) ──

    def rotl(value, n)
      n.zero? ? value : (((value << n) | (value >> (64 - n))) & MASK)
    end

    def keccak_f(a)
      RC.each do |rc|
        c = (0...5).map { |x| a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
        5.times do |x|
          d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
          0.step(20, 5) { |y| a[x + y] ^= d }
        end
        b = Array.new(25, 0)
        5.times { |x| 5.times { |y| b[y + (5 * (((2 * x) + (3 * y)) % 5))] = rotl(a[x + (5 * y)], ROT[x + (5 * y)]) } }
        0.step(20, 5) { |y| 5.times { |x| a[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & b[((x + 2) % 5) + y] & MASK) } }
        a[0] ^= rc
      end
      a
    end

    def keccak256(data)
      rate = 136
      padded = data.b + ("\0".b * (rate - (data.bytesize % rate)))
      padded.setbyte(data.bytesize, padded.getbyte(data.bytesize) ^ 0x01)
      padded.setbyte(padded.bytesize - 1, padded.getbyte(padded.bytesize - 1) ^ 0x80)
      a = Array.new(25, 0)
      (0...padded.bytesize).step(rate) do |off|
        padded[off, rate].unpack("Q<17").each_with_index { |lane, k| a[k] ^= lane }
        keccak_f(a)
      end
      a[0, 4].pack("Q<4")
    end

    TYPE_HASHES = {
      domain: keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
      safe_tx: keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"),
      # The guard contract hashes this exact string, so it keeps its original spelling.
      governance: keccak256("TouchQueGovernance(uint256 chainId,address safe,address to,uint256 value,bytes32 dataHash,uint8 operation)"),
      schedule: keccak256("schedule(address,bytes32,bytes)")
    }.freeze

    # ── Field parsing: the partner's own data, so a wrong field raises ──

    def field(hash, key)
      hash.key?(key) ? hash[key] : hash[key.to_sym]
    end

    def parse(target)
      tx = target.is_a?(Hash) ? field(target, "tx") : nil
      raise ConfigError, "SafeApproval: pass { \"chainId\", \"safe\", \"guard\", \"tx\" => { \"to\", \"value\", \"data\", \"operation\", ..., \"nonce\" } }" unless tx.is_a?(Hash)

      operation = field(tx, "operation") || 0
      raise ConfigError, "SafeApproval: tx.operation must be 0 (call) or 1 (delegatecall)" unless [0, 1].include?(operation)

      {
        chain_id: uint(field(target, "chainId"), "chainId", MAX_UINT64),
        safe: address(field(target, "safe"), "safe"),
        guard: address(field(target, "guard"), "guard"),
        to: address(field(tx, "to"), "tx.to"),
        value: uint(field(tx, "value") || 0, "tx.value", MAX_UINT256),
        data: bytes(field(tx, "data") || "0x", "tx.data"),
        operation: uint(operation, "tx.operation", 1),
        safe_tx_gas: uint(field(tx, "safeTxGas") || 0, "tx.safeTxGas", MAX_UINT256),
        base_gas: uint(field(tx, "baseGas") || 0, "tx.baseGas", MAX_UINT256),
        gas_price: uint(field(tx, "gasPrice") || 0, "tx.gasPrice", MAX_UINT256),
        gas_token: address(field(tx, "gasToken") || ZERO_ADDRESS, "tx.gasToken"),
        refund_receiver: address(field(tx, "refundReceiver") || ZERO_ADDRESS, "tx.refundReceiver"),
        nonce: uint(field(tx, "nonce"), "tx.nonce", MAX_UINT256)
      }
    end

    # A non-negative integer (Integer or decimal string) as a 32-byte word.
    def uint(value, name, max)
      v = if value.is_a?(Integer) then value
          elsif value.is_a?(String) && value.match?(/\A(0|[1-9][0-9]*)\z/) then value.to_i
          end
      raise ConfigError, "SafeApproval: #{name} must be a non-negative integer (a decimal string for large values)" if v.nil? || v.negative? || v > max

      [v.to_s(16).rjust(64, "0")].pack("H*")
    end

    def address(value, name)
      raise ConfigError, "SafeApproval: #{name} must be an address (0x and 40 hex characters)" unless value.is_a?(String) && value.match?(/\A0x[0-9a-fA-F]{40}\z/)

      ("\0".b * 12) + [value[2..]].pack("H*")
    end

    def bytes(value, name, size = nil)
      unless value.is_a?(String) && value.match?(/\A0x(?:[0-9a-fA-F]{2})*\z/) && (size.nil? || value.length == 2 + (2 * size))
        raise ConfigError, "SafeApproval: #{name} must be 0x-prefixed hex#{size ? " of #{size} bytes" : ""}"
      end

      [value[2..]].pack("H*")
    end

    def approval_bytes(approvals)
      list = Array(approvals)
      raise ConfigError, "SafeApproval: pass 1 to 255 approvals" unless list.size.between?(1, 255)

      list.each_with_index.map { |a, i| bytes(a.to_s.start_with?("0x") ? a : "0x#{a}", "approvals[#{i}]", 105) }.sort_by.with_index { |a, i| [a.getbyte(0), i] }
    end

    def ec_key(key)
      xy = key.is_a?(Hash) ? strip0x(field(key, "x").to_s) + strip0x(field(key, "y").to_s) : strip0x(key.to_s)
      return nil unless xy.match?(/\A[0-9a-fA-F]{128}\z/)

      ec = OpenSSL::PKey.read(SPKI_P256 + ["04#{xy}"].pack("H*"))
      ec.public_key.on_curve? ? ec : nil
    rescue OpenSSL::PKey::PKeyError, OpenSSL::PKey::EC::Point::Error
      nil
    end

    def strip0x(text)
      text.start_with?("0x") ? text[2..] : text
    end

    def hex(data)
      "0x#{data.unpack1("H*")}"
    end

    private_class_method :rotl, :keccak_f, :keccak256, :field, :parse, :uint, :address, :bytes, :approval_bytes, :ec_key, :strip0x, :hex
  end
end
