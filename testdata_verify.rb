require 'active_support'
require 'json'

matrix = {
  TestGenerateModernSimpleString: {
    url_safe: false, legacy: false, data: 'signed message', opt: {},
  },
  TestGenerateModernSimpleStringURLSafe: {
    url_safe: true, legacy: false, data: '>?>', opt: {},
  },
  TestGenerateModernSimpleEnvelope: {
    url_safe: false, legacy: false, data: 'signed message', opt: { purpose: 'pizza' },
  },
  TestGenerateModernComplexEnvelope: {
    url_safe: false, legacy: false, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestGenerateModernComplexEnvelopeURLSafe: {
    url_safe: true, legacy: false, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestGenerateLegacySimpleEnvelope: {
    url_safe: false, legacy: true, data: 'signed message', opt: { purpose: 'pizza' },
  },
  TestGenerateLegacyComplexEnvelope: {
    url_safe: false, legacy: true, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestGenerateLegacyComplexEnvelopeURLSafe: {
    url_safe: true, legacy: true, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestGenerateMismatchPurpose: {
    url_safe: false, legacy: false, data: 'signed message', opt: { purpose: 'pineapple' }, expect_invalid_sig: true,
  },
  TestGenerateExpired: {
    url_safe: false, legacy: false, data: 'signed message', opt: {}, expect_invalid_sig: true,
  },
}

matrix.each do |name, setup|
  input = File.read("message/verifier/testdata/#{name}.txt")

  v = ActiveSupport::MessageVerifier.new(
    '12345678',
    digest: 'SHA256',
    serializer: JSON,
    url_safe: setup[:url_safe],
    force_legacy_metadata_serializer: setup[:legacy],
  )

  parsed = v.verify(input, **setup[:opt])

  if parsed != setup[:data]
    raise "mismatch #{parsed}, #{setup[:data]}"
  end
rescue ActiveSupport::MessageVerifier::InvalidSignature
  next if setup[:expect_invalid_sig]
  puts setup
  raise
end

matrix = {
  TestEncryptCBC128: {
    cipher: 'aes-128-cbc', key: '1234567890123456', digest: 'SHA256',
  },
  TestEncryptCBC192: {
    cipher: 'aes-192-cbc', key: '123456789012345678901234', digest: 'SHA256',
  },
  TestEncryptCBC256: {
    cipher: 'aes-256-cbc', key: '12345678901234567890123456789012', digest: 'SHA256',
  },
  TestEncryptCBC256CustomHMAC: {
    cipher: 'aes-256-cbc', key: '12345678901234567890123456789012', digest: 'SHA256', hmac_key: 'abcdefg'
  },
  TestEncryptGCM128: {
    cipher: 'aes-128-gcm', key: '1234567890123456',
  },
  TestEncryptGCM192: {
    cipher: 'aes-192-gcm', key: '123456789012345678901234',
  },
  TestEncryptGCM256: {
    cipher: 'aes-256-gcm', key: '12345678901234567890123456789012',
  },
}

matrix.each do |name, setup|
  input = File.read("message/encryptor/testdata/#{name}.txt")

  e = ActiveSupport::MessageEncryptor.new(
    setup[:key],
    setup[:hmac_key],
    cipher: setup[:cipher],
    digest: setup[:digest],
    serializer: JSON,
    url_safe: false,
    force_legacy_metadata_serializer: false,
  )

  parsed = e.decrypt_and_verify(input)

  if parsed != 'encrypted message'
    raise "expect to get 'encrypted message', got: #{parsed}"
  end
rescue ActiveSupport::MessageEncryptor::InvalidMessage
  puts setup
  raise
end
