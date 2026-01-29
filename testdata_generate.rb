require 'active_support'
require 'json'
require 'fileutils'

FileUtils.rm_r('message/encryptor/testdata')
FileUtils.mkdir_p('message/encryptor/testdata')
FileUtils.rm_r('message/verifier/testdata')
FileUtils.mkdir_p('message/verifier/testdata')

matrix = {
  TestVerifyModernSimpleString: {
    url_safe: false, legacy: false, data: 'signed message', opt: {},
  },
  TestVerifyModernSimpleStringURLSafe: {
    url_safe: true, legacy: false, data: '>?>', opt: {},
  },
  TestVerifyModernSimpleEnvelope: {
    url_safe: false, legacy: false, data: 'signed message', opt: { purpose: 'pizza' },
  },
  TestVerifyModernComplexEnvelope: {
    url_safe: false, legacy: false, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestVerifyModernComplexEnvelopeURLSafe: {
    url_safe: true, legacy: false, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestVerifyLegacySimpleEnvelope: {
    url_safe: false, legacy: true, data: 'signed message', opt: { purpose: 'pizza' },
  },
  TestVerifyLegacyComplexEnvelope: {
    url_safe: false, legacy: true, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestVerifyLegacyComplexEnvelopeURLSafe: {
    url_safe: true, legacy: true, data: { 'ab' => 123, 'cd' => 'yellow', 'ef' => true, 'gh' => nil }, opt: { purpose: 'pizza' },
  },
  TestVerifyMismatchPurpose: {
    url_safe: false, legacy: false, data: 'signed message', opt: { purpose: 'pineapple' },
  },
  TestVerifyExpired: {
    url_safe: false, legacy: false, data: 'signed message', opt: { expires_at: Time.new(2007, 1, 1, 0, 0, 0) },
  },
}

matrix.each do |name, setup|
  v = ActiveSupport::MessageVerifier.new(
    '12345678',
    digest: 'SHA256',
    serializer: JSON,
    url_safe: setup[:url_safe],
    force_legacy_metadata_serializer: setup[:legacy],
  )

  out = v.generate(setup[:data], **setup[:opt])

  File.write("message/verifier/testdata/#{name}.txt", out)
end

matrix = {
  TestDecryptCBC128: {
    cipher: 'aes-128-cbc', key: '1234567890123456', digest: 'SHA256',
  },
  TestDecryptCBC192: {
    cipher: 'aes-192-cbc', key: '123456789012345678901234', digest: 'SHA256',
  },
  TestDecryptCBC256: {
    cipher: 'aes-256-cbc', key: '12345678901234567890123456789012', digest: 'SHA256',
  },
  TestDecryptCBC256CustomHMAC: {
    cipher: 'aes-256-cbc', key: '12345678901234567890123456789012', digest: 'SHA256', hmac_key: 'abcdefg'
  },
  TestDecryptGCM128: {
    cipher: 'aes-128-gcm', key: '1234567890123456',
  },
  TestDecryptGCM192: {
    cipher: 'aes-192-gcm', key: '123456789012345678901234',
  },
  TestDecryptGCM256: {
    cipher: 'aes-256-gcm', key: '12345678901234567890123456789012',
  },
}

matrix.each do |name, setup|
  e = ActiveSupport::MessageEncryptor.new(
    setup[:key],
    setup[:hmac_key],
    cipher: setup[:cipher],
    digest: setup[:digest],
    serializer: JSON,
    url_safe: false,
    force_legacy_metadata_serializer: false,
  )

  out = e.encrypt_and_sign('encrypted message')

  File.write("message/encryptor/testdata/#{name}.txt", out)
end
