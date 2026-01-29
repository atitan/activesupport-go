require 'active_support'
require 'json'
require 'fileutils'

FileUtils.mkdir_p('message/encryptor/testdata')
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

