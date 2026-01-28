require 'active_support'
require 'json'

digest = 'SHA256'
serializer = JSON
secret = '12345678'

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
    url_safe: false, legacy: false, data: 'signed message', opt: { purpose: 'pineapple' }, expect_invalid: true,
  },
  TestGenerateExpired: {
    url_safe: false, legacy: false, data: 'signed message', opt: {}, expect_invalid: true,
  },
}

matrix.each do |name, setup|
  input = File.read("testdata/#{name}.txt")

  v = ActiveSupport::MessageVerifier.new(
    secret,
    digest: digest,
    serializer: serializer,
    url_safe: setup[:url_safe],
    force_legacy_metadata_serializer: setup[:legacy],
  )

  parsed = v.verify(input, **setup[:opt])

  if parsed != setup[:data]
    raise "#{parsed}, #{setup[:data]}"
  end
rescue ActiveSupport::MessageVerifier::InvalidSignature
  raise unless setup[:expect_invalid]
end
