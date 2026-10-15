# frozen_string_literal: true

module PqcKeyProvisioningHelpers
  def generate_real_ml_dsa_44_key
    OpenSSL::PKey.generate_key('ML-DSA-44')
  rescue OpenSSL::PKey::PKeyError, NotImplementedError => e
    raise OpenSSL::PKey::PKeyError, "PQC_REQUIRE_ML_DSA=true requires native ML-DSA-44 generation; use Ruby linked to OpenSSL 3.5+ with an ML-DSA-capable provider: #{e.message}" if ENV['PQC_REQUIRE_ML_DSA'] == 'true'

    skip "Real ML-DSA-44 key tests require a supported OpenSSL provider: #{e.message}"
  end

  # Synthetic public bytes exercise DER encoding without requiring ML-DSA support.
  def synthetic_ml_dsa_44_public_key
    der = Multibase::ML_DSA_44_PUB_DER_HEADER + ("\x42" * 1312)
    "-----BEGIN PUBLIC KEY-----\n#{Base64.strict_encode64(der).scan(/.{1,64}/).join("\n")}\n-----END PUBLIC KEY-----\n"
  end
end
