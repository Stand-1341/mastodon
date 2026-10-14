# frozen_string_literal: true

require 'json/ld'

# Pin the complete standard context locally so signing never needs to download it.
# Source: https://w3id.org/security/data-integrity/v2
# Redirect target: https://www.w3.org/2025/credentials/vcdi/context/v2.jsonld
class JSON::LD::Context
  add_preloaded('https://w3id.org/security/data-integrity/v2') do
    context = JSON.parse(Rails.root.join('config', 'data_integrity_v2.jsonld').read).fetch('@context')
    new(processingMode: 'json-ld-1.1').parse(context)
  end

  alias_preloaded('http://w3id.org/security/data-integrity/v2', 'https://w3id.org/security/data-integrity/v2')
end
