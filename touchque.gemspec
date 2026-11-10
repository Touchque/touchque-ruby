# frozen_string_literal: true

require_relative "lib/touchque/version"

Gem::Specification.new do |spec|
  spec.name = "touchque"
  spec.version = TouchQue::VERSION
  spec.authors = ["TouchQue"]
  spec.email = ["developer@touchque.com"]
  spec.summary = "Official Ruby SDK for TouchQue: push approvals with number matching, passkeys, silent sign-ins, webhooks, Actions, AI agents and TouchQue Login."
  spec.description = "Server SDK for TouchQue Authenticator and TouchQue Login, with Rails integration (Railtie, controller concerns) and a Rack relay for @touchque/web."
  spec.homepage = "https://touchque.com"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"
  spec.metadata = {
    "source_code_uri" => "https://github.com/Touchque/touchque-ruby",
    "changelog_uri" => "https://github.com/Touchque/touchque-ruby/blob/main/CHANGELOG.md",
    "documentation_uri" => "https://support.touchque.com",
    "rubygems_mfa_required" => "true"
  }
  spec.files = Dir["lib/**/*.rb", "README.md", "CHANGELOG.md", "LICENSE"]
  spec.require_paths = ["lib"]
  # Only the standard library (net/http, openssl, json) at run time.
end
