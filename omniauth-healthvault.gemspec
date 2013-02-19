# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-healthvault/version'

Gem::Specification.new do |gem|
  gem.name          = "omniauth-healthvault"
  gem.version       = Omniauth::Healthvault::VERSION
  gem.authors       = ["Andrey Voronkov"]
  gem.email         = ["andrey.voronkov@medm.com"]
  gem.description   = %q{Microsoft HealthVault strategy for OmniAuth}
  gem.summary       = %q{Microsoft HealthVault strategy for OmniAuth}
  gem.homepage      = "https://github.com/Antiarchitect/omniauth-healthvault"
  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency 'omniauth', '~> 1.1.0'
end
