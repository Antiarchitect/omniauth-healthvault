# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-healthvault/version'

Gem::Specification.new do |gem|
  gem.name          = "omniauth-healthvault"
  gem.version       = Omniauth::Healthvault::VERSION
  gem.authors       = ["Andrey Voronkov"]
  gem.email         = ["andrey.voronkov@medm.com"]
  gem.description   = %q{This is the unofficial OmniAuth strategy for authenticating to Microsoft HealthVault.}
  gem.summary       = %q{This is the unofficial OmniAuth strategy for authenticating to Microsoft HealthVault.}
  gem.homepage      = "https://github.com/Antiarchitect/omniauth-healthvault"
  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency 'builder', '~> 3.0'
  gem.add_dependency 'faraday', '~> 0.8'
  gem.add_dependency 'multi_xml', '~> 0.5'
  gem.add_dependency 'omniauth', '~> 1.2'
end
