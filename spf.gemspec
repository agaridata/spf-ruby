$:.unshift File.expand_path("../lib", __FILE__)
require 'spf/version'

Gem::Specification.new do |s|
  s.name = "spf"
  s.version = SPF::VERSION

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Andrew Flury", "Julian Mehnle", "Jacob Rideout"]
  s.date = "2015-04-29"
  s.description = "    An object-oriented Ruby implementation of the Sender Policy Framework (SPF)\n    e-mail sender authentication system, fully compliant with RFC 4408.\n"
  s.email = ["code@agari.com", "aflury@agari.com", "jmehnle@agari.com", "jrideout@agari.com"]
  s.extra_rdoc_files = [
    "README.rdoc"
  ]
  s.files = [
    ".document",
    ".rspec",
    "Gemfile",
    "Gemfile.lock",
    "README.rdoc",
    "Rakefile",
    "lib/spf.rb",
    "lib/spf/error.rb",
    "lib/spf/eval.rb",
    "lib/spf/macro_string.rb",
    "lib/spf/model.rb",
    "lib/spf/request.rb",
    "lib/spf/result.rb",
    "lib/spf/util.rb",
    "lib/spf/version.rb",
    "lib/spf/ext/resolv.rb",
    "spec/spec_helper.rb",
    "spec/spf_spec.rb",
    "spf.gemspec"
  ]
  s.homepage = "https://github.com/agaridata/spf-ruby"
  s.licenses = ["none (all rights reserved)"]
  s.rubygems_version = "2.4.6"
  s.summary = "Implementation of the Sender Policy Framework"

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<ruby-ip>, ["~> 0.9.1"])
      s.add_development_dependency(%q<rake>, [">= 10"])
      s.add_development_dependency(%q<rspec>, ["~> 3.10"])
      s.add_development_dependency(%q<rdoc>, [">= 6.3.0"])
      s.add_development_dependency(%q<bundler>, [">= 2.4.13"])
      s.add_development_dependency(%q<simplecov>)
    else
      s.add_dependency(%q<ruby-ip>, ["~> 0.9.1"])
      s.add_dependency(%q<rake>, [">= 10"])
      s.add_dependency(%q<rspec>, ["~> 3.10"])
      s.add_dependency(%q<rdoc>, [">= 6.3.0"])
      s.add_dependency(%q<bundler>, [">= 2.4.13"])
      s.add_dependency(%q<simplecov>)
    end
  else
    s.add_dependency(%q<ruby-ip>, ["~> 0.9.1"])
    s.add_dependency(%q<rake>, [">= 10"])
    s.add_dependency(%q<rspec>, ["~> 3.10"])
    s.add_dependency(%q<rdoc>, [">= 6.3.0"])
    s.add_dependency(%q<bundler>, [">= 2.4.13"])
    s.add_dependency(%q<simplecov>)
  end
end

