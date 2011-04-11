# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{stratus}
  s.version = "1.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Serverworks Co.,Ltd."]
  s.date = %q{2011-04-11}
  s.description = %q{Interface classes for the AWS Identity and Access Management (IAM)}
  s.email = %q{tech@serverworks.co.jp}
  s.executables = ["iamsh", "iamsh-setup.rb"]
  s.extra_rdoc_files = [
    "LICENSE",
    "README.markdown"
  ]
  s.files = [
    "History.txt",
    "LICENSE",
    "README.markdown",
    "Rakefile",
    "VERSION",
    "bin/iamsh",
    "lib/stratus.rb",
    "lib/stratus/aws.rb",
    "lib/stratus/aws/iam.rb",
    "lib/stratus/aws/iam/client.rb",
    "lib/stratus/aws/iam/group.rb",
    "spec/spec.opts",
    "spec/spec_helper.rb",
    "spec/stratus/aws/iam/client_spec.rb",
    "spec/stratus/aws/iam/group_spec.rb",
    "spec/stratus/aws/iam_spec.rb",
    "spec/stratus_spec.rb"
  ]
  s.homepage = %q{http://github.com/serverworks/stratus}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.5.0}
  s.summary = %q{Interface classes for the AWS Identity and Access Management (IAM)}
  s.test_files = [
    "spec/spec_helper.rb",
    "spec/stratus/aws/iam/client_spec.rb",
    "spec/stratus/aws/iam/group_spec.rb",
    "spec/stratus/aws/iam_spec.rb",
    "spec/stratus_spec.rb"
  ]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activesupport>, [">= 2.3.10"])
      s.add_runtime_dependency(%q<xml-simple>, [">= 1.0.12"])
      s.add_runtime_dependency(%q<rest-client>, [">= 1.6.1"])
      s.add_development_dependency(%q<rcov>, [">= 0.9.6"])
      s.add_development_dependency(%q<rspec>, [">= 1.2.9"])
    else
      s.add_dependency(%q<activesupport>, [">= 2.3.10"])
      s.add_dependency(%q<xml-simple>, [">= 1.0.12"])
      s.add_dependency(%q<rest-client>, [">= 1.6.1"])
      s.add_dependency(%q<rcov>, [">= 0.9.6"])
      s.add_dependency(%q<rspec>, [">= 1.2.9"])
    end
  else
    s.add_dependency(%q<activesupport>, [">= 2.3.10"])
    s.add_dependency(%q<xml-simple>, [">= 1.0.12"])
    s.add_dependency(%q<rest-client>, [">= 1.6.1"])
    s.add_dependency(%q<rcov>, [">= 0.9.6"])
    s.add_dependency(%q<rspec>, [">= 1.2.9"])
  end
end

