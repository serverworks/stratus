# -*- ruby -*-

require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gem|
    gem.name = "stratus"
    gem.summary = %Q{Interface classes for the AWS Identity and Access Management (IAM)}
    gem.description = %Q{Interface classes for the AWS Identity and Access Management (IAM)}
    gem.email = "support@serverworks.co.jp"
    gem.homepage = "http://github.com/serverworks/stratus"
    gem.authors = ["Serverworks Co.,Ltd."]
    gem.add_dependency('xml-simple', '>= 1.0.12')
    gem.add_dependency('rest-client', '>= 1.6.1')
    gem.add_development_dependency('rcov', '>= 0.9.6')
    gem.add_development_dependency('rspec', '>= 1.2.9')
    gem.files = FileList['bin/iamsh', 'lib/**/*.rb', '[A-Z]*', 'spec/**/*'].to_a
  end
rescue LoadError
  puts "Jeweler (or a dependency) not available. Install it with: gem install jeweler"
end

require 'spec/rake/spectask'
Spec::Rake::SpecTask.new(:spec) do |spec|
  spec.libs << 'lib' << 'spec'
  spec.spec_files = FileList['spec/**/*_spec.rb']
end

Spec::Rake::SpecTask.new(:rcov) do |spec|
  spec.libs << 'lib' << 'spec'
  spec.pattern = 'spec/**/*_spec.rb'
  spec.rcov = true
end

task :spec => :check_dependencies

task :default => :spec

begin
  require 'yard'
  YARD::Rake::YardocTask.new do |t|
    #t.files   = ['lib/**/*.rb']
  end
rescue LoadError
  puts "YARD (or a dependency) not available. Install it with: [sudo] gem install yard"
end

# vim: syntax=Ruby
