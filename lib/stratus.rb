# -*- coding: utf-8; mode: ruby; -*-

module Stratus
end

# rubygems is only needed in 1.8
require 'rubygems' if RUBY_VERSION[2] == ?8

Dir[File.join(File.dirname(__FILE__), 'stratus/**/*.rb')].sort.each { |lib| require lib }
