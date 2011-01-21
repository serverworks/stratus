# -*- coding: utf-8; mode: ruby; -*-

require 'ostruct'
require 'active_support/inflector'

module Stratus::AWS::IAM
  class Group < OpenStruct
    def initialize(params)
      attributes = {}
      params.each { |k, v| attributes[k.underscore] = v }
      super(attributes)
    end
  end
end
