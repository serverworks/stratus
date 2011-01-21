# -*- coding: utf-8; mode: ruby; -*-

module Stratus::AWS::IAM
  class Client
    def initialize(access_key_id, secret_access_key)
      @base = Stratus::AWS::IAM::Base.new(access_key_id, secret_access_key)
    end

    # @return [Array<Stratus::AWS::IAM::Group>]
    def groups
      groups = []

      @base.list_groups['ListGroupsResult']['Groups']['member'].each do |i|
        groups << Group.new(i)
      end

      return groups
    end
  end
end
