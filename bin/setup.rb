#!/usr/bin/env ruby

if ENV['AMAZON_ACCESS_KEY_ID'] && ENV['AMAZON_SECRET_ACCESS_KEY']
  opts = {
    :access_key_id => ENV['AMAZON_ACCESS_KEY_ID'],
    :secret_access_key => ENV['AMAZON_SECRET_ACCESS_KEY']
  }
  @iam = Stratus::AWS::IAM::Base.new(opts[:access_key_id], opts[:secret_access_key])
end
