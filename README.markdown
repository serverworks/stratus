Stratus
====

Stratus is a client interface for the [AWS Identity and Access Management (IAM)](http://aws.amazon.com/documentation/iam/) Services.

It was developed to for usage in the Japanese AWS management console service [Cloudworks](http://www.cloudworks.jp/).

REQUIREMENTS:
----

* Ruby 1.8.7 or 1.9.2
* activesupport gem
* xml-simple gem
* rest-client gem
* json_pure or json gem (optionally)

INSTALL:
----

    $ gem install stratus

TESTING:
----

Currently, spec task only works for RSpec 1.

    $ rake spec

USAGE EXAMPLE:
----

### As interactive shell

You can run interactive shell `iamsh' and call IAM API.

    $ export AMAZON_ACCESS_KEY_ID=XXXXX
    $ export AMAZON_SECRET_ACCESS_KEY=XXXXX
    $ iamsh
    
        @iam defined.
    
        Examples to try:
    
          returns : all iam public methods
          >> @iam.methods.sort
    
          returns : get all Amazon IAM groups.
          >> @iam.list_groups
    
    Welcome to IRB.
    >>

Create a new IAM user by CreateUser API.

    >> @iam.create_user :user_name => 'john'
    >> result = @iam.list_users
    >> puts result['ListUsersResult']['Users']['member'].inspect
    [{"UserName"=>"john", "Arn"=>"arn:aws:iam::000000000000:user/john", "Path"=>"/", "UserId"=>"XXXXXXXXXXXXXXXXXXXX"}]

Then create an user policy JSON string.

    >> policy = {}
    >> policy['Statement'] = [{
      'Effect' => 'Allow',
      'Action' => 'ec2:Describe*',
      'Resource' => '*'
    }]
    >> require 'json'
    >> policy = policy.to_json

And put it by PutUserPolicy API.

    >> @iam.put_user_policy :user_name => 'john', :policy_name => 'AllowDescribeEC2', :policy_document => policy
    >> result = @iam.get_user_policy :user_name => 'john', :policy_name => 'AllowDescribeEC2'
    >> result['GetUserPolicyResult']['PolicyDocument']
    "{\"Statement\":[{\"Action\":\"ec2:Describe*\",\"Resource\":\"*\",\"Effect\":\"Allow\"}]}"

Delete an user policy and user.

    >> @iam.delete_user_policy :user_name => 'john', :policy_name => 'AllowDescribeEC2'
    >> @iam.delete_user :user_name => 'john'

### As library

You can require the library and call IAM API from any ruby script.

    require 'rubygems'
    require 'stratus'
    
    iam = Stratus::AWS::IAM::Base.new('YOUR_ACCESS_KEY_ID', 'YOUR_SECRET_ACCESS_KEY')
    result = iam.create_group :group_name => 'Developers'
    group = result['CreateGroupResult']['Group']
    puts "Group ARN is #{group['Arn']}"

Read the [IAM API Reference](http://docs.amazonwebservices.com/IAM/latest/APIReference/) for further information.

REFERENCES:
----

* [Using AWS Identity and Access Management](http://docs.amazonwebservices.com/IAM/latest/UserGuide/)
* [AWS Identity and Access Management API Reference](http://docs.amazonwebservices.com/IAM/latest/APIReference/)

LICENSE:
----

This software is licensed under the MIT licenses.

COPYRIGHT:
----

Copyright (c) 2010 Serverworks Co.,Ltd. See LICENSE for details.
