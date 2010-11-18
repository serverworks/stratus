require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../../../lib/stratus')
require File.expand_path(File.dirname(__FILE__) + '/../../../lib/stratus/aws')
require File.expand_path(File.dirname(__FILE__) + '/../../../lib/stratus/aws/iam')

describe "Stratus::AWS::IAM::Base" do
  before(:each) do
    @iam = Stratus::AWS::IAM::Base.new('aaa', 'bbb')
  end

  context "#get_group" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => get_group_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a intended group attributes." do
      result = @iam.get_group(:group_name => 'NewGroup1')
      result.should have_key('GetGroupResult')
      result['GetGroupResult'].should have_key('Users')
      result['GetGroupResult'].should have_key('Group')
      users = result['GetGroupResult']['Users']
      users.should be_nil
      group = result['GetGroupResult']['Group']
      group.should have_key('GroupId')
      group.should have_key('GroupName')
      group.should have_key('Path')
      group.should have_key('Arn')
    end

    it "must raise ArgumentError if the group_name parameter haven't been passed." do
      lambda { @iam.get_group }.should raise_error(ArgumentError)
    end
  end


  context "#create_group" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => create_group_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to create a new group" do
      result = @iam.create_group(:group_name => 'NewGroup1')
      result.should have_key('CreateGroupResult')
      result['CreateGroupResult'].should have_key('Group')
      group = result['CreateGroupResult']['Group']
      group.should have_key('GroupId')
      group.should have_key('GroupName')
      group.should have_key('Path')
      group.should have_key('Arn')
    end

    it "must raise ArgumentError if the group_name parameter haven't been passed." do
      lambda { @iam.create_group }.should raise_error(ArgumentError)
    end
  end

  context "#delete_group" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => delete_group_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to delete a intended group" do
      result = @iam.delete_group(:group_name => 'NewGroup1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the group_name parameter haven't been passed." do
      lambda { @iam.delete_group }.should raise_error(ArgumentError)
    end
  end

  it "#list_groups" do
    response = stub(RestClient::Response, :code => '200', :to_str => list_groups_response, :empty? => false)
    RestClient.stub!(:get).and_return(response)
    result = @iam.list_groups
    result['ListGroupsResult']['Groups']['member'].should have(1).groups
  end

  context "#update_group" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => update_group_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to update the intended group attributes" do
      result = @iam.update_group(:group_name => 'Group1', :new_group_name => 'NewGroup1')
      result.should have_key('ResponseMetadata')

      # The Amazon IAM UpdateGroup API is work,
      # But the response does not have a UpdateGroupResult tag.
      # Is this a Amazon's documentation or implementation Bug?
      #
      #result.should have_key('UpdateGroupResult')
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda { @iam.update_group }.should raise_error(ArgumentError)
    end
  end

  context "#add_user_to_group" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => add_user_to_group_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to add the new user to the group" do
      result = @iam.add_user_to_group(:group_name => 'Group1', :user_name => 'User1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda { @iam.add_user_to_group(:group_name => 'Group1') }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda { @iam.add_user_to_group(:user_name => 'User1') }.should raise_error(ArgumentError)
    end
  end

  context "#remove_user_from_group" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => remove_user_from_group_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to remove the new user to the group" do
      result = @iam.remove_user_from_group(:group_name => 'Group1', :user_name => 'User1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda { @iam.remove_user_from_group(:group_name => 'Group1') }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda { @iam.remove_user_from_group(:user_name => 'User1') }.should raise_error(ArgumentError)
    end
  end

  context "#get_user" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => get_user_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a user attributes" do
      result = @iam.get_user
      result.should have_key('GetUserResult')
      result['GetUserResult'].should have_key('User')
      user = result['GetUserResult']['User']
      user['UserId'].should_not be_nil
      user['Arn'].should_not be_nil

      # if the user that just getting attributes is not created by the CreateUser API,
      # GetUser API result does not have following keys.
      user['UserName'].should be_nil
      user['Path'].should be_nil
    end

    context "if :user_name option passed" do
      before(:each) do
        response = stub(RestClient::Response, :code => '200', :to_str => get_user_response(:with_user_name => true), :empty? => false)
        RestClient.stub!(:get).and_return(response)
      end

      it "must be able to get a user attributes" do
        result = @iam.get_user(:user_name => 'User1')
        result.should have_key('GetUserResult')
        result['GetUserResult'].should have_key('User')
        user = result['GetUserResult']['User']
        user['UserId'].should_not be_nil
        user['Arn'].should_not be_nil
        user['UserName'].should_not be_nil
        user['Path'].should_not be_nil
      end
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with('GetUser', {}).once.and_return(get_user_response)
      @iam.get_user
    end
  end

  context "#create_user" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => create_user_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to create a new user" do
      result = @iam.create_user(:user_name => 'NewUser')
      user = result['CreateUserResult']['User']
      user.should_not be_nil
      user['UserId'].should == 'AIDAI6PGTVSCYFGUNXK4G'
      user['Path'].should == '/'
      user['UserName'].should == 'NewUser'
      user['Arn'].should == 'arn:aws:iam::832248165982:user/NewUser'
    end

    it "must raise ArgumentError if the user_name parameter haven't been passed." do
      lambda { @iam.create_user }.should raise_error(ArgumentError)
    end
  end

  context "#delete_user" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => delete_user_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to delete a existing user" do
      result = @iam.delete_user(:user_name => 'NewUser')
      result.should have_key('ResponseMetadata')
      result['ResponseMetadata'].should have_key('RequestId')
    end

    it "must raise ArgumentError if the user_name parameter haven't been passed." do
      lambda { @iam.delete_user }.should raise_error(ArgumentError)
    end
  end

  context "#list_users" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => list_users_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to list existing users" do
      result = @iam.list_users
      result.should have_key('ListUsersResult')
      result['ListUsersResult'].should have_key('Users')
      result['ListUsersResult']['Users'].should have_key('member')
      users = result['ListUsersResult']['Users']['member']
      users.should be_kind_of(Array)
      users.each do |user|
        user['UserId'].should_not be_empty
        user['Path'].should == '/'
        user['UserName'].should_not be_empty
        user['Arn'].should_not be_empty
      end
    end
  end

  context "#list_groups_for_user" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => list_groups_for_user_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get groups for the intended user" do
      result = @iam.list_groups_for_user(:user_name => 'User1')
      result.should have_key('ListGroupsForUserResult')
      result['ListGroupsForUserResult'].should have_key('Groups')
      result['ListGroupsForUserResult']['Groups'].should be_nil
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda { @iam.list_groups_for_user }.should raise_error(ArgumentError)
    end
  end

  context "#update_user" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => update_user_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to update the intended user attributes" do
      result = @iam.update_user(:user_name => 'User1', :new_user_name => 'NewUser1')
      result.should have_key('ResponseMetadata')

      # The Amazon IAM UpdateUser API is work,
      # But the response does not have a UpdateUserResult tag.
      # Is this a Amazon's documentation or implementation Bug?
      #
      #result.should have_key('UpdateUserResult')
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda { @iam.update_user }.should raise_error(ArgumentError)
    end
  end

  context "#create_access_key" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => create_access_key_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to create a new access key" do
      result = @iam.create_access_key(:user_name => 'User1')
      result.should have_key('CreateAccessKeyResult')
      result['CreateAccessKeyResult'].should have_key('AccessKey')
      result['CreateAccessKeyResult']['AccessKey'].should_not be_nil
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with('CreateAccessKey', {}).once.and_return(create_access_key_response)
      @iam.create_access_key
    end
  end

  context "#delete_access_key" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => delete_access_key_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to delete a intended access key" do
      result = @iam.delete_access_key(:access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :user_id => 'User1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :access_key_id option haven't been passed." do
      lambda { @iam.delete_access_key }.should raise_error(ArgumentError)
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with(
        'DeleteAccessKey', {'AccessKeyId' => 'AKIAXXXXXXXXXXXXXXXX'}
      ).once.and_return(delete_access_key_response)
      @iam.delete_access_key(:access_key_id => 'AKIAXXXXXXXXXXXXXXXX')
    end
  end

  context "#update_access_key" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => update_access_key_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to update a intended access key" do
      result = @iam.update_access_key(:access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :status => 'Active', :user_id => 'User1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :access_key_id option haven't been passed." do
      lambda {
        @iam.update_access_key(:user_name => 'User1', :status => 'Active')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :status option haven't been passed." do
      lambda {
        @iam.update_access_key(:user_name => 'User1', :access_key_id => 'AKIAXXXXXXXXXXXXXXXX')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if invalid :status option have been passed." do
      lambda {
        @iam.update_access_key(:user_name => 'User1', :access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :status => 'active')
        @iam.update_access_key(:user_name => 'User1', :access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :status => :active)
        @iam.update_access_key(:user_name => 'User1', :access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :status => 'Active')
      }.should_not raise_error(ArgumentError)
      lambda {
        @iam.update_access_key(:user_name => 'User1', :access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :status => 'XXXX')
      }.should raise_error(ArgumentError)
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with(
        'UpdateAccessKey', {'AccessKeyId' => 'AKIAXXXXXXXXXXXXXXXX', 'Status' => 'Inactive'}
      ).once.and_return(update_access_key_response)
      @iam.update_access_key(:access_key_id => 'AKIAXXXXXXXXXXXXXXXX', :status => :inactive)
    end
  end

  context "#list_access_keys" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => list_access_keys_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a list of access keys" do
      result = @iam.list_access_keys(:user_name => 'User1')
      result.should have_key('ListAccessKeysResult')
      result['ListAccessKeysResult'].should have_key('AccessKeyMetadata')
      result['ListAccessKeysResult']['AccessKeyMetadata'].should have_key('member')
      result['ListAccessKeysResult']['AccessKeyMetadata']['member'].should be_kind_of(Array)
      result['ListAccessKeysResult']['AccessKeyMetadata']['member'].each do |key|
        key['UserName'].should_not be_nil
        key['AccessKeyId'].should_not be_nil
        key['Status'].should_not be_nil
      end
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with('ListAccessKeys', {}).once.and_return(list_access_keys_response)
      @iam.list_access_keys
    end
  end

  context "#get_group_policy" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => get_group_policy_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a intended group policy" do
      result = @iam.get_group_policy(:group_name => 'Group1', :policy_name => 'Policy1')
      result.should have_key('GetGroupPolicyResult')
      result['GetGroupPolicyResult'].should have_key('GroupName')
      result['GetGroupPolicyResult'].should have_key('PolicyName')
      result['GetGroupPolicyResult'].should have_key('PolicyDocument')
      result['GetGroupPolicyResult']['GroupName'].should_not be_empty
      result['GetGroupPolicyResult']['PolicyName'].should_not be_empty
      result['GetGroupPolicyResult']['PolicyDocument'].should_not be_empty
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda {
        @iam.get_group_policy(:policy_name => 'Policy1')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_name option haven't been passed." do
      lambda {
        @iam.get_group_policy(:group_name => 'Group1')
      }.should raise_error(ArgumentError)
    end
  end

  context "#put_group_policy" do
    before(:each) do
      @policy = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
      response = stub(RestClient::Response, :code => '200', :to_str => put_group_policy_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to put a new group policy" do
      result = @iam.put_group_policy(:group_name => 'Group1', :policy_name => 'Policy1', :policy_document => @policy)
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda {
        @iam.put_group_policy(:policy_name => 'Policy1', :policy_document => @policy)
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_name option haven't been passed." do
      lambda {
        @iam.put_group_policy(:group_name => 'Group1', :policy_document => @policy)
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_document option haven't been passed." do
      lambda {
        @iam.put_group_policy(:group_name => 'Group1', :policy_name => 'Policy1')
      }.should raise_error(ArgumentError)
    end
  end

  context "#delete_group_policy" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => delete_group_policy_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to delete intended group policy" do
      result = @iam.delete_group_policy(:group_name => 'Group1', :policy_name => 'Policy1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda {
        @iam.delete_group_policy(:policy_name => 'Policy1')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_name option haven't been passed." do
      lambda {
        @iam.delete_group_policy(:group_name => 'Group1')
      }.should raise_error(ArgumentError)
    end
  end

  context "#list_group_policies" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => list_group_policies_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a list of group policies" do
      result = @iam.list_group_policies(:group_name => 'Group1')
      result.should have_key('ListGroupPoliciesResult')
      result['ListGroupPoliciesResult'].should have_key('PolicyNames')
      result['ListGroupPoliciesResult']['PolicyNames'].should have_key('member')
      result['ListGroupPoliciesResult']['PolicyNames']['member'].should be_kind_of(Array)
      result['ListGroupPoliciesResult']['PolicyNames']['member'].each do |policy_name|
        policy_name.should_not be_nil
      end
    end

    it "must raise ArgumentError if the :group_name option haven't been passed." do
      lambda {
        @iam.list_group_policies
      }.should raise_error(ArgumentError)
    end
  end

  context "#get_user_policy" do
    before(:all) { require 'json' }
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => get_user_policy_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a intended user policy" do
      result = @iam.get_user_policy(:user_name => 'User1', :policy_name => 'Policy1')
      result.should have_key('GetUserPolicyResult')
      result['GetUserPolicyResult'].should have_key('UserName')
      result['GetUserPolicyResult'].should have_key('PolicyName')
      result['GetUserPolicyResult'].should have_key('PolicyDocument')
      result['GetUserPolicyResult']['UserName'].should_not be_empty
      result['GetUserPolicyResult']['PolicyName'].should_not be_empty
      result['GetUserPolicyResult']['PolicyDocument'].should_not be_empty
    end

    it "must return a policy document formated by JSON" do
      result = @iam.get_user_policy(:user_name => 'User1', :policy_name => 'Policy1')
      lambda {
        policy = JSON.parse(result['GetUserPolicyResult']['PolicyDocument'])
        policy.should have_key('Statement')
      }.should_not raise_error(JSON::ParserError)
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda {
        @iam.get_user_policy(:policy_name => 'Policy1')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_name option haven't been passed." do
      lambda {
        @iam.get_user_policy(:user_name => 'User1')
      }.should raise_error(ArgumentError)
    end
  end

  context "#put_user_policy" do
    before(:each) do
      @policy = '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
      response = stub(RestClient::Response, :code => '200', :to_str => put_user_policy_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to put a new user policy" do
      result = @iam.put_user_policy(:user_name => 'User1', :policy_name => 'Policy1', :policy_document => @policy)
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda {
        @iam.put_user_policy(:policy_name => 'Policy1', :policy_document => @policy)
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_name option haven't been passed." do
      lambda {
        @iam.put_user_policy(:user_name => 'User1', :policy_document => @policy)
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_document option haven't been passed." do
      lambda {
        @iam.put_user_policy(:user_name => 'User1', :policy_name => 'Policy1')
      }.should raise_error(ArgumentError)
    end
  end

  context "#delete_user_policy" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => delete_user_policy_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to delete intended user policy" do
      result = @iam.delete_user_policy(:user_name => 'User1', :policy_name => 'Policy1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda {
        @iam.delete_user_policy(:policy_name => 'Policy1')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :policy_name option haven't been passed." do
      lambda {
        @iam.delete_user_policy(:user_name => 'User1')
      }.should raise_error(ArgumentError)
    end
  end

  context "#list_user_policies" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => list_user_policies_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a list of user policies" do
      result = @iam.list_user_policies(:user_name => 'User1')
      result.should have_key('ListUserPoliciesResult')
      result['ListUserPoliciesResult'].should have_key('PolicyNames')
      result['ListUserPoliciesResult']['PolicyNames'].should have_key('member')
      result['ListUserPoliciesResult']['PolicyNames']['member'].should be_kind_of(Array)
      result['ListUserPoliciesResult']['PolicyNames']['member'].each do |policy_name|
        policy_name.should_not be_nil
      end
    end

    it "must raise ArgumentError if the :user_name option haven't been passed." do
      lambda {
        @iam.list_user_policies
      }.should raise_error(ArgumentError)
    end
  end

  context "#upload_signing_certificate" do
    before(:each) do
      @response = stub(RestClient::Response, :code => '200', :to_str => upload_signing_certificate_response, :empty? => false)
      RestClient.stub!(:post).and_return(@response)
    end

    it "must be able to upload a new certification" do
      RestClient.should_not_receive(:get)
      RestClient.should_receive(:post).and_return(@response)
      result = @iam.upload_signing_certificate(:user_name => 'User1', :certificate_body => dummy_certificate)
      result.should have_key('UploadSigningCertificateResult')
      result['UploadSigningCertificateResult'].should have_key('Certificate')
      result['UploadSigningCertificateResult']['Certificate'].should have_key('CertificateBody')
      result['UploadSigningCertificateResult']['Certificate']['CertificateBody'].gsub(/^ +/, "").should == dummy_certificate
    end

    it "must raise ArgumentError if the :certificate_body option haven't been passed." do
      lambda {
        @iam.upload_signing_certificate(:user_name => 'User1')
      }.should raise_error(ArgumentError)
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with(
        'UploadSigningCertificate', {'CertificateBody' => dummy_certificate}
      ).once.and_return(upload_signing_certificate_response)
      @iam.upload_signing_certificate(:certificate_body => dummy_certificate)
    end
  end

  context "#update_signing_certificate" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => update_signing_certificate_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to update a intended certificate" do
      result = @iam.update_signing_certificate(:certificate_id => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA', :status => 'Active', :user_id => 'User1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :certificate_id option haven't been passed." do
      lambda {
        @iam.update_signing_certificate(:user_name => 'User1', :status => 'Active')
      }.should raise_error(ArgumentError)
    end

    it "must raise ArgumentError if the :status option haven't been passed." do
      lambda {
        @iam.update_signing_certificate(:user_name => 'User1', :certificate_id => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA')
      }.should raise_error(ArgumentError)
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with(
        'UpdateSigningCertificate', {'CertificateId' => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA', 'Status' => 'Active'}
      ).once.and_return(update_signing_certificate_response)
      @iam.update_signing_certificate(:certificate_id => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA', :status => :active)
    end
  end

  context "#delete_signing_certificate" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => delete_signing_certificate_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to delete a intended certificate" do
      result = @iam.delete_signing_certificate(:certificate_id => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA', :user_id => 'User1')
      result.should have_key('ResponseMetadata')
    end

    it "must raise ArgumentError if the :certificate_id option haven't been passed." do
      lambda {
        @iam.delete_signing_certificate(:user_name => 'User1')
      }.should raise_error(ArgumentError)
    end

    it "must call the 'call_api' internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with(
        'DeleteSigningCertificate', {'CertificateId' => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA'}
      ).once.and_return(delete_signing_certificate_response)
      @iam.delete_signing_certificate(:certificate_id => 'PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA')
    end
  end

  context "#list_signing_certificates" do
    before(:each) do
      response = stub(RestClient::Response, :code => '200', :to_str => list_signing_certificates_response, :empty? => false)
      RestClient.stub!(:get).and_return(response)
    end

    it "must be able to get a list of certificates" do
      result = @iam.list_signing_certificates(:user_name => 'User1')
      result.should have_key('ListSigningCertificatesResult')
      result['ListSigningCertificatesResult'].should have_key('Certificates')
      result['ListSigningCertificatesResult']['Certificates'].should have_key('member')
      result['ListSigningCertificatesResult']['Certificates']['member'].should be_kind_of(Array)
      result['ListSigningCertificatesResult']['Certificates']['member'].each do |certificate|
        certificate.should have_key('CertificateId')
      end
    end

    it "must call the 'call_api' method internally without 'UserName' parameter if :user_name option not given" do
      @iam.should_receive(:call_api).with('ListSigningCertificates', {}).once.and_return(list_signing_certificates_response)
      @iam.list_signing_certificates()
    end

    it "must call the 'call_api' method internally with 'Marker' parameter if :marker option given" do
      @iam.should_receive(:call_api).with(
        'ListSigningCertificates', {'Marker' => 'marker'}
      ).once.and_return(list_signing_certificates_response)
      result = @iam.list_signing_certificates(:marker => 'marker')
    end

    it "must call the 'call_api' method internally with 'MaxItems' parameter if :max_items option given" do
      @iam.should_receive(:call_api).with(
        'ListSigningCertificates', {'MaxItems' => 10}
      ).once.and_return(list_signing_certificates_response)
      @iam.list_signing_certificates(:max_items => 10)
    end

    it "must call the 'call_api' method internally with 'Marker' and 'MaxItems' parameter if :marker and :max_items option given" do
      @iam.should_receive(:call_api).with(
        'ListSigningCertificates', {'Marker' => 'marker', 'MaxItems' => 10}
      ).once.and_return(list_signing_certificates_response)
      @iam.list_signing_certificates(:marker => 'marker', :max_items => 10)
    end
  end

  def get_group_response
    return <<-RES
      <GetGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <GetGroupResult>
          <Users/>
          <IsTruncated>false</IsTruncated>
          <Group>
            <GroupId>AGPAIDO7XVSF6MYKVGFIA</GroupId>
            <GroupName>NewGroup1</GroupName>
            <Path>/</Path>
            <Arn>arn:aws:iam::832248165982:group/NewGroup1</Arn>
          </Group>
        </GetGroupResult>
        <ResponseMetadata>
          <RequestId>ea3adc94-ba45-11df-a356-3d1e141e353d</RequestId>
        </ResponseMetadata>
      </GetGroupResponse>
    RES
  end

  def create_group_response
    return <<-RES
      <CreateGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <CreateGroupResult>
          <Group>
            <GroupId>AGPAJHLP6LD46WOZLH64A</GroupId>
            <GroupName>NewGroup1</GroupName>
            <Path>/</Path>
            <Arn>arn:aws:iam::832248165982:group/NewGroup1</Arn>
          </Group>
        </CreateGroupResult>
        <ResponseMetadata>
          <RequestId>496c3bad-ba3f-11df-a8c6-9f6df870c6f2</RequestId>
        </ResponseMetadata>
      </CreateGroupResponse>
    RES
  end

  def delete_group_response
    return <<-RES
      <DeleteGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>06b3f9ae-ba42-11df-89f0-69aaa229db19</RequestId>
        </ResponseMetadata>
      </DeleteGroupResponse>
    RES
  end

  def list_groups_response
    [
     '<ListGroupsResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">',
     '<ListGroupsResult>',
     '<IsTruncated>false</IsTruncated>',
     '<Groups>',
     '<member>',
     '<GroupId>AGPAIBHPCA4Z3Y2HAR3SE</GroupId>',
     '<GroupName>Development</GroupName>',
     '<Path>/</Path>',
     '<Arn>arn:aws:iam::326454305199:group/Development</Arn>',
     '</member>',
     '</Groups>',
     '</ListGroupsResult>',
     '<ResponseMetadata>',
     '<RequestId>944a9b23-b97a-11df-996e-e7c1660b9998</RequestId>',
     '</ResponseMetadata>',
     '</ListGroupsResponse>',
    ].join("\n")
  end

  def update_group_response
    return <<-RES
      <UpdateGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>46f03346-ba49-11df-a1ef-f7061c8dca90</RequestId>
        </ResponseMetadata>
      </UpdateGroupResponse>
    RES
  end

  def add_user_to_group_response
    return <<-RES
      <AddUserToGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>f4606eb1-ba4e-11df-92f8-89ed818707d9</RequestId>
        </ResponseMetadata>
      </AddUserToGroupResponse>
    RES
  end

  def remove_user_from_group_response
    return <<-RES
      <RemoveUserFromGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>8294a061-ba51-11df-a518-4f7d9054fd5f</RequestId>
        </ResponseMetadata>
      </RemoveUserFromGroupResponse>
    RES
  end

  def create_user_response
    return <<-RES
      <CreateUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">$
        <CreateUserResult>$
          <User>$
            <UserId>AIDAI6PGTVSCYFGUNXK4G</UserId>$
            <Path>/</Path>$
            <UserName>NewUser</UserName>$
            <Arn>arn:aws:iam::832248165982:user/NewUser</Arn>$
          </User>$
        </CreateUserResult>$
        <ResponseMetadata>$
          <RequestId>dfeceb17-b98c-11df-aaf3-4191ccb1dcaa</RequestId>$
        </ResponseMetadata>$
      </CreateUserResponse>$
    RES
  end

  def delete_user_response
    return <<-RES
      <DeleteUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>2a91c5c6-b99b-11df-92f8-89ed818707d9</RequestId>
        </ResponseMetadata>
      </DeleteUserResponse>
    RES
  end

  def list_users_response
    return <<-RES
      <ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ListUsersResult>
          <Users>
            <member>
              <UserId>AIDAJPTEYQSGQ525SOKXW</UserId>
              <Path>/</Path>
              <UserName>NewUser</UserName>
              <Arn>arn:aws:iam::832248165982:user/NewUser</Arn>
            </member>
          </Users>
          <IsTruncated>false</IsTruncated>
        </ListUsersResult>
        <ResponseMetadata>
          <RequestId>6332d0e4-b99e-11df-a1ef-f7061c8dca90</RequestId>
        </ResponseMetadata>
      </ListUsersResponse>
    RES
  end

  def get_user_response(options = {:with_user_name => false})
    if options[:with_user_name]
      return <<-RES
        "<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
          <GetUserResult>
            <User>
              <UserId>AIDAJEDM3GIZBSIR6SSHK</UserId>
              <Path>/</Path>
              <UserName>User1</UserName>
              <Arn>arn:aws:iam::832248165982:user/User1</Arn>
            </User>
          </GetUserResult>
          <ResponseMetadata>
            <RequestId>6a98020f-ba24-11df-aaf3-4191ccb1dcaa</RequestId>
          </ResponseMetadata>
        </GetUserResponse>
      RES
    end

    return <<-RES
      <GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <GetUserResult>
          <User>
            <UserId>832248165982</UserId>
            <Arn>arn:aws:iam::832248165982:root</Arn>
          </User>
        </GetUserResult>
        <ResponseMetadata>
          <RequestId>e8f05387-ba23-11df-89f0-69aaa229db19</RequestId>
        </ResponseMetadata>
      </GetUserResponse>
    RES
  end

  def list_groups_for_user_response
    return <<-RES
      <ListGroupsForUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ListGroupsForUserResult>
          <IsTruncated>false</IsTruncated>
          <Groups/>
        </ListGroupsForUserResult>
        <ResponseMetadata>
          <RequestId>bf42415e-ba29-11df-a1ef-f7061c8dca90</RequestId>
        </ResponseMetadata>
      </ListGroupsForUserResponse>
    RES
  end

  def update_user_response
    return <<-RES
      <UpdateUserResponse xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\">
        <ResponseMetadata>
          <RequestId>5e00d1d4-ba31-11df-b738-6709d34e9585</RequestId>
        </ResponseMetadata>
      </UpdateUserResponse>
    RES
  end

  def create_access_key_response
    return <<-RES
      <CreateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <CreateAccessKeyResult>
          <AccessKey>
            <SecretAccessKey>XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</SecretAccessKey>
            <Status>Active</Status>
            <AccessKeyId>AKIAXXXXXXXXXXXXXXXX</AccessKeyId>
            <UserName>User1</UserName>
            <CreateDate>2010-09-07T07:53:29.546Z</CreateDate>
          </AccessKey>
        </CreateAccessKeyResult>
        <ResponseMetadata>
          <RequestId>00ee559f-ba55-11df-92f8-89ed818707d9</RequestId>
        </ResponseMetadata>
      </CreateAccessKeyResponse>
    RES
  end

  def delete_access_key_response
    return <<-RES
      <DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>cf5417f0-ba57-11df-996e-e7c1660b9998</RequestId>
        </ResponseMetadata>
      </DeleteAccessKeyResponse>
    RES
  end

  def update_access_key_response
    return <<-RES
      <UpdateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>dfbe66c0-ba63-11df-a356-3d1e141e353d</RequestId>
        </ResponseMetadata>
      </UpdateAccessKeyResponse>
    RES
  end

  def list_access_keys_response
    return <<-RES
      <ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ListAccessKeysResult>
          <IsTruncated>false</IsTruncated>
          <AccessKeyMetadata>
            <member>
              <Status>Active</Status>
              <AccessKeyId>AKIAXXXXXXXXXXXXXXXX</AccessKeyId>
              <UserName>User1</UserName>
              <CreateDate>2010-09-07T08:43:17Z</CreateDate>
            </member>
          </AccessKeyMetadata>
        </ListAccessKeysResult>
        <ResponseMetadata>
          <RequestId>f9460529-ba5b-11df-996e-e7c1660b9998</RequestId>
        </ResponseMetadata>
      </ListAccessKeysResponse>
    RES
  end

  def get_group_policy_response
    return <<-RES
      <GetGroupPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <GetGroupPolicyResult>
          <PolicyName>Policy1</PolicyName>
          <GroupName>Group1</GroupName>
          <PolicyDocument>%7B%22Statement%22%3A%5B%7B%22Resource%22%3A%22%2A%22%2C%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%7D%5D%7D</PolicyDocument>
        </GetGroupPolicyResult>
        <ResponseMetadata>
          <RequestId>84c5d59b-baec-11df-b3cb-6d0722822344</RequestId>
        </ResponseMetadata>
      </GetGroupPolicyResponse>
    RES
  end

  def put_group_policy_response
    return <<-RES
      <PutGroupPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>676431f9-bae9-11df-996e-e7c1660b9998</RequestId>
        </ResponseMetadata>
      </PutGroupPolicyResponse>
    RES
  end

  def delete_group_policy_response
    return <<-RES
      <DeleteGroupPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>27686694-bb08-11df-a8c6-9f6df870c6f2</RequestId>
        </ResponseMetadata>
      </DeleteGroupPolicyResponse>
    RES
  end

  def list_group_policies_response
    return <<-RES
      <ListGroupPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ListGroupPoliciesResult>
          <PolicyNames>
            <member>Policy1</member>
          </PolicyNames>
          <IsTruncated>false</IsTruncated>
        </ListGroupPoliciesResult>
        <ResponseMetadata>
          <RequestId>a8528a43-bb0b-11df-b3cb-6d0722822344</RequestId>
        </ResponseMetadata>
      </ListGroupPoliciesResponse>
    RES
  end

  def get_user_policy_response
    return <<-RES
      <GetUserPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <GetUserPolicyResult>
          <PolicyName>Policy1</PolicyName>
          <UserName>User1</UserName>
          <PolicyDocument>%7B%22Statement%22%3A%5B%7B%22Resource%22%3A%22%2A%22%2C%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%7D%5D%7D</PolicyDocument>
        </GetUserPolicyResult>
        <ResponseMetadata>
          <RequestId>c8a77c43-bb0e-11df-a518-4f7d9054fd5f</RequestId>
        </ResponseMetadata>
      </GetUserPolicyResponse>
    RES
  end

  def put_user_policy_response
    return <<-RES
      <PutUserPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>ec1ca2cb-bb0e-11df-996e-e7c1660b9998</RequestId>
        </ResponseMetadata>
      </PutUserPolicyResponse>
    RES
  end

  def delete_user_policy_response
    return <<-RES
      <DeleteUserPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>83c49d29-bb12-11df-996e-e7c1660b9998</RequestId>
        </ResponseMetadata>
      </DeleteUserPolicyResponse>
    RES
  end

  def list_user_policies_response
    return <<-RES
      <ListUserPoliciesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ListUserPoliciesResult>
          <PolicyNames>
            <member>Policy1</member>
          </PolicyNames>
          <IsTruncated>false</IsTruncated>
        </ListUserPoliciesResult>
        <ResponseMetadata>
          <RequestId>b84ad9d2-bb13-11df-aaf3-4191ccb1dcaa</RequestId>
        </ResponseMetadata>
      </ListUserPoliciesResponse>
    RES
  end

  def upload_signing_certificate_response
    return <<-RES
      <UploadSigningCertificateResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <UploadSigningCertificateResult>
          <Certificate>
            <Status>Active</Status>
            <CertificateId>PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA</CertificateId>
            <UserName>User1</UserName>
            <CertificateBody>-----BEGIN CERTIFICATE-----
      MIIBrjCCAVigAwIBAgIJAJAOioXmW9VvMA0GCSqGSIb3DQEBBQUAMBwxGjAYBgNV
      BAMTEU5vcmloaXRvIFlvc2hpb2thMB4XDTEwMDkwODA5MDgyM1oXDTEwMTAwODA5
      MDgyM1owHDEaMBgGA1UEAxMRTm9yaWhpdG8gWW9zaGlva2EwXDANBgkqhkiG9w0B
      AQEFAANLADBIAkEA0IDAJgXhdMhjLEiG1TMOZgeInMGidxVn0jukTZujWZ2iawpr
      B+Qgw4AOvfOOif1ZAzJ2N4Y3DOyuuEYTZhQ+nQIDAQABo30wezAdBgNVHQ4EFgQU
      7+EbzgqFJ5H4f+F8tVVclyuhAnswTAYDVR0jBEUwQ4AU7+EbzgqFJ5H4f+F8tVVc
      lyuhAnuhIKQeMBwxGjAYBgNVBAMTEU5vcmloaXRvIFlvc2hpb2thggkAkA6KheZb
      1W8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAANBAHumka+fYPGm15+8m4kq
      go6GPf+b8JYNClRmsus93/YdLSJJeXdTvaCcnBQWJCXaQ5UCr1qZ5Kiu9+0/Vk34
      nXg=
      -----END CERTIFICATE-----
      </CertificateBody>
            <UploadDate>2010-09-08T09:24:47Z</UploadDate>
          </Certificate>
        </UploadSigningCertificateResult>
        <ResponseMetadata>
          <RequestId>c6d0939c-bb2b-11df-a1ef-f7061c8dca90</RequestId>
        </ResponseMetadata>
      </UploadSigningCertificateResponse>
    RES
  end

  def dummy_certificate
    return <<-EOF
-----BEGIN CERTIFICATE-----
MIIBrjCCAVigAwIBAgIJAJAOioXmW9VvMA0GCSqGSIb3DQEBBQUAMBwxGjAYBgNV
BAMTEU5vcmloaXRvIFlvc2hpb2thMB4XDTEwMDkwODA5MDgyM1oXDTEwMTAwODA5
MDgyM1owHDEaMBgGA1UEAxMRTm9yaWhpdG8gWW9zaGlva2EwXDANBgkqhkiG9w0B
AQEFAANLADBIAkEA0IDAJgXhdMhjLEiG1TMOZgeInMGidxVn0jukTZujWZ2iawpr
B+Qgw4AOvfOOif1ZAzJ2N4Y3DOyuuEYTZhQ+nQIDAQABo30wezAdBgNVHQ4EFgQU
7+EbzgqFJ5H4f+F8tVVclyuhAnswTAYDVR0jBEUwQ4AU7+EbzgqFJ5H4f+F8tVVc
lyuhAnuhIKQeMBwxGjAYBgNVBAMTEU5vcmloaXRvIFlvc2hpb2thggkAkA6KheZb
1W8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAANBAHumka+fYPGm15+8m4kq
go6GPf+b8JYNClRmsus93/YdLSJJeXdTvaCcnBQWJCXaQ5UCr1qZ5Kiu9+0/Vk34
nXg=
-----END CERTIFICATE-----
    EOF
  end

  def update_signing_certificate_response
    return <<-RES
      <UpdateSigningCertificateResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>02945b3a-bb32-11df-a8c6-9f6df870c6f2</RequestId>
        </ResponseMetadata>
      </UpdateSigningCertificateResponse>
    RES
  end

  def delete_signing_certificate_response
    return <<-RES
      <DeleteSigningCertificateResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ResponseMetadata>
          <RequestId>2113a2d0-bbaf-11df-b3cb-6d0722822344</RequestId>
        </ResponseMetadata>
      </DeleteSigningCertificateResponse>
    RES
  end

  def list_signing_certificates_response
    return <<-RES
      <ListSigningCertificatesResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
        <ListSigningCertificatesResult>
          <IsTruncated>false</IsTruncated>
          <Certificates>
            <member>
              <Status>Active</Status>
              <CertificateId>PBEX2T7R5DA3SVZHQDK2HQ2G3ZOP7SYA</CertificateId>
              <UserName>User1</UserName>
              <CertificateBody>-----BEGIN CERTIFICATE-----
      MIIBrjCCAVigAwIBAgIJAJAOioXmW9VvMA0GCSqGSIb3DQEBBQUAMBwxGjAYBgNV
      BAMTEU5vcmloaXRvIFlvc2hpb2thMB4XDTEwMDkwODA5MDgyM1oXDTEwMTAwODA5
      MDgyM1owHDEaMBgGA1UEAxMRTm9yaWhpdG8gWW9zaGlva2EwXDANBgkqhkiG9w0B
      AQEFAANLADBIAkEA0IDAJgXhdMhjLEiG1TMOZgeInMGidxVn0jukTZujWZ2iawpr
      B+Qgw4AOvfOOif1ZAzJ2N4Y3DOyuuEYTZhQ+nQIDAQABo30wezAdBgNVHQ4EFgQU
      7+EbzgqFJ5H4f+F8tVVclyuhAnswTAYDVR0jBEUwQ4AU7+EbzgqFJ5H4f+F8tVVc
      lyuhAnuhIKQeMBwxGjAYBgNVBAMTEU5vcmloaXRvIFlvc2hpb2thggkAkA6KheZb
      1W8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAANBAHumka+fYPGm15+8m4kq
      go6GPf+b8JYNClRmsus93/YdLSJJeXdTvaCcnBQWJCXaQ5UCr1qZ5Kiu9+0/Vk34
      nXg=
      -----END CERTIFICATE-----
      </CertificateBody>
              <UploadDate>2010-09-08T09:24:47Z</UploadDate>
            </member>
          </Certificates>
        </ListSigningCertificatesResult>
        <ResponseMetadata>
          <RequestId>20a2a122-bb2f-11df-a8c6-9f6df870c6f2</RequestId>
        </ResponseMetadata>
      </ListSigningCertificatesResponse>
    RES
  end
end

