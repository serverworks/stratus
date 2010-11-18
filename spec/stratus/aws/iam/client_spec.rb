require File.expand_path(File.dirname(__FILE__) + '/../../../spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../../../../lib/stratus')
require File.expand_path(File.dirname(__FILE__) + '/../../../../lib/stratus/aws')
require File.expand_path(File.dirname(__FILE__) + '/../../../../lib/stratus/aws/iam')

class IAMBaseStub
  def list_groups
    {"ListGroupsResult"=>
      {"IsTruncated"=>"false",
        "Groups"=>
        {"member"=>
          [{"GroupId"=>"AGPAI5CJDQYAAILTSCKWM",
             "Arn"=>"arn:aws:iam::763958113208:group/Administrator",
             "Path"=>"/",
             "GroupName"=>"Administrator"},
           {"GroupId"=>"AGPAJXMNNTLP6O6CIWNCW",
             "Arn"=>"arn:aws:iam::763958113208:group/Developer/Developer",
             "Path"=>"/Developer/",
             "GroupName"=>"Developer"}]}},
      "ResponseMetadata"=>{"RequestId"=>"b2fc292f-c09e-11df-b52e-932157311353"},
      "xmlns"=>"https://iam.amazonaws.com/doc/2010-05-08/"}
  end
end

describe "Stratus::AWS::IAM::Client::Base" do
  before(:each) do
    Stratus::AWS::IAM::Base.should_receive(:new).and_return(IAMBaseStub.new)
    @iam = Stratus::AWS::IAM::Client.new('aaa', 'bbb')
  end

  context "#groups" do
    it "should return a list of groups" do
      @iam.groups.should have(2).groups
    end

    it "should contain a group which has group attributes" do
      @iam.groups.first.group_id.should == 'AGPAI5CJDQYAAILTSCKWM'
      @iam.groups.first.arn.should == 'arn:aws:iam::763958113208:group/Administrator'
      @iam.groups.first.path.should == '/'
      @iam.groups.first.group_name.should == 'Administrator'
    end
  end
end
