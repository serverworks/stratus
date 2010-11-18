require File.expand_path(File.dirname(__FILE__) + '/../../../spec_helper')
require File.expand_path(File.dirname(__FILE__) + '/../../../../lib/stratus')
require File.expand_path(File.dirname(__FILE__) + '/../../../../lib/stratus/aws')
require File.expand_path(File.dirname(__FILE__) + '/../../../../lib/stratus/aws/iam')

describe "Stratus::AWS::IAM::Group" do
  context "#initialize" do
    it "should store parameters as attributes with camelized attribute name" do
      group = Stratus::AWS::IAM::Group.new({
                                                     'GroupId' => 'AGPAI5CJDQYAAILTSCKWM',
                                                     "Arn" => "arn:aws:iam::763958113208:group/Administrator",
                                                     "Path" => "/",
                                                     "GroupName" => "Test",
                                                   })
      group.group_id = 'AGPAI5CJDQYAAILTSCKWM'
      group.arn = 'arn:aws:iam::763958113208:group/Administrator'
      group.path = '/'
      group.group_name = 'Test'
    end
  end
end
