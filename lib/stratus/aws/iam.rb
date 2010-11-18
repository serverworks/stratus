require 'base64'
require 'time'
require 'rest_client'
require 'rexml/document'

begin
  require 'xmlsimple' unless defined? XmlSimple
rescue Exception => e
  require 'xml-simple' unless defined? XmlSimple
end

module Stratus
  module AWS

    class Response
      # Parse the XML response from AWS
      #
      # @option options [String] :xml The XML response from AWS that we want to parse
      # @option options [Hash] :parse_options Override the options for XmlSimple.
      # @return [Hash] the input :xml converted to a custom Ruby Hash by XmlSimple.
      def self.parse(options = {})
        options = {
          :xml => '',
          :parse_options => { 'forcearray' => ['item', 'member'], 'suppressempty' => nil, 'keeproot' => false }
        }.merge(options)
        response = XmlSimple.xml_in(options[:xml], options[:parse_options])
      end
    end

    module IAM
      DEFAULT_HOST = 'iam.amazonaws.com'
      API_VERSION = '2010-05-08'

      class Base
        VALID_ACCESS_KEY_STATUSES = [:active, :inactive].freeze
        VALID_HTTP_METHODS = [:get, :post].freeze

        # @param [String] access_key_id
        # @param [String] secret_access_key
        def initialize(access_key_id, secret_access_key)
          @access_key_id = access_key_id
          @secret_access_key = secret_access_key
          @endpoint = "https://#{DEFAULT_HOST}/"
        end

        # @return [String]
        def api_version
          API_VERSION
        end

        # @return [String]
        def default_host
          DEFAULT_HOST
        end

        # @return [String]
        def endpoint
          @endpoint
        end

        # Calls GetGropup API
        #
        # @param [Hash] :group_name parameter is required
        # @return [Hash]
        def get_group(options = {})
          check_group_name(options)
          params = make_pagination_params(options)
          params['GroupName'] = options[:group_name]
          response = call_api('GetGroup', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls CreateGropup API
        #
        # @param [Hash] :group_name parameter is required
        # @return [Hash]
        def create_group(options = {})
          check_group_name(options)
          params = { 'GroupName' => options[:group_name] }
          params['Path'] = options[:path] if options[:path]
          response = call_api('CreateGroup', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls DeleteGropup API
        #
        # @param [Hash] :group_name parameter is required
        # @return [Hash]
        def delete_group(options = {})
          check_group_name(options)
          params = { 'GroupName' => options[:group_name] }
          response = call_api('DeleteGroup', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls ListGroups API
        #
        # @return [Hash]
        def list_groups(options = {})
          params = make_pagination_params(options)
          params['PathPrefix'] = options[:path_prefix] if options[:path_prefix]
          response = call_api('ListGroups', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls UpdateGroup API
        #
        # @param [Hash] :group_name parameter is required
        # @return [Hash]
        def update_group(options = {})
          check_group_name(options)
          params = { 'GroupName' => options[:group_name] }
          params['NewGroupName'] = options[:new_group_name] if options[:new_group_name]
          params['NewPathName'] = options[:new_path_name] if options[:new_path_name]
          response = call_api('UpdateGroup', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls AddUserToGroup API
        #
        # @param [Hash] :group_name and :user_name parameters is required
        # @return [Hash]
        def add_user_to_group(options = {})
          check_group_name(options)
          check_user_name(options)
          params = { 'GroupName' => options[:group_name], 'UserName' => options[:user_name] }
          response = call_api('AddUserToGroup', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls RemoveUserFromGroup API
        #
        # @param [Hash] :group_name and :user_name parameters is required
        # @return [Hash]
        def remove_user_from_group(options = {})
          check_group_name(options)
          check_user_name(options)
          params = { 'GroupName' => options[:group_name], 'UserName' => options[:user_name] }
          response = call_api('RemoveUserFromGroup', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls GetUser API
        #
        # @param [Hash]
        # @return [Hash]
        def get_user(options = {})
          params = {}
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('GetUser', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls CreateUser API
        #
        # @param [Hash] :user_name parameter is required
        # @return [Hash]
        def create_user(options = {})
          check_user_name(options)
          params = { 'UserName' => options[:user_name] }
          params['Path'] = options[:path] if options[:path]
          response = call_api('CreateUser', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls DeleteUser API
        #
        # @param [Hash] :user_name parameter is required
        # @return [Hash]
        def delete_user(options = {})
          check_user_name(options)
          params = { 'UserName' => options[:user_name] }
          response = call_api('DeleteUser', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls ListUsers API
        #
        # @param [Hash]
        # @return [Hash]
        def list_users(options = {})
          params = make_pagination_params(options)
          params['PathPrefix'] = options[:path_prefix] if options[:path_prefix]
          response = call_api('ListUsers', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls ListGroupsForUser API
        #
        # @param [Hash] :user_name parameter is required
        # @return [Hash]
        def list_groups_for_user(options = {})
          check_user_name(options)
          params = make_pagination_params(options)
          params['UserName'] = options[:user_name]
          response = call_api('ListGroupsForUser', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls UpdateUser API
        #
        # @param [Hash] :user_name parameter is required
        # @return [Hash]
        def update_user(options = {})
          check_user_name(options)
          params = {}
          params['UserName'] = options[:user_name]
          params['NewPath'] = options[:new_path] if options[:new_path]
          params['NewUserName'] = options[:new_user_name] if options[:new_user_name]
          response = call_api('UpdateUser', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls CreateAccessKey API
        #
        # @param [Hash] options
        # @return [Hash]
        def create_access_key(options = {})
          params = {}
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('CreateAccessKey', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls DeleteAccessKey API
        #
        # @param [Hash] options :access_key_id option is required.
        # @return [Hash]
        def delete_access_key(options = {})
          check_access_key_id(options)
          params = { 'AccessKeyId' => options[:access_key_id] }
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('DeleteAccessKey', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls UpdateAccessKey API
        #
        # @param [Hash] options :access_key_id and :status options is required.
        # @return [Hash]
        def update_access_key(options = {})
          check_access_key_id(options)
          check_activity_status(options)
          params = { 'AccessKeyId' => options[:access_key_id], 'Status' => options[:status].to_s.capitalize }
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('UpdateAccessKey', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls ListAccessKeys API
        #
        # @param [Hash] options
        # @return [Hash]
        def list_access_keys(options = {})
          params = make_pagination_params(options)
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('ListAccessKeys', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls GetGroupPolicy API
        #
        # @param [Hash] options :group_name and :policy_name options is required.
        # @return [Hash]
        def get_group_policy(options = {})
          check_group_name(options)
          check_policy_name(options)
          params = { 'GroupName' => options[:group_name], 'PolicyName' => options[:policy_name] }
          response = call_api('GetGroupPolicy', params)
          result = Response.parse(:xml => response.to_str)
          if result && result['GetGroupPolicyResult'] && result['GetGroupPolicyResult']['PolicyDocument']
            result['GetGroupPolicyResult']['PolicyDocument'] = decode_uri(result['GetGroupPolicyResult']['PolicyDocument'])
          end
          result
        end

        # Calls PutGroupPolicy API
        #
        # @param [Hash] options
        # @return [Hash]
        def put_group_policy(options = {})
          check_group_name(options)
          check_policy_name(options)
          check_policy_document(options)
          params = {
            'GroupName' => options[:group_name],
            'PolicyName' => options[:policy_name],
            'PolicyDocument' => options[:policy_document]
          }
          response = call_api('PutGroupPolicy', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls DeleteGroupPolicy API
        #
        # @param [Hash] options :group_name and :policy_name options is required.
        # @return [Hash]
        def delete_group_policy(options = {})
          check_group_name(options)
          check_policy_name(options)
          params = { 'GroupName' => options[:group_name], 'PolicyName' => options[:policy_name] }
          response = call_api('DeleteGroupPolicy', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls ListGroupPolicies API
        #
        # @param [Hash] options :group_name options is required.
        # @return [Hash]
        def list_group_policies(options = {})
          check_group_name(options)
          params = make_pagination_params(options)
          params['GroupName'] = options[:group_name]
          response = call_api('ListGroupPolicies', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls GetUserPolicy API
        #
        # @param [Hash] options :user_name and :policy_name options is required.
        # @return [Hash]
        def get_user_policy(options = {})
          check_user_name(options)
          check_policy_name(options)
          params = { 'UserName' => options[:user_name], 'PolicyName' => options[:policy_name] }
          response = call_api('GetUserPolicy', params)
          result = Response.parse(:xml => response.to_str)
          if result && result['GetUserPolicyResult'] && result['GetUserPolicyResult']['PolicyDocument']
            result['GetUserPolicyResult']['PolicyDocument'] = decode_uri(result['GetUserPolicyResult']['PolicyDocument'])
          end
          result
        end

        # Calls PutUserPolicy API
        #
        # @param [Hash] options
        # @return [Hash]
        def put_user_policy(options = {})
          check_user_name(options)
          check_policy_name(options)
          check_policy_document(options)
          params = {
            'UserName' => options[:user_name],
            'PolicyName' => options[:policy_name],
            'PolicyDocument' => options[:policy_document]
          }
          response = call_api('PutUserPolicy', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls DeleteUserPolicy API
        #
        # @param [Hash] options :user_name and :policy_name options is required.
        # @return [Hash]
        def delete_user_policy(options = {})
          check_user_name(options)
          check_policy_name(options)
          params = { 'UserName' => options[:user_name], 'PolicyName' => options[:policy_name] }
          response = call_api('DeleteUserPolicy', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls ListUserPolicies API
        #
        # @param [Hash] options :user_name options is required.
        # @return [Hash]
        def list_user_policies(options = {})
          check_user_name(options)
          params = make_pagination_params(options)
          params['UserName'] = options[:user_name]
          response = call_api('ListUserPolicies', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls UploadSigningCertificate API
        #
        # @param [Hash] options :certificate_body options is required.
        # @return [Hash]
        def upload_signing_certificate(options = {})
          check_certificate_body(options)
          params = { 'CertificateBody' => options[:certificate_body] }
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('UploadSigningCertificate', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls UpdateSigningCertificate API
        #
        # @param [Hash] options :certificate_id and :status options is required.
        # @return [Hash]
        def update_signing_certificate(options = {})
          check_certificate_id(options)
          check_activity_status(options)
          params = { 'CertificateId' => options[:certificate_id], 'Status' => options[:status].to_s.capitalize }
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('UpdateSigningCertificate', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls DeleteSigningCertificate API
        #
        # @param [Hash] options :certificate_id options is required.
        # @return [Hash]
        def delete_signing_certificate(options = {})
          check_certificate_id(options)
          params = { 'CertificateId' => options[:certificate_id] }
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('DeleteSigningCertificate', params)
          Response.parse(:xml => response.to_str)
        end

        # Calls list_signing_certificates API
        #
        # @param [Hash] options
        # @return [Hash]
        def list_signing_certificates(options = {})
          params = make_pagination_params(options)
          params['UserName'] = options[:user_name] if options[:user_name]
          response = call_api('ListSigningCertificates', params)
          Response.parse(:xml => response.to_str)
        end

        # @param [String] action AWS IAM API action name
        # @param [Hash] params
        # @return RestClient::Response
        def call_api(action, params)
          params['Action'] = action.to_s
          if params['Action'] == 'UploadSigningCertificate'
            return request(params, :method => :post)
          end
          request(params)
        end

        protected

        # @param [Hash] params
        # @return [RestClient::Response]
        def request(params, options = {})
          options = { :method => :get, :api_version => '2010-05-08' }.merge(options)
          auth_params = {
            'AWSAccessKeyId' => @access_key_id,
            'SignatureMethod' => 'HmacSHA1',
            'SignatureVersion' => '2',
            'Timestamp' => Time.now.utc.iso8601,
            'Version' => options[:api_version]
          }
          signed_params = sign_to_params(auth_params.merge(params), options[:method])
          if (options[:method] == :post)
            return RestClient.post self.endpoint, signed_params
          end
          RestClient.get self.endpoint, { :params => signed_params }
        end

        # @param [Hash] params
        # @return [Hash]
        def sign_to_params(params, http_method = :get)
          unless (VALID_HTTP_METHODS.include?(http_method))
            raise ArgumentError, 'Invalid HTTP method proviced. method must be :get or :post'
          end
          tmp = []
          sorted_params = params.sort { |a, b| a[0] <=> b[0] }
          encoded_params = sorted_params.collect do |p|
            encoded = (CGI::escape(p[0].to_s) + '=' + CGI::escape(p[1].to_s))
            # Ensure spaces are encoded as '%20', not '+'
            encoded = encoded.gsub('+', '%20')
            # According to RFC3986 (the scheme for values expected by signing requests), '~' should not be encoded
            encoded = encoded.gsub('%7E', '~')
          end
          sigquery = encoded_params.join('&')

          # Generate the request description string
          method = http_method.to_s.upcase
          request_uri = '/'
          req_desc = method + "\n" + default_host + "\n" + request_uri + "\n" + sigquery

          # create sig
          digest = OpenSSL::Digest::Digest.new('sha1')
          sig = Base64.encode64(OpenSSL::HMAC.digest(digest, @secret_access_key, req_desc)).gsub("\n", '')

          params.merge({ 'Signature' => sig })
        end

        private

        # Check to be sure the :user_name option exist
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:user_name] is nil or empty.
        def check_user_name(options)
          raise ArgumentError, 'No user name provided' if options[:user_name].nil? || options[:user_name].empty?
          options
        end

        # Check to be sure the :group_name option exist
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:group_name] is nil or empty.
        def check_group_name(options)
          raise ArgumentError, 'No group name provided' if options[:group_name].nil? || options[:group_name].empty?
          options
        end

        # Check to be sure the :access_key option exist
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:group_name] is nil or empty.
        def check_access_key_id(options)
          raise ArgumentError, 'No access key id provided' if options[:access_key_id].nil? || options[:access_key_id].empty?
          options
        end

        # Check to be sure the :status option and validate the :status option format
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:group_name] is nil or empty.
        def check_activity_status(options)
          status = options[:status].to_s
          raise ArgumentError, 'No status provided' if status.empty?
          unless VALID_ACCESS_KEY_STATUSES.include?(status.downcase.to_sym)
            raise ArgumentError, 'status option value must be "Active" or "Inactive"'
          end
          options
        end

        # Check to be sure the :policy_name option exist
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:policy_name] is nil or empty.
        def check_policy_name(options)
          raise ArgumentError, 'No policy name provided' if options[:policy_name].nil? || options[:policy_name].empty?
          options
        end

        # Check to be sure the :policy_document option exist
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:policy_document] is nil or empty.
        def check_policy_document(options)
          raise ArgumentError, 'No policy document provided' if options[:policy_document].nil? || options[:policy_document].empty?
          options
        end

        # Check to be sure the :certificate_id option exist
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:policy_document] is nil or empty.
        def check_certificate_id(options)
          raise ArgumentError, 'No certificate body provided' if options[:certificate_id].nil? || options[:certificate_id].empty?
          options
        end

        # Check to be sure the :certificate_body option exist
        #
        # @param [Hash] options
        # @return [Hash]
        # @raise [ArgumentError] throw if the option[:policy_document] is nil or empty.
        def check_certificate_body(options)
          raise ArgumentError, 'No certificate body provided' if options[:certificate_body].nil? || options[:certificate_body].empty?
          options
        end

        # Make a parameters hash for ***List methos from options
        #
        # ex. ListAccessKeys, ListUsers, ListGroups, etc...
        #
        # @param [Hash] options that passed from argument
        # @return [Hash]
        def make_pagination_params(options)
          params = {}
          params['Marker'] = options[:marker] if options[:marker]
          params['MaxItems'] = options[:max_items] if options[:max_items]
          params
        end

        # Decode a URI according to RFC 3986
        #
        # Notice: CGI.escape is not accoding to RFC 3986,
        #         but CGI.unescape seems according to RFC 3986.
        #         ex. CGI.unescape('~') -> '~'
        #             CGI.unescape('%2B') -> '+'
        #             CGI.unescape('%20') -> ' '
        #
        # @param [String] uri A string encoded by RFC 3986
        # @return [String] Decoded string
        def decode_uri(uri)
          return uri unless uri
          CGI::unescape(uri)
        end
      end
    end
  end
end

