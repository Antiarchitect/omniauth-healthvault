require 'builder'
require 'faraday'
require 'multi_xml'

module OmniAuth
  module Strategies
    # Authenticate to Microsoft HealthVault service and retrieve basic user information.
    # Documentation available here:
    # http://msdn.microsoft.com/library/jj863179
    #
    # @example Basic Usage
    #   use OmniAuth::Builder do
    #     provider :healthvault, ENV['HEALTHVAULT_APP_ID'], ENV['HEALTHVAULT_PKCS12_CERT_LOCATION']
    #   end
    #
    class Healthvault
      include OmniAuth::Strategy

      PLATFORM_VERSION = '1.12.1002.8529'

      args [:app_id, :pkcs_12_location]

      option :name, 'healthvault'

      option :app_id, nil

      option :platform_url, 'https://platform.healthvault.com/platform/wildcat.ashx'
      option :shell_url, 'https://account.healthvault.com/redirect.aspx'

      def request_phase
        url = "#{options[:shell_url]}?target=AUTH&targetqs=appid%3D#{options[:app_id]}"
        redirect url
      end

      def callback_phase
        if request.params['target'] == 'AppAuthSuccess'
          @certificate = OpenSSL::PKCS12.new(File.read(options[:pkcs_12_location]), nil)
          @wctoken = request.params['wctoken']
          @shared_secret = Base64.strict_encode64(SecureRandom.hex)
          @app_auth_token = create_authenticated_session_token
          @raw_info = get_person_info
        end
        super
      end

      uid { @raw_info['person_id'] }
      info { { name: @raw_info['name'] } }
      extra { { raw_info: @raw_info } }

      private

      def send_request(body)
        conn = ::Faraday.new(url: options[:platform_url]) do |faraday|
          faraday.request  :url_encoded
          faraday.response :logger
          faraday.adapter  ::Faraday.default_adapter
        end
        conn.post do |i|
          i.headers['Content-Type'] = 'text/xml'
          i.body = body
        end
      end

      def create_authenticated_session_token
        response = send_request(build_create_authenticated_session_token_request)
        parse_create_authenticated_session_token_response(response.body)
      end

      def get_person_info
        if @app_auth_token.present?
          body = build_get_person_info_request
          response = send_request(body)
          parse_get_person_info_response(response.body)
        end
      end

      def build_get_person_info_request
        info = ::Builder::XmlMarkup.new.info
        header = ::Builder::XmlMarkup.new.header do |header|
          header.method 'GetPersonInfo'
          header.tag! 'method-version', 1
          header.tag! 'auth-session' do
            header.tag! 'auth-token', @app_auth_token
            header.tag! 'user-auth-token', @wctoken
          end
          header.language 'en'
          header.country 'US'
          header.tag! 'msg-time', Time.now.to_datetime.rfc3339
          header.tag! 'msg-ttl', 36000
          header.version PLATFORM_VERSION
          header.tag! 'info-hash' do
            header.tag! 'hash-data', Base64.strict_encode64(OpenSSL::Digest::SHA1.digest(info)), 'algName' => 'SHA1'
          end
        end
        body = ::Builder::XmlMarkup.new
        body.tag!('wc-request:request', 'xmlns:wc-request' => 'urn:com.microsoft.wc.request') do
          body.auth do
            body.tag! 'hmac-data', Base64.strict_encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, Base64.decode64(@shared_secret), header)), 'algName' => 'HMACSHA1'
          end
          body << header
          body << info
        end
      end

      def parse_get_person_info_response(response_body)
        result = ::MultiXml.parse(response_body)
        result['response']['info']['person_info'] rescue nil
      end

      def build_create_authenticated_session_token_request
        content = ::Builder::XmlMarkup.new
        content = content.content do
          content.tag! 'app-id', options[:app_id]
          content.tag! 'shared-secret' do
            content.tag! 'hmac-alg', @shared_secret, 'algName' => 'HMACSHA1'
          end
        end
        body = ::Builder::XmlMarkup.new
        body.tag!('wc-request:request', 'xmlns:wc-request' => 'urn:com.microsoft.wc.request') do
          body.header do
            body.method 'CreateAuthenticatedSessionToken'
            body.tag! 'method-version', 1
            body.tag! 'app-id', options[:app_id]
            body.language 'en'
            body.country 'US'
            body.tag! 'msg-time', Time.now.to_datetime.rfc3339
            body.tag! 'msg-ttl', 36000
            body.version PLATFORM_VERSION
          end
          body.info do
            body.tag! 'auth-info' do
              body.tag! 'app-id', options[:app_id]
              body.credential do
                body.appserver do
                  body.sig Base64.strict_encode64(@certificate.key.sign(OpenSSL::Digest::SHA1.new, content)), 'digestMethod' => 'SHA1',
                           'sigMethod' => 'RSA-SHA1', 'thumbprint' => OpenSSL::Digest::SHA1.hexdigest(@certificate.certificate.to_der).upcase
                  body << content
                end
              end
            end
          end
        end
      end

      def parse_create_authenticated_session_token_response(response_body)
        result = ::MultiXml.parse(response_body)
        result['response']['info']['token']['__content__'] rescue nil
      end
    end
  end
end