require 'builder'
require 'faraday'
require 'multi_xml'

module OmniAuth
  module Strategies
    # Authenticate to Microsoft HealthVault service utilizing OAuth 2.0 and retrieve basic user information.
    # Documentation available here:
    # http://msdn.microsoft.com/library/jj863179
    #
    # @example Basic Usage
    #   use OmniAuth::Strategies::HealthVault, 'app_id', [:settings]
    #
    class Healthvault
      include OmniAuth::Strategy

      PLATFORM_VERSION = '1.12.1002.8529'

      args [:app_id, :pubkey_thumbprint, :cert_file]

      option :app_id, nil

      option :platform_url
      option :shell_url, 'https://account.healthvault.com/redirect.aspx'
      option :platform_url, 'https://platform.healthvault.com/platform/wildcat.ashx'

      def request_phase
        url = "#{options[:shell_url]}?target=AUTH&targetqs=appid%3D#{options[:app_id]}"
        redirect url
      end

      def callback_phase
        if request.params['target'] == 'AppAuthSuccess'
          shared_secret = Base64.encode64(SecureRandom.hex)
          app_auth_token = create_authenticated_session_token(shared_secret)
          get_person_info
        end
        super
      end

      private

      def create_authenticated_session_token(shared_secret)
        body = build_create_authenticated_session_token_request(shared_secret)
        conn = ::Faraday.new(url: options[:platform_url]) do |faraday|
          faraday.request  :url_encoded             # form-encode POST params
          faraday.response :logger                  # log requests to STDOUT
          faraday.adapter  ::Faraday.default_adapter  # make requests with Net::HTTP
        end
        response = conn.post do |i|
          i.headers['Content-Type'] = 'text/xml'
          i.body = body
        end
        parse_create_authenticated_session_token_response(response.body)
      end

      def get_person_info

      end

      def build_create_authenticated_session_token_request(shared_secret)
        content = ::Builder::XmlMarkup.new
        content = content.content do
          content.tag! 'app-id', options[:app_id]
          content.tag! 'shared-secret' do
            content.tag! 'hmac-alg', shared_secret, 'algName' => 'HMACSHA1'
          end
        end
        pem = File.read(options[:cert_file])
        signature = Base64.encode64(OpenSSL::PKey::RSA.new(pem).sign(OpenSSL::Digest::SHA1.new, content))
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
                  body.sig signature, 'digestMethod' => 'SHA1', 'sigMethod' => 'RSA-SHA1', 'thumbprint' => options[:pubkey_thumbprint]
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