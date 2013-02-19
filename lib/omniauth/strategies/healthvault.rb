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

      args [:app_id]

      option :app_id, nil

      option :shell_url, 'https://account.healthvault.com/redirect.aspx'
      option :callback_url, nil

      def request_phase
        request = "#{options[:shell_url]}?target=AUTH&targetqs=appid%3D#{options[:app_id]}"
        request += "%26redirect=#{options[:callback_url]}" if options[:callback_url]
        redirect request
      end

      uid do
        request.params['wctoken']
      end
    end
  end
end