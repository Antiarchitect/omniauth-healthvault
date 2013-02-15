require 'omniauth/strategies/oauth2'

module OmniAuth
  module Strategies
    # Authenticate to Microsoft HealthVault service utilizing OAuth 2.0 and retrieve basic user information.
    # Documentation available here:
    # http://msdn.microsoft.com/library/jj863179
    #
    # @example Basic Usage
    #   use OmniAuth::Strategies::HealthVault, 'app_id'
    #
    class HealthVault < OmniAuth::Strategies::OAuth2

      option :name, 'healthvault'

      option :client_options, { site: 'https://account.healthvault.com' }

      uid{ raw_info['id'] }

      info do
        {
          name: raw_info['name'],
          email: raw_info['email']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/redirect.aspx?target=AUTH&').parsed
      end

    end
  end
end