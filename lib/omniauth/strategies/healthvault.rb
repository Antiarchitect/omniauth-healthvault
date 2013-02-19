module OmniAuth
  module Strategies
    # Authenticate to Microsoft HealthVault service utilizing OAuth 2.0 and retrieve basic user information.
    # Documentation available here:
    # http://msdn.microsoft.com/library/jj863179
    #
    # @example Basic Usage
    #   use OmniAuth::Strategies::HealthVault, 'app_id'
    #
    class Healthvault
      include OmniAuth::Strategy

      # DEVELOPER WORKS FINE
      #
      #option :fields, [:name, :email]
      #option :uid_field, :email
      #
      #def request_phase
      #  form = OmniAuth::Form.new(:title => "User Info", :url => callback_path)
      #  options.fields.each do |field|
      #    form.text_field field.to_s.capitalize.gsub("_", " "), field.to_s
      #  end
      #  form.button "Sign In"
      #  form.to_response
      #end
      #
      #uid do
      #  request.params[options.uid_field.to_s]
      #end
      #
      #info do
      #  options.fields.inject({}) do |hash, field|
      #    hash[field] = request.params[field.to_s]
      #    hash
      #  end
      #end

      args [:app_id, :shell_server, :callback_url]

      option :app_id, nil
      option :shell_server, 'https://account.healthvault.com/redirect.aspx'
      option :callback_url, nil

      def request_phase
        request = "#{options[:shell_server]}?target=AUTH&targetqs=appid%3D#{options[:app_id]}"
        request += "%26redirect=http://46.47.200.74/user/auth/healthvault/callback" # remove this in production
        redirect request
      end

      uid do
        request.params['wctoken']
      end
    end
  end
end