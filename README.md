# OmniAuth Healthvault

This is the unofficial OmniAuth strategy for authenticating to Microsoft HealthVault. To use it, you'll need to sign up for an application id on the Microsoft HealthVault [Application Configuration Center](https://config.healthvault.com) and have a public and private keys packed in PKCS#12 file (.pfx or .p12).

## Generating .cer file (public key in DER format) from a PKCS#12

.cer file is one of the required conditions to register your application in Application Configuration Center:

    openssl pkcs12 -in my.pfx -clcerts -nokeys | openssl x509 -inform PEM -outform DER -out my.cer

## Basic Usage

    use OmniAuth::Builder do
      provider :healthvault, ENV['HEALTHVAULT_APP_ID'], ENV['HEALTHVAULT_PKCS12_CERT_LOCATION']
    end

## Preproduction Usage

    provider :github, ENV['HEALTHVAULT_APP_ID'], ENV['HEALTHVAULT_PKCS12_FILE_LOCATION'], {
      platform_url: 'https://platform.healthvault-ppe.com/platform/wildcat.ashx',
      shell_url: 'https://account.healthvault-ppe.com/redirect.aspx'
    }

## License

Copyright (c) 2013 Andrey Voronkov and Swissmed Mobile Inc.

MIT License

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
