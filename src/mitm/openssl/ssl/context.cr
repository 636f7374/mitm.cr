abstract class OpenSSL::SSL::Context
  class Server < Context
    # Set the CA certificate by string, in PEM format, used to
    # validate the peers certificate.
    def ca_certificate_text=(text : String)
      _certificate = OpenSSL::X509::SuperCertificate.parse text: text
      self.ca_certificate_text = _certificate
    end

    # Set the CA certificate by string, in PEM format, used to
    # validate the peers certificate.
    def ca_certificate_text=(certificate : OpenSSL::X509::SuperCertificate)
      ret = LibSSL.ssl_ctx_use_certificate @handle, certificate
      raise OpenSSL::Error.new "SSL_CTX_use_certificate" unless 1_i32 == ret

      certificate.attach_extra_chain_cert! ssl_context: @handle
    end

    # Set the private key by string, The key must in PEM format.
    def private_key_text=(text : String)
      _private_key = OpenSSL::PKey.parse_private_key text: text
      self.private_key_text = _private_key
    end

    # Set the private key by string, The key must in PEM format.
    def private_key_text=(pkey : LibCrypto::EVP_PKEY | OpenSSL::PKey)
      ret = LibSSL.ssl_ctx_use_privatekey @handle, pkey
      raise OpenSSL::Error.new "SSL_CTX_use_PrivateKey" unless 1_i32 == ret
    end
  end
end
