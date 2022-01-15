@[Link(ldflags: "`printf %s '#{__DIR__}/../../../patch/*.o'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libcrypto || printf %s '-lcrypto'`")]
@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs --silence-errors libssl || printf %s '-lssl -lcrypto'`")]
lib LibSSLPatch
  fun ssl_ctx_add_extra_chain_cert = SSL_CTX_add_extra_chain_cert__(ctx : LibSSL::SSLContext, x509 : LibCrypto::X509) : LibC::Int
  fun ssl_ctx_add0_chain_cert = SSL_CTX_add0_chain_cert__(ctx : LibSSL::SSLContext, x509 : LibCrypto::X509) : LibC::Int
end
