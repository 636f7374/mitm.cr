#include <openssl/ssl.h>

long SSL_CTX_add_extra_chain_cert__(SSL_CTX *ctx, X509 *x509) {
  return SSL_CTX_add_extra_chain_cert(ctx, x509);
}

int SSL_CTX_add0_chain_cert__(SSL_CTX *ctx, X509 *x509) {
  return SSL_CTX_add0_chain_cert(ctx, x509);
}