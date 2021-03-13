<div align = "center"><img src="images/icon.png" width="256" height="256" /></div>

<div align = "center">
  <h1>Mitm.cr - Man-in-the-middle Toolkit</h1>
</div>

<p align="center">
  <a href="https://crystal-lang.org">
    <img src="https://img.shields.io/badge/built%20with-crystal-000000.svg" /></a>
  <a href="https://github.com/636f7374/mitm.cr/actions">
    <img src="https://github.com/636f7374/mitm.cr/workflows/Continuous%20Integration/badge.svg" /></a>
  <a href="https://github.com/636f7374/mitm.cr/releases">
    <img src="https://img.shields.io/github/release/636f7374/mitm.cr.svg" /></a>
  <a href="https://github.com/636f7374/mitm.cr/blob/master/license">
    <img src="https://img.shields.io/github/license/636f7374/mitm.cr.svg"></a>
</p>

## Description

* High-performance, reliable, and stable Man-in-the-middle Toolkit.
* This repository is under evaluation and will replace [Cherry.cr](https://github.com/636f7374/cherry.cr).

## Features

* [X] Polished
* [X] Mitm

## Usage

* Please check the examples folder.

### Used as Shard

Add this to your application's shard.yml:

```yaml
dependencies:
  mitm:
    github: 636f7374/mitm.cr
```

### Installation

```bash
$ git clone https://github.com/636f7374/mitm.cr.git
```

## Development

```bash
$ make test
```

## References

* [Official | Ruby OpenSSL::X509::Certificate](https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/X509/Certificate.html)
* [Official | OpenSSL Documentation](https://www.openssl.org/docs/)
* [Official | OpenSSL x509v3_config](https://www.openssl.org/docs/manmaster/man5/x509v3_config.html)
* [Official | PEM_read_bio_PrivateKey](https://www.openssl.org/docs/man1.1.0/man3/PEM_write_bio_RSA_PUBKEY.html)
* [Official | X509V3_get_d2i](https://www.openssl.org/docs/man1.1.0/man3/X509_add1_ext_i2d.html)
* [Official | Secure programming with the OpenSSL API](https://developer.ibm.com/tutorials/l-openssl/)
* [Github | Golang Nid.go](https://github.com/spacemonkeygo/openssl/blob/master/nid.go)
* [Github | Rust OpenSSL Password callbacks](https://github.com/sfackler/rust-openssl/pull/410)
* [Github | OpenSSL SSL_Rsa.c](https://github.com/openssl/openssl/blob/master/ssl/ssl_rsa.c)
* [Blogs | The Most Common OpenSSL Commands](https://www.sslshopper.com/article-most-common-openssl-commands.html)
* [Blogs | OpenSSL – Convert RSA Key to private key](https://rafpe.ninja/2016/08/17/openssl-convert-rsa-key-to-private-key/)
* [Blogs | problem with d2i_X509?](http://openssl.6102.n7.nabble.com/problem-with-d2i-X509-td1537.html)
* [Blogs | Parsing X.509 Certificates with OpenSSL and C](https://zakird.com/2013/10/13/certificate-parsing-with-openssl)
* [Blogs | Using the OpenSSL library with macOS Sierra](https://medium.com/@timmykko/using-openssl-library-with-macos-sierra-7807cfd47892)
* [StackOverflow | Read certificate files from memory instead of a file using OpenSSL](https://stackoverflow.com/questions/3810058/read-certificate-files-from-memory-instead-of-a-file-using-openssl)
* [StackOverflow | Programmatically Create X509 Certificate using OpenSSL](https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl)
* [StackOverflow | OpenSSL Command to check if a server is presenting a certificate](https://stackoverflow.com/questions/24457408/openssl-command-to-check-if-a-server-is-presenting-a-certificate)
* [StackOverflow | C++ OpenSSL export private key](https://stackoverflow.com/questions/5367991/c-openssl-export-private-key)
* [StackOverflow | Why is openssl key length different from specified bytes](https://security.stackexchange.com/questions/102508/why-is-openssl-key-length-different-from-specified-bytes)
* [StackOverflow | Reading PEM-formatted RSA keyfile with the OpenSSL C API](https://stackoverflow.com/questions/16675147/reading-pem-formatted-rsa-keyfile-with-the-openssl-c-api)
* [StackOverflow | OpenSSL certificate lacks key identifiers](https://stackoverflow.com/questions/2883164/openssl-certificate-lacks-key-identifiers)
* [StackOverflow | OpenSSL CA keyUsage extension](https://superuser.com/questions/738612/openssl-ca-keyusage-extension)
* ...

## Related

* [#7897 | Need to enhance the OpenSSL::SSL::Context loads Certificate / PrivateKey from Memory](https://github.com/crystal-lang/crystal/issues/7897)
* [#7896 | Need to enhance the OpenSSL::X509 more features](https://github.com/crystal-lang/crystal/issues/7896)
* [#8108 | openssl ssl_accept sometimes does not return, causes server to hang permanently](https://github.com/crystal-lang/crystal/issues/8108)
* [#7291 | Get SNI for OpenSSL](https://github.com/crystal-lang/crystal/pull/7291)
* ...

## Credit

* [\_Icon::Freepik/LawAndJustice](https://www.flaticon.com/packs/law-and-justice-62)

## Contributors

|Name|Creator|Maintainer|Contributor|
|:---:|:---:|:---:|:---:|
|**[636f7374](https://github.com/636f7374)**|√|√|√|

## License

* BSD 3-Clause Clear License
