module OpenSSL::X509
  class SuperCertificate
    enum KeyUsage : UInt8
      DigitalSignature = 0_u8
      NonRepudiation   = 1_u8
      KeyEncipherment  = 2_u8
      DataEncipherment = 3_u8
      KeyAgreement     = 4_u8
      KeyCertSign      = 5_u8
      CRLSign          = 6_u8
      EncipherOnly     = 7_u8
      DecipherOnly     = 8_u8
    end

    enum ExtKeyUsage : UInt8
      ServerAuth      =  0_u8
      ClientAuth      =  1_u8
      CodeSigning     =  2_u8
      EmailProtection =  3_u8
      TimeStamping    =  4_u8
      MsCodeInd       =  5_u8
      MsCodeCom       =  6_u8
      MsCtlSign       =  7_u8
      MsSgc           =  8_u8
      MsEfs           =  9_u8
      NsSgc           = 10_u8
    end

    getter certificate : LibCrypto::X509
    getter certificateChains : Set(LibCrypto::X509)
    getter freed : Bool

    def initialize(@certificate : LibCrypto::X509 = LibCrypto.x509_new, @certificateChains : Set(LibCrypto::X509) = Set(LibCrypto::X509).new)
      @freed = false
    end

    def self.parse(text : String)
      certificate_chains = Set(LibCrypto::X509).new

      mem_bio = MemBIO.new
      mem_bio.write data: text

      pointer_x509_aux = LibCrypto.pem_read_bio_x509_aux mem_bio, nil, nil, nil

      if pointer_x509_aux.null?
        mem_bio.free

        raise Error.new "PEM_read_bio_X509_AUX"
      end

      loop do
        x509_certificate = LibCrypto.pem_read_bio_x509 mem_bio, nil, nil, nil
        break if x509_certificate.null?

        certificate_chains << x509_certificate
      end

      mem_bio.free

      new certificate: pointer_x509_aux, certificateChains: certificate_chains
    end

    def attach_extra_chain_cert!(ssl_context : LibSSL::SSLContext)
      certificateChains.each { |certificate| LibSSLPatch.ssl_ctx_add_extra_chain_cert ssl_context, certificate }
      @certificateChains = Set(LibCrypto::X509).new

      true
    end

    def public_key=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_set_pubkey self, pkey
      raise Error.new "X509_set_pubkey" if ret.zero?
    end

    def public_key : OpenSSL::PKey
      OpenSSL::PKey.new pkey: LibCrypto.x509_get_pubkey(self), keyType: OpenSSL::PKey::KeyFlag::PUBLIC_KEY
    end

    def serial=(number : Int)
      asn1 = ASN1::Integer.new
      LibCrypto.asn1_integer_set asn1, number

      ret = LibCrypto.x509_set_serialnumber self, asn1
      raise Error.new "X509_set_serialNumber" if ret.zero?

      asn1.free
      true
    end

    def serial : ASN1::Integer
      ret = LibCrypto.x509_get_serialnumber self
      raise Error.new "X509_get_serialNumber" if ret.zero?

      ASN1::Integer.new integer: ret
    end

    def not_before=(valid_period : Int = 0_i64)
      asn1 = ASN1::Time.days_from_now valid_period

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        ret = LibCrypto.x509_set1_notbefore self, asn1
        asn1.free
      {% else %}
        ret = LibCrypto.x509_set_notbefore self, asn1
      {% end %}

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        raise Error.new "X509_set1_notBefore" if ret.zero?
      {% else %}
        raise Error.new "X509_set_notBefore" if ret.zero?
      {% end %}

      valid_period
    end

    def not_before : ASN1::Time
      before = LibCrypto.x509_get0_notbefore self
      raise Error.new "X509_get0_notBefore" if before.null?

      asn1 = ASN1::Time.new time: before
      asn1.freed = true

      asn1
    end

    def not_after=(valid_period : Int = 365_i64)
      asn1 = ASN1::Time.days_from_now valid_period

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        ret = LibCrypto.x509_set1_notafter self, asn1
        asn1.free
      {% else %}
        ret = LibCrypto.x509_set_notafter self, asn1
      {% end %}

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        raise Error.new "X509_set1_notAfter" if ret.zero?
      {% else %}
        raise Error.new "X509_set_notAfter" if ret.zero?
      {% end %}

      valid_period
    end

    def not_after : ASN1::Time
      after = LibCrypto.x509_get0_notafter self
      raise Error.new "X509_get0_notAfter" if after.null?

      asn1 = ASN1::Time.new time: after
      asn1.freed = true

      asn1
    end

    def issuer_name=(issuer : String)
      name = SuperName.parse issuer
      self.issuer_name = name

      name.free
      true
    end

    def issuer_name=(name : SuperName)
      ret = LibCrypto.x509_set_issuer_name self, name
      raise Error.new "X509_set_issuer_name" if ret.zero?

      true
    end

    def issuer_name : SuperName
      issuer = LibCrypto.x509_get_issuer_name self
      raise Error.new "X509_get_issuer_name" if issuer.null?

      SuperName.new name: issuer
    end

    def subject_name=(subject : String)
      name = SuperName.parse subject
      self.subject_name = name

      name.free
      true
    end

    def subject_name=(name : SuperName)
      ret = LibCrypto.x509_set_subject_name self, name
      raise Error.new "X509_set_subject_name" if ret.zero?

      true
    end

    def subject_name : SuperName
      subject = LibCrypto.x509_get_subject_name self
      raise Error.new "X509_get_subject_name" if subject.null?

      SuperName.new name: subject
    end

    def version=(version = 2_i64)
      ret = LibCrypto.x509_set_version self, version
      raise Error.new "X509_set_version" if ret.zero?

      version
    end

    def extension_count
      ret = LibCrypto.x509_get_ext_count self
      raise Error.new "X509_get_ext_count" if ret.zero?

      ret
    end

    def extension=(item = X509::SuperExtension)
      self.extensions = [item]
    end

    def extensions=(list : Array(LibCrypto::X509_EXTENSION))
      list.each do |_extension|
        unless LibCrypto.x509_add_ext(self, _extension, -1_i32).null?
          LibCrypto.x509_extension_free _extension

          next
        end

        LibCrypto.x509_extension_free _extension
        raise Error.new "X509_add_ext"
      end
    end

    def extensions=(list : Array(X509::SuperExtension))
      list.each do |_extension|
        unless LibCrypto.x509_add_ext(self, _extension, -1_i32).null?
          _extension.free

          next
        end

        _extension.free
        raise Error.new "X509_add_ext"
      end
    end

    def extensions : Array(Extension)
      count = LibCrypto.x509_get_ext_count self

      Array(Extension).new count do |item|
        ext = LibCrypto.x509_get_ext self, item

        Extension.new ext: ext
      end
    end

    def add_extension_item(nid : NID, value, critical = false)
      self.extension = ExtensionFactory.create self, nid: nid, value: value, critical: critical
    end

    def verify(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_verify self, pkey
      raise Error.new "X509_verify" if ret < 0_i32

      true
    end

    def sign(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY, algorithm = LibCrypto.evp_sha256)
      raise Error.new "X509_sign" if LibCrypto.x509_sign(self, pkey, algorithm).zero?
    end

    def to_s : String
      io = IO::Memory.new
      to_io io

      String.new io.to_slice
    end

    def to_io(io : IO) : IO
      mem_bio = OpenSSL::MemBIO.new
      LibCrypto.pem_write_bio_x509 mem_bio, self
      mem_bio.to_io io: io

      mem_bio.free
      io
    end

    def random_serial : Int32
      Random.rand x: Int32::MAX
    end

    def free : Bool
      return false if freed
      LibCrypto.x509_free self
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @certificate
    end
  end
end
