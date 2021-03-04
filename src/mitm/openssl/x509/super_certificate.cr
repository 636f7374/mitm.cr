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

    def initialize(@certificate : LibCrypto::X509 = LibCrypto.x509_new)
    end

    def self.parse(text : String)
      mem_bio = MemBIO.new
      mem_bio.write data: text

      x509 = LibCrypto.pem_read_bio_x509 mem_bio, nil, nil, nil
      raise Exception.new String.build { |io| io << "SuperCertificate.parse: " << "Parse failed, get null pointer (" << x509.class << ")!" } if x509.null?

      new x509
    end

    def public_key
      OpenSSL::PKey.new LibCrypto.x509_get_pubkey(self),
        OpenSSL::PKey::KeyFlag::PUBLIC_KEY
    end

    def pkey
      @pkey
    end

    def serial
      ret = LibCrypto.x509_get_serialnumber self
      raise Error.new "X509_get_serialNumber" if ret.zero?

      ASN1::Integer.new integer: ret
    end

    def not_before
      before = LibCrypto.x509_get0_notbefore self
      raise Error.new "X509_get0_notBefore" if before.null?

      ASN1::Time.new time: before
    end

    def not_after
      after = LibCrypto.x509_get0_notafter self
      raise Error.new "X509_get0_notAfter" if after.null?

      ASN1::Time.new time: after
    end

    def issuer_name
      issuer = LibCrypto.x509_get_issuer_name self
      raise Error.new "X509_get_issuer_name" if issuer.null?

      SuperName.new name: issuer
    end

    def subject_name
      subject = LibCrypto.x509_get_subject_name self
      raise Error.new "X509_get_subject_name" if subject.null?

      SuperName.new name: subject
    end

    def extension_count
      ret = LibCrypto.x509_get_ext_count self
      raise Error.new "X509_get_ext_count" if ret.zero?

      ret
    end

    def extensions
      count = LibCrypto.x509_get_ext_count self

      Array(Extension).new count do |item|
        ext = LibCrypto.x509_get_ext self, item

        Extension.new ext
      end
    end

    def add_extension_item(nid : NID, value, critical = false)
      self.extension = ExtensionFactory.create self, nid: nid, value: value, critical: critical
    end

    def extension=(item = LibCrypto::X509_EXTENSION)
      self.extensions = [item]
    end

    def extensions=(list : Array(LibCrypto::X509_EXTENSION))
      list.each do |item|
        unless LibCrypto.x509_add_ext(self, item, -1_i32).null?
          LibCrypto.x509_extension_free item

          next
        end

        LibCrypto.x509_extension_free item
        raise OpenSSL::Error.new "X509_add_ext"
      end
    end

    def verify(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_verify self, pkey
      raise Error.new "X509_verify" if ret < 0_i32

      true
    end

    def sign(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY, algorithm = LibCrypto.evp_sha256)
      raise OpenSSL::Error.new "X509_sign" if LibCrypto.x509_sign(self, pkey, algorithm).zero?
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

      io
    end

    def subject_name=(subject : String) : String
      name = SuperName.parse subject
      self.subject_name = name

      subject
    end

    def subject_name=(name : SuperName) : SuperName
      ret = LibCrypto.x509_set_subject_name self, name
      raise Error.new "X509_set_subject_name" if ret.zero?

      name
    end

    def issuer_name=(issuer : String) : String
      name = SuperName.parse issuer
      self.issuer_name = name

      issuer
    end

    def issuer_name=(name : SuperName) : SuperName
      ret = LibCrypto.x509_set_issuer_name self, name
      raise Error.new "X509_set_issuer_name" if ret.zero?

      name
    end

    def pkey=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      @pkey = pkey
    end

    def public_key=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_set_pubkey self, pkey
      raise Error.new "X509_set_pubkey" if ret.zero?

      @pkey = pkey
    end

    def version=(version = 2_i64)
      ret = LibCrypto.x509_set_version self, version
      raise Error.new "X509_set_version" if ret.zero?

      version
    end

    def serial=(number : Int)
      asn1 = ASN1::Integer.new
      LibCrypto.asn1_integer_set asn1, number

      ret = LibCrypto.x509_set_serialnumber self, asn1
      raise Error.new "X509_set_serialNumber" if ret.zero?

      number
    end

    def not_before=(valid_period : Int = 0_i64)
      asn1 = ASN1::Time.days_from_now valid_period

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        ret = LibCrypto.x509_set1_notbefore self, asn1
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

    def not_after=(valid_period : Int = 365_i64)
      asn1 = ASN1::Time.days_from_now valid_period

      {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.2") >= 0_i32 %}
        ret = LibCrypto.x509_set1_notafter self, asn1
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

    def random_serial : Int32
      Random.rand Int32::MAX
    end

    def finalize
      return if @certificate.null?
      LibCrypto.x509_free self
    end

    def to_unsafe
      @certificate
    end
  end
end
