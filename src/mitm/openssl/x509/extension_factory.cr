module OpenSSL::X509
  struct ExtensionFactory
    def initialize(@issuerCertificate : SuperCertificate, @subjectCertificate : SuperCertificate)
    end

    def self.new(certificate : SuperCertificate)
      new issuerCertificate: certificate, subjectCertificate: certificate
    end

    def issuer_certificate=(certificate : SuperCertificate)
      @issuerCertificate = certificate
    end

    def subject_certificate=(certificate : SuperCertificate)
      @subjectCertificate = certificate
    end

    def create_subject_alt_name(domain : String)
      create_subject_alt_name domains: [domain]
    end

    def create_subject_alt_name(domains : Array(String))
      create nid: NID::NID_subject_alt_name, value: alt_name_merge(domains: domains)
    end

    def alt_name_merge(domains : Array(String))
      value = domains.map { |domain| String.build { |io| io << "DNS:" << domain } }
      value.join ", "
    end

    def create_ext_usage(ext_key_usage : SuperCertificate::ExtKeyUsage)
      create_ext_usage list: [ext_key_usage]
    end

    def create_ext_usage(list : Array(SuperCertificate::ExtKeyUsage))
      create nid: NID::NID_ext_key_usage, value: usage_merge(list: list)
    end

    def create_usage(list : Array(SuperCertificate::KeyUsage))
      create nid: NID::NID_key_usage, value: usage_merge(list: list), critical: true
    end

    def create_usage(key_usage : SuperCertificate::KeyUsage)
      create_usage [key_usage]
    end

    def usage_merge(list : Array(SuperCertificate::KeyUsage | SuperCertificate::ExtKeyUsage))
      value = list.map { |value| value.to_s.camelcase lower: true }
      value.join ", "
    end

    def self.build_value(value, critical : Bool)
      String.build do |io|
        io << "critical, " if critical
        io << value
      end
    end

    def self.create(certificate : SuperCertificate, nid : OpenSSL::NID, value : String, critical : Bool = false)
      create issuer: certificate, subject: certificate, nid: nid, value: value, critical: critical
    end

    def self.create(issuer : SuperCertificate, subject : SuperCertificate, nid : OpenSSL::NID, value : String, critical : Bool = false)
      ctx = LibCrypto::X509V3_CTX.new
      LibCrypto.x509v3_set_ctx pointerof(ctx), issuer, subject, nil, nil, 0_i32

      ret = LibCrypto.x509v3_ext_conf_nid nil, pointerof(ctx), nid, build_value value, critical
      raise Error.new "X509V3_EXT_conf_nid" if ret.null?

      ret
    end

    def create(nid : OpenSSL::NID, value : String, critical : Bool = false)
      ctx = LibCrypto::X509V3_CTX.new
      LibCrypto.x509v3_set_ctx pointerof(ctx), @issuerCertificate, @subjectCertificate, nil, nil, 0_i32

      ret = LibCrypto.x509v3_ext_conf_nid nil, pointerof(ctx), nid, ExtensionFactory.build_value(value: value, critical: critical)
      raise Error.new "X509V3_EXT_conf_nid" if ret.null?

      ret
    end
  end
end
