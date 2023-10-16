module OpenSSL::X509
  class SuperExtension < Extension
    getter freed : Bool

    def initialize(nid : Int32, value : String, critical = false)
      valstr = String.build do |str|
        str << "critical," if critical
        str << value
      end

      @ext = LibCrypto.x509v3_ext_nconf_nid nil, nil, nid, valstr
      raise Error.new "X509V3_EXT_nconf_nid" if @ext.null?

      @freed = false
    end

    def free : Bool
      return false if freed
      LibCrypto.x509_extension_free @ext
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @ext
    end
  end
end

require "openssl/x509"
