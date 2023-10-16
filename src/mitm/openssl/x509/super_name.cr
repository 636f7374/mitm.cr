module OpenSSL::X509
  class SuperName < Name
    getter freed : Bool

    def initialize
      @name = LibCrypto.x509_name_new
      raise Error.new "X509_NAME_new" if @name.null?
      @freed = false
    end

    def initialize(name : LibCrypto::X509_NAME)
      @name = LibCrypto.x509_name_dup name
      raise Error.new "X509_NAME_dup" if @name.null?
      @freed = false
    end

    def free : Bool
      return false if freed
      LibCrypto.x509_name_free @name
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @name
    end
  end
end
