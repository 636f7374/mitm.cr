module OpenSSL::ASN1
  class Integer
    getter freed : Bool

    def initialize(@integer : LibCrypto::ASN1_INTEGER)
      @freed = false
    end

    def self.new
      new LibCrypto.asn1_integer_new
    end

    def freed=(value : Bool)
      @freed = value
    end

    def free : Bool
      return false if freed
      LibCrypto.asn1_integer_free self
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @integer
    end
  end
end
