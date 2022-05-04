module OpenSSL::ASN1
  class Time
    getter freed : Bool

    def initialize(@time : LibCrypto::ASN1_TIME)
      @freed = false
    end

    def self.new(period : Int)
      new LibCrypto.x509_gmtime_adj nil, period
    end

    def self.days_from_now(days : Int)
      new days * 60_i32 * 60_i32 * 24_i32
    end

    def freed=(value : Bool)
      @freed = value
    end

    def free : Bool
      return false if freed
      LibCrypto.asn1_time_free self
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @time
    end
  end
end
