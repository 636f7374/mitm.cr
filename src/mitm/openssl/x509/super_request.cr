module OpenSSL::X509
  class SuperRequest
    getter freed : Bool

    def initialize(@req : LibCrypto::X509_REQ)
      @freed = false
    end

    def self.new
      generate
    end

    def self.generate
      x509_req = LibCrypto.x509_req_new
      raise OpenSSL::Error.new "X509_REQ_new" if x509_req.null?

      new x509_req
    end

    def self.parse(text : String, password = nil)
      mem_bio = MemBIO.new
      mem_bio.write data: text

      x509_req = LibCrypto.pem_read_bio_x509_req mem_bio, nil, nil, password
      mem_bio.free
      raise Exception.new String.build { |io| io << "SuperRequest.parse: " << "Parse failed, get null pointer (" << x509_req.class << ")!" } if x509_req.null?

      new x509_req
    end

    def subject_name
      subject = LibCrypto.x509_req_get_subject_name self
      raise OpenSSL::Error.new "X509_REQ_get_subject_name" if subject.null?

      SuperName.new subject
    end

    def public_key
      OpenSSL::PKey.new LibCrypto.x509_req_get_pubkey(self),
        OpenSSL::PKey::KeyFlag::PUBLIC_KEY
    end

    def pkey
      @pkey
    end

    def sign(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY, algorithm = LibCrypto.evp_sha256)
      raise OpenSSL::Error.new "X509_REQ_sign" if LibCrypto.x509_req_sign(self, pkey, algorithm).zero?
    end

    def subject_name=(subject : String)
      name = SuperName.parse subject
      self.subject_name = name

      subject
    end

    def subject_name=(name : SuperName)
      ret = LibCrypto.x509_req_set_subject_name self, name
      raise OpenSSL::Error.new "X509_set_subject_name" if ret.zero?

      name
    end

    def pkey=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      @pkey = pkey
    end

    def public_key=(pkey : OpenSSL::PKey | LibCrypto::EVP_PKEY)
      ret = LibCrypto.x509_req_set_pubkey self, pkey
      raise OpenSSL::Error.new "X509_REQ_set_pubkey" if ret.zero?

      @pkey = pkey
    end

    def version=(version = 0_i64)
      ret = LibCrypto.x509_req_set_version self, version
      raise OpenSSL::Error.new "X509_REQ_set_version" if ret.zero?

      version
    end

    def to_s
      io = IO::Memory.new
      to_io io

      String.new io.to_slice
    end

    def to_io(io : IO)
      mem_bio = OpenSSL::MemBIO.new
      LibCrypto.pem_write_bio_x509_req mem_bio, self
      mem_bio.to_io io

      mem_bio.free
      io
    end

    def free : Bool
      return false if freed
      LibCrypto.x509_req_free self
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @req
    end
  end
end
