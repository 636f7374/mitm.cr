module OpenSSL
  class PKey
    enum KeyFlag : UInt8
      ALL         = 0_u8
      PRIVATE_KEY = 1_u8
      PUBLIC_KEY  = 2_u8
    end

    getter keyType : KeyFlag
    getter pkey : LibCrypto::EVP_PKEY
    getter freed : Bool

    def initialize(@pkey : LibCrypto::EVP_PKEY = LibCrypto.evp_pkey_new, @keyType = KeyFlag::ALL)
      @freed = false
    end

    def self.parse_public_key(text : String, password = nil)
      mem_bio = MemBIO.new
      mem_bio.write data: text

      pkey = LibCrypto.pem_read_bio_pubkey mem_bio, nil, nil, password
      raise Exception.new String.build { |io| io << "PKey.parse_public_key: " << "Parse failed, get null pointer (" << pkey.class << ")!" } if pkey.null?

      new pkey, KeyFlag::PUBLIC_KEY
    end

    def self.parse_private_key(text : String, password = nil)
      mem_bio = MemBIO.new
      mem_bio.write data: text

      pkey = LibCrypto.pem_read_bio_privatekey mem_bio, nil, nil, password
      raise Exception.new String.build { |io| io << "PKey.parse_private_key: " << "Parse failed, get null pointer (" << pkey.class << ")!" } if pkey.null?

      new pkey, KeyFlag::PRIVATE_KEY
    end

    def private_key?
      KeyFlag::PRIVATE_KEY == keyType
    end

    def public_key?
      KeyFlag::PUBLIC_KEY == keyType
    end

    def to_rsa
      rsa = LibCrypto.evp_pkey_get1_rsa self
      raise Exception.new String.build { |io| io << "PKey.to_rsa: " << "Parse failed, get null pointer (" << rsa.class << ")!" } if rsa.null?

      RSA.new rsa: rsa, keyType: keyType
    end

    def to_dsa
      dsa = LibCrypto.evp_pkey_get1_dsa self
      raise Exception.new String.build { |io| io << "PKey.to_dsa: " << "Parse failed, get null pointer (" << dsa.class << ")!" } if dsa.null?

      DSA.new dsa: dsa, keyType: keyType
    end

    def modulus_size
      LibCrypto.evp_pkey_size self
    end

    def free : Bool
      return false if freed
      LibCrypto.evp_pkey_free @pkey
      @freed = true
    end

    def finalize
      free
    end

    def to_unsafe
      @pkey
    end
  end
end
