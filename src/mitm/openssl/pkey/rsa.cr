module OpenSSL
  class PKey
    class RSA < PKey
      getter rsa : LibCrypto::RSA
      getter keyType : KeyFlag
      getter pkey : LibCrypto::EVP_PKEY
      getter freed : Bool

      def initialize(@rsa : LibCrypto::RSA, @keyType : KeyFlag = KeyFlag::ALL)
        @pkey = LibCrypto.evp_pkey_new
        LibCrypto.evp_pkey_assign @pkey, OpenSSL::NID::NID_rsaEncryption, @rsa.as(Pointer(Void*))
        @freed = false
      end

      def self.new(bits : Int = 4096_i32)
        generate bits: bits
      end

      def self.generate(bits : Int = 4096_i32, exponent = 65537_u32)
        new rsa: LibCrypto.rsa_generate_key(bits, exponent, nil, nil), keyType: KeyFlag::ALL
      end

      def self.parse_public_key(text : String, password = nil)
        mem_bio = MemBIO.new
        mem_bio.write data: text

        rsa_key = LibCrypto.pem_read_bio_rsapublickey mem_bio, nil, nil, password
        mem_bio.free
        raise Exception.new String.build { |io| io << "RSA.parse_public_key: " << "Parse failed, get null pointer (" << rsa_key.class << ")!" } if rsa_key.null?

        new rsa: rsa_key, keyType: KeyFlag::PUBLIC_KEY
      end

      def self.parse_private_key(text : String, password = nil)
        mem_bio = MemBIO.new
        mem_bio.write data: text

        rsa_key = LibCrypto.pem_read_bio_rsaprivatekey mem_bio, nil, nil, password
        mem_bio.free
        raise Exception.new String.build { |io| io << "RSA.parse_private_key: " << "Parse failed, get null pointer (" << rsa_key.class << ")!" } if rsa_key.null?

        new rsa: rsa_key, keyType: KeyFlag::PRIVATE_KEY
      end

      def to_s(cipher = nil, password = nil)
        to_s key_flag: keyType, cipher: cipher, password: password
      end

      def to_s(key_flag : KeyFlag, cipher = nil, password = nil)
        io = IO::Memory.new
        to_io io: io, key_flag: key_flag, cipher: cipher, password: password

        String.new io.to_slice
      end

      def to_io(io : IO, cipher = nil, password = nil)
        to_io io: io, key_flag: keyType, cipher: cipher, password: password
      end

      def to_io(io : IO, key_flag : KeyFlag, cipher = nil, password = nil)
        mem_bio = MemBIO.new

        case key_flag
        in .private_key?
          LibCrypto.pem_write_bio_rsaprivatekey mem_bio, self, cipher, nil, 0_i32, nil, password
          mem_bio.to_io io: io
        in .public_key?
          LibCrypto.pem_write_bio_rsa_pubkey mem_bio, self
          mem_bio.to_io io: io
        in .all?
        end

        mem_bio.free
        io
      end

      def modulus_size
        LibCrypto.rsa_size self
      end

      def private_key? : PKey?
        return unless keyType.all?

        private_key!
      end

      def private_key! : PKey
        private_key_rsa = LibCrypto.rsaprivateKey_dup self
        raise OpenSSL::Error.new "RSAPrivateKey_dup" if private_key_rsa.null?

        RSA.new rsa: private_key_rsa, keyType: KeyFlag::PRIVATE_KEY
      end

      def public_key? : PKey?
        return unless keyType.all?

        public_key!
      end

      def public_key! : PKey
        public_key_rsa = LibCrypto.rsapublickey_dup self
        raise OpenSSL::Error.new "RSAPublicKey_dup" if public_key_rsa.null?

        RSA.new rsa: public_key_rsa, keyType: KeyFlag::PUBLIC_KEY
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
        @rsa
      end
    end
  end
end
