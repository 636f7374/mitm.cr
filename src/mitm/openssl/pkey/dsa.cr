module OpenSSL
  class PKey
    class DSA < PKey
      getter dsa : LibCrypto::DSA
      getter keyType : KeyFlag
      getter pkey : LibCrypto::EVP_PKEY
      getter freed : Bool

      def initialize(@dsa : LibCrypto::DSA, @keyType : KeyFlag = KeyFlag::ALL)
        @pkey = LibCrypto.evp_pkey_new
        LibCrypto.evp_pkey_assign @pkey, OpenSSL::NID::NID_dsa, @dsa.as(Pointer(Void*))
        @freed = false
      end

      def self.new(bits : Int = 4096_i32)
        generate bits: bits
      end

      def self.generate(bits : Int = 4096_i32) : DSA
        seed = uninitialized UInt8[32_i32]
        raise OpenSSL::Error.new if LibCrypto.rand_bytes(seed.to_slice, 32_i32).zero?

        dsa_key = LibCrypto.dsa_new
        raise OpenSSL::Error.new if dsa_key.null?

        LibCrypto.dsa_generate_parameters_ex dsa: dsa_key, bits: bits, seed: seed.to_slice.to_unsafe, seed_len: 32_i32,
          counter_ret: out counter, h_ret: out h, cb_arg: nil
        raise OpenSSL::Error.new if dsa_key.null?

        if 1_i32 != LibCrypto.dsa_generate_key(dsa_key)
          LibCrypto.dsa_free dsa_key
          raise OpenSSL::Error.new
        end

        new dsa: dsa_key, keyType: KeyFlag::ALL
      end

      def self.parse_public_key(text : String, password = nil)
        pkey = PKey.parse_public_key text: text, password: password
        pkey.to_dsa
      end

      def self.parse_private_key(text : String, password = nil)
        mem_bio = MemBIO.new
        mem_bio.write data: text

        dsa_key = LibCrypto.pem_read_bio_dsaprivatekey mem_bio, nil, nil, password
        mem_bio.free
        raise Exception.new String.build { |io| io << "DSA.parse_private_key: " << "Parse failed, get null pointer (" << dsa_key.class << ")!" } if dsa_key.null?

        new dsa: dsa_key, keyType: KeyFlag::PRIVATE_KEY
      end

      def to_s(key_flag : KeyFlag, cipher : LibCrypto::EVP_CIPHER? = nil, password = nil)
        io = IO::Memory.new
        to_io io: io, key_flag: key_flag, cipher: cipher, password: password

        String.new io.to_slice
      end

      def to_s(cipher : LibCrypto::EVP_CIPHER? = nil, password = nil)
        to_s key_flag: keyType, cipher: cipher, password: password
      end

      def to_io(io : IO, cipher : LibCrypto::EVP_CIPHER? = nil, password = nil)
        to_io io: io, key_type: keyType, cipher: cipher, password: password
      end

      def to_io(io : IO, key_flag : KeyFlag, cipher : LibCrypto::EVP_CIPHER? = nil, password = nil)
        mem_bio = MemBIO.new

        case key_flag
        in .private_key?
          LibCrypto.pem_write_bio_dsaprivatekey mem_bio, self, cipher, nil, 0_i32, nil, password
          mem_bio.to_io io: io
        in .public_key?
          LibCrypto.pem_write_bio_dsa_pubkey mem_bio, self
          mem_bio.to_io io: io
        in .all?
        end

        mem_bio.free
        io
      end

      def modulus_size
        LibCrypto.dsa_size self
      end

      def private_key? : PKey?
        return unless keyType.all?

        private_key!
      end

      def private_key! : PKey
        private_key = to_s key_flag: KeyFlag::PRIVATE_KEY
        DSA.parse_private_key text: private_key
      end

      def public_key? : PKey?
        return unless keyType.all?

        public_key!
      end

      def public_key! : PKey
        public_key = to_s key_flag: KeyFlag::PUBLIC_KEY
        DSA.parse_public_key text: public_key
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
        @dsa
      end
    end
  end
end
