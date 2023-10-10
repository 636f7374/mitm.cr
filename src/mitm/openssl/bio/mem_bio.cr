class OpenSSL::MemBIO < IO
  getter freed : Bool

  def initialize(@bio : LibCrypto::Bio* = LibCrypto.bio_new(LibCrypto.bio_s_mem))
    @freed = false
  end

  def read(slice : Bytes)
    LibCrypto.bio_read self, slice, slice.size
  end

  def write(data : String) : Nil
    write slice: data.to_slice
  end

  def write(slice : Bytes) : Nil
    LibCrypto.bio_write self, slice, slice.size
  end

  def reset
    ret = LibCrypto.bio_ctrl self, LibCrypto::BIO_CTRL_RESET, 0_i64, nil
    raise OpenSSL::Error.new "BIO_ctrl" if ret.zero?

    ret
  end

  def to_io(io : IO)
    IO.copy self, io
  end

  def to_s
    io = IO::Memory.new
    to_io io

    String.new io.to_slice
  end

  def free : Bool
    return false if freed
    LibCrypto.bio_free_all self
    @freed = true
  end

  def finalize
    free
  end

  def to_unsafe
    @bio
  end
end
