module Mitm::Client
  def self.upgrade(io : IO, hostname : String? = nil, options : Array(LibSSL::Options)? = nil,
                   verify_mode : OpenSSL::SSL::VerifyMode = OpenSSL::SSL::VerifyMode::NONE) : Tuple(OpenSSL::SSL::Context::Client?, IO)
    return Tuple.new nil, io unless tls_context = Context.create_client verify_mode: verify_mode
    options.try &.each { |option| context.add_options options: option } rescue nil

    upgraded = begin
      tls_socket = OpenSSL::SSL::Socket::Client.new io: io, context: tls_context, sync_close: true, hostname: hostname
    rescue ex
      io.close rescue nil
      tls_socket.try &.close rescue nil
      tls_context.free

      nil
    end

    Tuple.new tls_context, (upgraded || io)
  end
end
