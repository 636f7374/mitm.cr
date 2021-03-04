module Mitm::Client
  def self.upgrade(io : IO, hostname : String? = nil, options : Array(LibSSL::Options)? = nil,
                   verify_mode : OpenSSL::SSL::VerifyMode = OpenSSL::SSL::VerifyMode::NONE) : Tuple(OpenSSL::SSL::Context::Client?, IO)
    return Tuple.new nil, io unless context = Context.create_client verify_mode: verify_mode

    options.try &.each { |option| context.add_options options: option } rescue nil
    upgraded = OpenSSL::SSL::Socket::Client.new io: io, context: context, sync_close: true, hostname: hostname rescue nil

    Tuple.new context, (upgraded || io)
  end
end
