module Mitm::Server
  def self.upgrade(io : IO, request : HTTP::Request, mitm_context : MITM::Context,
                   options : Array(LibSSL::Options)? = nil) : Tuple(OpenSSL::SSL::Context::Server?, IO)
    return Tuple.new nil, io unless context = mitm_context.create_server request: request

    options.try &.each { |option| context.add_options options: option } rescue nil
    upgraded = OpenSSL::SSL::Socket::Server.new io: io, context: context, sync_close: true rescue nil
    upgraded.sync = true if upgraded

    Tuple.new context, (upgraded || io)
  end
end
