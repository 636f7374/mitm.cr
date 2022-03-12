module Mitm::Server
  def self.upgrade(io : IO, request : HTTP::Request, mitm_context : Mitm::Context,
                   options : Set(LibSSL::Options)? = nil, alpn_protocol : String? = nil) : Tuple(OpenSSL::SSL::Context::Server?, IO)
    return Tuple.new nil, io unless context = mitm_context.create_context_server request: request
    alpn_protocol.try { |_alpn_protocol| context.alpn_protocol = _alpn_protocol }

    options.try &.each { |option| context.add_options options: option } rescue nil
    upgraded = OpenSSL::SSL::Socket::Server.new io: io, context: context, sync_close: true rescue nil
    upgraded.sync = true if upgraded

    Tuple.new context, (upgraded || io)
  end
end
