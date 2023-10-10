module Mitm::Server
  def self.upgrade(io : IO, hostname : String, mitm_context : Mitm::Context, options : Set(LibSSL::Options)? = nil, alpn_protocol : String? = nil) : Tuple(OpenSSL::SSL::Context::Server?, IO, Exception?)
    ssl_context = mitm_context.create_context_server hostname: hostname
    alpn_protocol.try { |_alpn_protocol| ssl_context.alpn_protocol = _alpn_protocol }
    options.try &.each { |option| ssl_context.add_options options: option }

    begin
      upgraded = OpenSSL::SSL::Socket::Server.new io: io, context: ssl_context, sync_close: true
      upgraded.sync = true
    rescue ex
      upgraded.try &.close rescue nil
      ssl_context.free

      return Tuple.new nil, io, ex
    end

    Tuple.new ssl_context, upgraded, nil
  end
end
