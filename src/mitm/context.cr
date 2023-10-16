class Mitm::Context
  getter rootCertificate : String
  getter rootPrivateKey : String
  getter caching : Caching
  property country : String
  property location : String
  property notBefore : Int64
  property notAfter : Int64

  def initialize(@rootCertificate : String, @rootPrivateKey : String, @caching : Caching)
    @country = "FI"
    @location = "Helsinki"
    @notBefore = -1_i64
    @notAfter = 365_i64
  end

  def self.new(root_certificate : String, root_private_key : String, capacity : Int32)
    new rootCertificate: root_certificate, rootPrivateKey: root_private_key, caching: Caching.new(capacity: capacity)
  end

  def self.create_client(verify_mode = OpenSSL::SSL::VerifyMode::NONE) : OpenSSL::SSL::Context::Client
    client = OpenSSL::SSL::Context::Client.new
    client.verify_mode = verify_mode

    client
  end

  def create_context_server(request : HTTP::Request) : OpenSSL::SSL::Context::Server?
    return unless hostname = request.hostname
    create_context_server hostname: hostname
  end

  private def create_context_server(text_certificate : String, text_private_key : String) : OpenSSL::SSL::Context::Server
    _certificate = OpenSSL::X509::SuperCertificate.parse text: text_certificate
    _private_key = OpenSSL::PKey.parse_private_key text: text_private_key

    server = OpenSSL::SSL::Context::Server.new
    server.ca_certificate_text = _certificate
    server.private_key_text = _private_key

    server
  end

  def create_context_server(hostname : String, modulus_size : Int32 = 2048_i32) : OpenSSL::SSL::Context::Server
    caching.get(hostname: hostname).try do |entry|
      certificate, private_key = entry
      return create_context_server text_certificate: certificate, text_private_key: private_key
    end

    root_certificate = OpenSSL::X509::SuperCertificate.parse text: rootCertificate
    root_private_key = OpenSSL::PKey.parse_private_key text: rootPrivateKey

    private_key = OpenSSL::PKey::RSA.new bits: modulus_size
    certificate = OpenSSL::X509::SuperCertificate.new
    issuer_name = root_certificate.subject_name

    x509_name = OpenSSL::X509::SuperName.new
    x509_name.add_entry oid: "C", value: country
    x509_name.add_entry oid: "ST", value: " "
    x509_name.add_entry oid: "L", value: location
    x509_name.add_entry oid: "O", value: " "
    x509_name.add_entry oid: "OU", value: " "
    x509_name.add_entry oid: "CN", value: hostname

    certificate.version = 2_i32
    certificate.serial = certificate.random_serial
    certificate.not_before = notBefore
    certificate.not_after = notAfter
    certificate.public_key = private_key.pkey
    certificate.subject_name = x509_name
    certificate.issuer_name = issuer_name

    extended_key_usage = OpenSSL::X509::SuperExtension.new nid: OpenSSL::NID::NID_ext_key_usage.value, value: [OpenSSL::EXTENDED_KEY_USAGE[:SERVER_AUTH]].join(", "), critical: false
    key_usage = OpenSSL::X509::SuperExtension.new nid: OpenSSL::NID::NID_key_usage.value, value: [OpenSSL::KEY_USAGE[:NON_REPUDIATION], OpenSSL::KEY_USAGE[:DIGITAL_SIGNATURE], OpenSSL::KEY_USAGE[:KEY_ENCIPHERMENT], OpenSSL::KEY_USAGE[:DATA_ENCIPHERMENT]].join(", "), critical: true
    subject_alt_name = OpenSSL::X509::SuperExtension.new nid: OpenSSL::NID::NID_subject_alt_name.value, value: OpenSSL.generate_subject_alt_name(domains: [hostname]), critical: false
    basic_constraints = OpenSSL::X509::SuperExtension.new nid: OpenSSL::NID::NID_basic_constraints.value, value: "CA:FALSE", critical: true
    #  subject_key_identifier = OpenSSL::X509::Extension.new nid: OpenSSL::NID::NID_subject_key_identifier.value, value: "hash", critical: false # => X509V3_EXT_nconf_nid: error:1100007D:X509 V3 routines::no subject details (OpenSSL::Error) (?)
    certificate.extensions = [extended_key_usage, key_usage, subject_alt_name, basic_constraints]

    certificate.sign pkey: root_private_key
    caching.set hostname: hostname, entry: Tuple.new certificate.to_s, private_key.to_s(OpenSSL::PKey::KeyFlag::PRIVATE_KEY)

    server = OpenSSL::SSL::Context::Server.new
    server.ca_certificate_text = certificate
    server.private_key_text = private_key.pkey

    # root_private_key.free
    # root_certificate.free
    # private_key.free
    # certificate.free
    # x509_name.free
    # issuer_name.free

    server
  end
end

require "openssl/x509"
