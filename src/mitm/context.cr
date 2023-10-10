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

    extension_factory = OpenSSL::X509::ExtensionFactory.new certificate: root_certificate

    certificate.extensions = [
      # extension_factory.create(OpenSSL::NID::NID_basic_constraints, "CA:FALSE", true),
      # extension_factory.create(OpenSSL::NID::NID_subject_key_identifier, "hash", false),
      extension_factory.create_subject_alt_name(hostname),
      extension_factory.create_ext_usage(OpenSSL::X509::SuperCertificate::ExtKeyUsage::ServerAuth),
      extension_factory.create_usage([
        OpenSSL::X509::SuperCertificate::KeyUsage::NonRepudiation,
        OpenSSL::X509::SuperCertificate::KeyUsage::DigitalSignature,
        OpenSSL::X509::SuperCertificate::KeyUsage::KeyEncipherment,
        OpenSSL::X509::SuperCertificate::KeyUsage::DataEncipherment,
      ]),
    ]

    certificate.sign pkey: root_private_key
    caching.set hostname: hostname, entry: Tuple.new certificate.to_s, private_key.to_s(OpenSSL::PKey::KeyFlag::PRIVATE_KEY)

    server = OpenSSL::SSL::Context::Server.new
    server.ca_certificate_text = certificate
    server.private_key_text = private_key.pkey

    # root_private_key.free
    root_certificate.free
    private_key.free
    certificate.free
    # x509_name.free
    # issuer_name.free

    server
  end

  def create_root_context_tuple(modulus_size : Int32 = 2048_i32) : Tuple(String, String)
    private_key = OpenSSL::PKey::RSA.new bits: modulus_size
    certificate = OpenSSL::X509::SuperCertificate.new

    x509_name = OpenSSL::X509::SuperName.new
    x509_name.add_entry oid: "C", value: country
    x509_name.add_entry oid: "ST", value: " "
    x509_name.add_entry oid: "L", value: location
    x509_name.add_entry oid: "O", value: " "
    x509_name.add_entry oid: "OU", value: " "

    certificate.version = 2_i32
    certificate.serial = certificate.random_serial
    certificate.not_before = notBefore
    certificate.not_after = notAfter
    certificate.public_key = private_key.pkey
    certificate.subject_name = x509_name
    certificate.issuer_name = x509_name

    extension_factory = OpenSSL::X509::ExtensionFactory.new certificate: certificate

    certificate.extensions = [
      extension_factory.create(OpenSSL::NID::NID_basic_constraints, "CA:FALSE", true),
      extension_factory.create(OpenSSL::NID::NID_subject_key_identifier, "hash", false),
      extension_factory.create(OpenSSL::NID::NID_authority_key_identifier, "keyid,issuer"),
      extension_factory.create_ext_usage(OpenSSL::X509::SuperCertificate::ExtKeyUsage::ServerAuth),
      extension_factory.create_usage([
        OpenSSL::X509::SuperCertificate::KeyUsage::NonRepudiation,
        OpenSSL::X509::SuperCertificate::KeyUsage::DigitalSignature,
        OpenSSL::X509::SuperCertificate::KeyUsage::KeyEncipherment,
        OpenSSL::X509::SuperCertificate::KeyUsage::DataEncipherment,
      ]),
    ]

    certificate.sign pkey: private_key.pkey

    private_key.free
    certificate.free
    x509_name.free

    Tuple.new certificate.to_s, private_key.to_s(OpenSSL::PKey::KeyFlag::PRIVATE_KEY)
  end
end
