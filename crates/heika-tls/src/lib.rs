//! ノードと TLS でつなぐ。
//!
//! catapult と同じく TLS 1.3 と X25519 だけを使い、証明書は Ed25519 の2枚のチェーン（ノード、CA）だけを扱う。
//! webpki は v1 の証明書を読めないので、証明書は heika-cert で読んで自分で確かめる。

use std::fmt;
use std::io::{self, Read, Write};
use std::iter;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use heika_cert::certificate::{self, Certificate, ChainError};
use heika_cert::key;
use heika_core::key::{PrivateKey, PublicKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::version::TLS13;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme,
};

/// TLS で名乗るための、証明書のチェーンと秘密鍵。
pub struct Identity {
    certified_key: Arc<CertifiedKey>,
}

impl Identity {
    /// ノード、CA の順のチェーンと、ノードの証明書の秘密鍵から作る。
    ///
    /// チェーンは catapult の条件を満たしていなければならない。
    /// 秘密鍵は rustls と ring に渡り、そちらでは使い終わっても0で上書きされない。
    pub fn new(chain: &[Certificate], key: &PrivateKey) -> Result<Self, IdentityError> {
        certificate::check_catapult_chain(chain).map_err(IdentityError::Chain)?;
        if PublicKey::from_private_key(key) != *chain[0].public_key() {
            return Err(IdentityError::KeyMismatch);
        }
        let der = key::private_key_to_der(key);
        let signing_key = provider()
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.to_vec())))
            .expect("ring loads an Ed25519 PKCS#8 v1 key");
        let chain = chain
            .iter()
            .map(|certificate| CertificateDer::from(certificate.to_der().to_vec()))
            .collect();
        Ok(Self {
            certified_key: Arc::new(CertifiedKey::new(chain, signing_key)),
        })
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identity(..)")
    }
}

/// 名乗るための証明書と秘密鍵が使えない理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// チェーンが catapult の条件を満たさない
    Chain(ChainError),
    /// 秘密鍵がノードの証明書の公開鍵と組でない
    KeyMismatch,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chain(error) => write!(
                f,
                "証明書のチェーンが catapult の条件を満たしていません（{error}）"
            ),
            Self::KeyMismatch => f.write_str("秘密鍵がノードの証明書の公開鍵と組になっていません"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// 相手の証明書をどこまで確かめるか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerVerification {
    /// catapult がつなぐときと同じく、チェーンの条件と有効期間を確かめる
    Catapult,
    /// 中身を調べるために、チェーンは確かめずに受け付ける。
    /// 相手がノードの証明書の秘密鍵を持っていることだけは、TLS の署名で確かめる
    Inspect,
}

/// `identity` で名乗る、TLS 1.3 と X25519 だけのクライアントの設定。
pub fn client_config(identity: &Identity, verification: ServerVerification) -> ClientConfig {
    let provider = provider();
    ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .expect("ring supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier {
            provider,
            verification,
        }))
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(
            identity.certified_key.clone(),
        )))
}

fn provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    // catapult は鍵交換に X25519 しか使わない
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    Arc::new(provider)
}

#[derive(Debug)]
struct Verifier {
    provider: Arc<CryptoProvider>,
    verification: ServerVerification,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.verification == ServerVerification::Inspect {
            return Ok(ServerCertVerified::assertion());
        }
        let chain = iter::once(end_entity)
            .chain(intermediates)
            .map(parse)
            .collect::<Result<Vec<_>, _>>()?;
        certificate::check_catapult_chain(&chain).map_err(|error| match error {
            ChainError::NotTwoCertificates | ChainError::RootNotSelfSigned => {
                CertificateError::UnknownIssuer
            }
            ChainError::NotSignedByRoot => CertificateError::BadSignature,
        })?;
        let now = UNIX_EPOCH + Duration::from_secs(now.as_secs());
        for certificate in &chain {
            check_validity(certificate, now)?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// rustls の `verify_tls13_signature` は webpki に証明書を読ませるので、公開鍵だけを渡す版を使う。
fn verify_tls13_signature(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, Error> {
    let spki = key::public_key_to_der(parse(cert)?.public_key());
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(&spki[..]),
        dss,
        &provider.signature_verification_algorithms,
    )
}

fn parse(der: &CertificateDer<'_>) -> Result<Certificate, Error> {
    Certificate::from_der(der).map_err(|_| CertificateError::BadEncoding.into())
}

fn check_validity(certificate: &Certificate, now: SystemTime) -> Result<(), Error> {
    if now < certificate.not_before() {
        return Err(CertificateError::NotValidYet.into());
    }
    if now > certificate.not_after() {
        return Err(CertificateError::Expired.into());
    }
    Ok(())
}

/// [`inspect`] と [`send`] で起きたこと。
#[derive(Debug)]
pub struct Inspection {
    /// 相手が出した証明書の DER。ノード、CA の順のはず
    pub peer_certificates: Vec<Vec<u8>>,
    pub client_certificate: ClientCertificate,
}

/// こちらの証明書が受け付けられたか。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientCertificate {
    /// 待つあいだ切られなかったので、受け付けられたとみなせる
    Kept,
    /// TLS のアラートで切られた。中身はアラートの種類
    Rejected(String),
    /// アラートなしで切られた
    Closed,
    /// 相手から何か届いた。catapult なら起きないはず
    DataReceived,
}

/// `address` に接続して、相手が出した証明書と、こちらの証明書が受け付けられたかを調べる。
/// Symbol のパケットはやりとりせず、相手のチェーンも確かめない。
///
/// catapult はハンドシェイクのあと自分からは何も送らず、こちらの証明書を受け付けなければ
/// TLS のアラートを送って切る。なので、ハンドシェイクのあと `wait` のあいだ待ち、
/// 切られなければ受け付けられたとみなす。
pub fn inspect(
    address: &str,
    identity: &Identity,
    timeout: Duration,
    wait: Duration,
) -> Result<Inspection, ConnectError> {
    exchange(
        address,
        identity,
        ServerVerification::Inspect,
        None,
        timeout,
        wait,
    )
}

/// `address` に接続して、種類が `packet_type` で本体が `body` の Symbol のパケットを1つ送る。応答は待たない。
///
/// 相手のチェーンは catapult と同じ条件で確かめる。送ったあとは [`inspect`] と同じく `wait` のあいだ待ち、
/// こちらの証明書が弾かれなかったかを確かめる。弾かれたなら、パケットは読まれていない。
pub fn send(
    address: &str,
    identity: &Identity,
    packet_type: u32,
    body: &[u8],
    timeout: Duration,
    wait: Duration,
) -> Result<Inspection, ConnectError> {
    let size = u32::try_from(PACKET_HEADER_SIZE + body.len())
        .map_err(|_| ConnectError::Io(io::Error::other("パケットが大きすぎます")))?;
    let mut packet = Vec::with_capacity(size as usize);
    packet.extend_from_slice(&size.to_le_bytes());
    packet.extend_from_slice(&packet_type.to_le_bytes());
    packet.extend_from_slice(body);
    exchange(
        address,
        identity,
        ServerVerification::Catapult,
        Some(&packet),
        timeout,
        wait,
    )
}

/// パケットのヘッダーは、ヘッダーを含む全長 `u32` と種類 `u32` の8バイト。
const PACKET_HEADER_SIZE: usize = 8;

/// 接続してハンドシェイクを済ませ、`packet` があれば送り、`wait` のあいだ切られないか待つ。
fn exchange(
    address: &str,
    identity: &Identity,
    verification: ServerVerification,
    packet: Option<&[u8]>,
    timeout: Duration,
    wait: Duration,
) -> Result<Inspection, ConnectError> {
    let socket_address = address
        .to_socket_addrs()
        .map_err(ConnectError::Address)?
        .next()
        .ok_or_else(|| {
            ConnectError::Address(io::Error::new(
                io::ErrorKind::NotFound,
                "アドレスが見つかりません",
            ))
        })?;
    let mut socket =
        TcpStream::connect_timeout(&socket_address, timeout).map_err(ConnectError::Connect)?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(ConnectError::Io)?;
    let config = client_config(identity, verification);
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name(address)).expect("the config is valid");
    while connection.is_handshaking() {
        if let Err(error) = connection.complete_io(&mut socket) {
            // 相手の証明書を受け取ったあとでアラートが来たなら、こちらの証明書が弾かれた
            return match (alert(&error), peer_certificates(&connection)) {
                (Some(alert), Some(peer_certificates)) => Ok(Inspection {
                    peer_certificates,
                    client_certificate: ClientCertificate::Rejected(alert),
                }),
                _ => Err(ConnectError::Handshake(error)),
            };
        }
    }
    let peer_certificates = peer_certificates(&connection).unwrap_or_default();
    if let Some(packet) = packet {
        let mut stream = rustls::Stream::new(&mut connection, &mut socket);
        if let Err(error) = stream.write_all(packet).and_then(|()| stream.flush()) {
            return match alert(&error) {
                Some(alert) => Ok(Inspection {
                    peer_certificates,
                    client_certificate: ClientCertificate::Rejected(alert),
                }),
                None => Err(ConnectError::Io(error)),
            };
        }
    }
    socket
        .set_read_timeout(Some(wait))
        .map_err(ConnectError::Io)?;
    let mut byte = [0];
    let client_certificate = match rustls::Stream::new(&mut connection, &mut socket).read(&mut byte)
    {
        Ok(0) => ClientCertificate::Closed,
        Ok(_) => ClientCertificate::DataReceived,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            ClientCertificate::Kept
        }
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => ClientCertificate::Closed,
        Err(error) => match alert(&error) {
            Some(alert) => ClientCertificate::Rejected(alert),
            None => return Err(ConnectError::Io(error)),
        },
    };
    connection.send_close_notify();
    let _ = connection.complete_io(&mut socket);
    Ok(Inspection {
        peer_certificates,
        client_certificate,
    })
}

/// SNI に使う名前。catapult は見ないので、ホスト名として使えなければ適当な名前にする。
fn server_name(address: &str) -> ServerName<'static> {
    let host = address
        .rsplit_once(':')
        .map_or(address, |(host, _)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    ServerName::try_from(host.to_owned())
        .unwrap_or_else(|_| ServerName::try_from("peer").expect("a valid DNS name"))
}

fn alert(error: &io::Error) -> Option<String> {
    match error.get_ref()?.downcast_ref::<Error>()? {
        Error::AlertReceived(description) => Some(format!("{description:?}")),
        _ => None,
    }
}

fn peer_certificates(connection: &ClientConnection) -> Option<Vec<Vec<u8>>> {
    connection
        .peer_certificates()
        .map(|certificates| certificates.iter().map(|der| der.to_vec()).collect())
}

/// [`inspect`] と [`send`] が失敗した理由。
#[derive(Debug)]
pub enum ConnectError {
    /// 接続先のアドレスを解決できない
    Address(io::Error),
    /// TCP でつながらない
    Connect(io::Error),
    /// TLS のハンドシェイクが終わらない
    Handshake(io::Error),
    Io(io::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(error) => write!(f, "接続先のアドレスを解決できませんでした: {error}"),
            Self::Connect(error) => write!(f, "TCP でつながりませんでした: {error}"),
            Self::Handshake(error) => {
                write!(f, "TLS のハンドシェイクが終わりませんでした: {error}")
            }
            Self::Io(error) => write!(f, "通信できませんでした: {error}"),
        }
    }
}

impl std::error::Error for ConnectError {}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    use heika_cert::certificate::{Template, Version};
    use rustls::pki_types::UnixTime;
    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use rustls::{DistinguishedName, ServerConfig, ServerConnection};

    use super::*;

    const WAIT: Duration = Duration::from_millis(300);

    fn template(subject: &str) -> Template<'_> {
        let now = SystemTime::now();
        Template {
            subject,
            not_before: now - Duration::from_secs(60),
            not_after: now + Duration::from_secs(24 * 60 * 60),
            serial_number: &[1],
            version: Version::V1,
        }
    }

    /// `seed` から作った CA と、`seed + 1` から作ったノードのチェーンと、ノードの秘密鍵
    fn chain(seed: u8) -> (Vec<Certificate>, PrivateKey) {
        let ca_key = PrivateKey::from_bytes(&[seed; 32]);
        let node_key = PrivateKey::from_bytes(&[seed + 1; 32]);
        let ca = Certificate::self_signed(&ca_key, &template("CN=CA")).unwrap();
        let node = Certificate::issue(
            &ca,
            &ca_key,
            &PublicKey::from_private_key(&node_key),
            &template("CN=node"),
        )
        .unwrap();
        (vec![node, ca], node_key)
    }

    fn ders(chain: &[Certificate]) -> Vec<CertificateDer<'static>> {
        chain
            .iter()
            .map(|certificate| CertificateDer::from(certificate.to_der().to_vec()))
            .collect()
    }

    fn verify(chain: &[CertificateDer<'_>], now: SystemTime) -> Result<ServerCertVerified, Error> {
        let verifier = Verifier {
            provider: provider(),
            verification: ServerVerification::Catapult,
        };
        let now = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).unwrap());
        verifier.verify_server_cert(
            &chain[0],
            &chain[1..],
            &ServerName::try_from("peer").unwrap(),
            &[],
            now,
        )
    }

    #[test]
    fn verifies_a_catapult_chain() {
        let (chain, _) = chain(1);
        assert!(verify(&ders(&chain), SystemTime::now()).is_ok());
    }

    #[test]
    fn rejects_an_expired_or_future_chain() {
        let (chain, _) = chain(1);
        let later = SystemTime::now() + Duration::from_secs(2 * 24 * 60 * 60);
        assert_eq!(
            verify(&ders(&chain), later).unwrap_err(),
            CertificateError::Expired.into()
        );
        let earlier = SystemTime::now() - Duration::from_secs(2 * 60);
        assert_eq!(
            verify(&ders(&chain), earlier).unwrap_err(),
            CertificateError::NotValidYet.into()
        );
    }

    #[test]
    fn rejects_a_chain_with_another_ca() {
        let (chain, _) = chain(1);
        let other = chain_with_other_ca(&chain);
        assert_eq!(
            verify(&ders(&other), SystemTime::now()).unwrap_err(),
            CertificateError::BadSignature.into()
        );
        assert_eq!(
            verify(&ders(&chain[..1]), SystemTime::now()).unwrap_err(),
            CertificateError::UnknownIssuer.into()
        );
    }

    /// 同じ DN で別の鍵の CA に差し替えたチェーン
    fn chain_with_other_ca(chain: &[Certificate]) -> Vec<Certificate> {
        let (others, _) = self::chain(5);
        vec![chain[0].clone(), others[1].clone()]
    }

    #[test]
    fn refuses_an_identity_with_the_wrong_key_or_chain() {
        let (chain, node_key) = chain(1);
        let ca_key = PrivateKey::from_bytes(&[1; 32]);
        assert_eq!(
            Identity::new(&chain, &ca_key).unwrap_err(),
            IdentityError::KeyMismatch
        );
        assert_eq!(
            Identity::new(&chain[..1], &node_key).unwrap_err(),
            IdentityError::Chain(ChainError::NotTwoCertificates)
        );
    }

    /// テストのサーバーで、クライアントの証明書を受け付けるか弾くかだけを決める
    #[derive(Debug)]
    struct TestClientVerifier {
        provider: Arc<CryptoProvider>,
        accept: bool,
    }

    impl ClientCertVerifier for TestClientVerifier {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, Error> {
            if self.accept {
                Ok(ClientCertVerified::assertion())
            } else {
                Err(CertificateError::UnknownIssuer.into())
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("TLS 1.2 is not supported".into()))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            super::verify_tls13_signature(&self.provider, message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }
    }

    /// 1回だけ接続を受けるサーバーを立てて、そのアドレスを返す
    fn serve(identity: Identity, accept: bool) -> String {
        let provider = provider();
        let config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(TestClientVerifier { provider, accept }))
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(identity.certified_key)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut connection = ServerConnection::new(Arc::new(config)).unwrap();
            while connection.is_handshaking() {
                if connection.complete_io(&mut socket).is_err() {
                    break;
                }
            }
            // catapult と同じく、自分からは何も送らずに待つ
            thread::sleep(WAIT * 3);
        });
        address
    }

    fn client_identity() -> Identity {
        let (chain, key) = chain(3);
        Identity::new(&chain, &key).unwrap()
    }

    #[test]
    fn inspects_a_server_that_keeps_the_connection() {
        let (chain, key) = chain(1);
        let address = serve(Identity::new(&chain, &key).unwrap(), true);
        let inspection =
            inspect(&address, &client_identity(), Duration::from_secs(5), WAIT).unwrap();
        assert_eq!(inspection.client_certificate, ClientCertificate::Kept);
        let expected: Vec<_> = chain
            .iter()
            .map(|certificate| certificate.to_der().to_vec())
            .collect();
        assert_eq!(inspection.peer_certificates, expected);
    }

    #[test]
    fn inspects_a_server_that_rejects_our_certificate() {
        let (chain, key) = chain(1);
        let address = serve(Identity::new(&chain, &key).unwrap(), false);
        let inspection =
            inspect(&address, &client_identity(), Duration::from_secs(5), WAIT).unwrap();
        assert!(
            matches!(
                inspection.client_certificate,
                ClientCertificate::Rejected(_)
            ),
            "{:?}",
            inspection.client_certificate
        );
        assert_eq!(inspection.peer_certificates.len(), 2);
    }

    /// 1回だけ接続を受け、こちらの証明書を受け付けて、届いたバイト列を相手が閉じるまで読むサーバー
    fn serve_and_read(identity: Identity) -> (String, mpsc::Receiver<Vec<u8>>) {
        let provider = provider();
        let config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(TestClientVerifier {
                provider,
                accept: true,
            }))
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(identity.certified_key)));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut connection = ServerConnection::new(Arc::new(config)).unwrap();
            let mut received = Vec::new();
            let _ = rustls::Stream::new(&mut connection, &mut socket).read_to_end(&mut received);
            sender.send(received).unwrap();
        });
        (address, receiver)
    }

    #[test]
    fn sends_a_packet() {
        let (chain, key) = chain(1);
        let (address, received) = serve_and_read(Identity::new(&chain, &key).unwrap());
        let inspection = send(
            &address,
            &client_identity(),
            9,
            b"body",
            Duration::from_secs(5),
            WAIT,
        )
        .unwrap();
        assert_eq!(inspection.client_certificate, ClientCertificate::Kept);
        assert_eq!(
            received.recv().unwrap(),
            [&12u32.to_le_bytes()[..], &9u32.to_le_bytes(), b"body"].concat()
        );
    }

    #[test]
    fn does_not_send_to_a_server_with_an_invalid_chain() {
        let (chain, key) = chain(1);
        let other = chain_with_other_ca(&chain);
        let (address, received) = serve_and_read(Identity {
            certified_key: Arc::new(CertifiedKey::new(
                ders(&other),
                provider()
                    .key_provider
                    .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        key::private_key_to_der(&key).to_vec(),
                    )))
                    .unwrap(),
            )),
        });
        let error = send(
            &address,
            &client_identity(),
            9,
            b"body",
            Duration::from_secs(5),
            WAIT,
        )
        .unwrap_err();
        assert!(matches!(error, ConnectError::Handshake(_)), "{error:?}");
        assert_eq!(received.recv().unwrap(), b"");
    }
    #[test]
    fn fails_to_connect_to_a_closed_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let error =
            inspect(&address, &client_identity(), Duration::from_secs(5), WAIT).unwrap_err();
        assert!(matches!(error, ConnectError::Connect(_)), "{error:?}");
    }
}
