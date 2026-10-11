//! X.509 の証明書。catapult のノードが TLS でつなぐときに使う、Ed25519 の鍵の証明書だけを扱う。
//!
//! 発行するのは v1（拡張なし）と v3（shoestring が OpenSSL 3 で作るのと同じ拡張）。読むほうも v1 と v3 を受け付ける。
//! catapult は DN を見ないので、subject と issuer には DN を自由に書ける。発行するときは RFC 4514 の形でも OpenSSL の形でも受け付ける。

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, mem};

use der::asn1::{AnyRef, BitString, ObjectIdentifier, OctetString};
use der::oid::AssociatedOid;
use der::pem::LineEnding;
use der::{Decode, Encode, EncodePem, Sequence};
use heika_core::key::{PrivateKey, PublicKey};
use heika_core::signature::Signature;
use sha1::{Digest, Sha1};
use x509_cert::certificate::Version as RawVersion;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

use crate::key;

/// Ed25519 の OID（RFC 8410）
const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// v1 の TBSCertificate。version は既定値の v1 なので書かない。
#[derive(Sequence)]
struct TbsCertificateV1 {
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
}

/// v3 の TBSCertificate。
#[derive(Sequence)]
struct TbsCertificateV3 {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    version: RawVersion,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT")]
    extensions: Vec<Extension>,
}

/// 署名した証明書。TBSCertificate は署名したバイト列をそのまま入れる。
#[derive(Sequence)]
struct SignedCertificate<'a> {
    tbs_certificate: AnyRef<'a>,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

/// 発行する証明書のバージョン。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// 拡張なし
    V1,
    /// shoestring が OpenSSL 3 で作るのと同じ拡張を付ける。
    /// CA には basicConstraints（critical、CA:TRUE）と SKI と AKI、ノードには SKI と AKI。
    /// 鍵の識別子は OpenSSL と同じく公開鍵の SHA-1
    V3,
}

/// 発行する証明書の中身。
#[derive(Clone, Debug)]
pub struct Template<'a> {
    /// RFC 4514 の DN（`CN=node,O=example`）か、OpenSSL の `-subj` の形（`/O=example/CN=node`）
    pub subject: &'a str,
    /// 秒より細かい部分は切り捨てる
    pub not_before: SystemTime,
    /// 秒より細かい部分は切り捨てる
    pub not_after: SystemTime,
    /// 符号なしの大きな整数として読む。20バイトまで
    pub serial_number: &'a [u8],
    pub version: Version,
}

/// Ed25519 の鍵の X.509 の証明書。
#[derive(Clone)]
pub struct Certificate {
    inner: x509_cert::Certificate,
    der: Vec<u8>,
    public_key: PublicKey,
}

impl Certificate {
    /// 自己署名の証明書を発行する。ノードの CA の証明書になる。
    pub fn self_signed(key: &PrivateKey, template: &Template) -> Result<Self, IssueError> {
        let subject = parse_name(template.subject)?;
        let public_key = PublicKey::from_private_key(key);
        let issuer = Issuer {
            name: subject.clone(),
            key,
            key_identifier: key_identifier(&public_key).to_vec(),
        };
        issue(&issuer, subject, &public_key, true, template)
    }

    /// `ca` の鍵で `public_key` に証明書を発行する。issuer には `ca` の subject を使う。
    ///
    /// `ca_key` が `ca` の公開鍵と組でなければ発行しない。
    pub fn issue(
        ca: &Certificate,
        ca_key: &PrivateKey,
        public_key: &PublicKey,
        template: &Template,
    ) -> Result<Self, IssueError> {
        if PublicKey::from_private_key(ca_key) != ca.public_key {
            return Err(IssueError::KeyMismatch);
        }
        // OpenSSL と同じく、CA の証明書に SKI があればそれを、なければ公開鍵の SHA-1 を使う
        let key_identifier = ca
            .inner
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .map_or_else(
                || self::key_identifier(&ca.public_key).to_vec(),
                |(_, identifier)| identifier.0.as_bytes().to_vec(),
            );
        let issuer = Issuer {
            name: ca.inner.tbs_certificate().subject().clone(),
            key: ca_key,
            key_identifier,
        };
        issue(
            &issuer,
            parse_name(template.subject)?,
            public_key,
            false,
            template,
        )
    }

    /// DER から読む。DER として正規でないもの、Ed25519 の鍵と署名でないものは受け付けない。
    pub fn from_der(der: &[u8]) -> Result<Self, ParseCertificateError> {
        let inner =
            x509_cert::Certificate::from_der(der).map_err(|_| ParseCertificateError::InvalidDer)?;
        // 署名の対象は TBSCertificate のバイト列そのものなので、読み直して同じにならないものは扱わない
        if inner.to_der().ok().as_deref() != Some(der) {
            return Err(ParseCertificateError::InvalidDer);
        }
        let tbs = inner.tbs_certificate();
        let ed25519 = AlgorithmIdentifierOwned {
            oid: ED25519,
            parameters: None,
        };
        if *inner.signature_algorithm() != ed25519 || *tbs.signature() != ed25519 {
            return Err(ParseCertificateError::NotEd25519);
        }
        let spki = tbs
            .subject_public_key_info()
            .to_der()
            .map_err(|_| ParseCertificateError::InvalidDer)?;
        let public_key =
            key::public_key_from_der(&spki).map_err(|_| ParseCertificateError::NotEd25519)?;
        Ok(Self {
            inner,
            der: der.to_vec(),
            public_key,
        })
    }

    /// `-----BEGIN CERTIFICATE-----` の PEM から読む。
    pub fn from_pem(pem: &str) -> Result<Self, ParseCertificateError> {
        // x509-cert で読んでから DER に戻すと正規でない DER も直ってしまうので、PEM の中身をそのまま渡す
        let (label, der) = der::pem::decode_vec(pem.trim().as_bytes())
            .map_err(|_| ParseCertificateError::InvalidPem)?;
        if label != "CERTIFICATE" {
            return Err(ParseCertificateError::InvalidPem);
        }
        Self::from_der(&der)
    }

    /// PEM の証明書をつないだもの（`node.full.crt.pem` など）を、書かれた順に読む。
    pub fn from_pem_chain(pem: &str) -> Result<Vec<Self>, ParseCertificateError> {
        const END: &str = "-----END CERTIFICATE-----";
        let mut certificates = Vec::new();
        let mut rest = pem.trim();
        while !rest.is_empty() {
            let end = rest.find(END).ok_or(ParseCertificateError::InvalidPem)? + END.len();
            certificates.push(Self::from_pem(&rest[..end])?);
            rest = rest[end..].trim_start();
        }
        if certificates.is_empty() {
            return Err(ParseCertificateError::InvalidPem);
        }
        Ok(certificates)
    }

    pub fn to_der(&self) -> &[u8] {
        &self.der
    }

    /// PEM にする。末尾に改行は付けない。
    pub fn to_pem(&self) -> String {
        let pem = self
            .inner
            .to_pem(LineEnding::LF)
            .expect("a parsed certificate encodes");
        pem.trim_end().to_owned()
    }

    /// 1、2、3 のどれか。
    pub fn version(&self) -> u8 {
        match self.inner.tbs_certificate().version() {
            RawVersion::V1 => 1,
            RawVersion::V2 => 2,
            RawVersion::V3 => 3,
        }
    }

    /// 先頭の0を除いた、符号なしの大きな整数のバイト列。
    pub fn serial_number(&self) -> &[u8] {
        self.inner.tbs_certificate().serial_number().as_bytes()
    }

    /// RFC 4514 の DN。
    pub fn issuer(&self) -> String {
        self.inner.tbs_certificate().issuer().to_string()
    }

    /// RFC 4514 の DN。
    pub fn subject(&self) -> String {
        self.inner.tbs_certificate().subject().to_string()
    }

    pub fn not_before(&self) -> SystemTime {
        self.inner
            .tbs_certificate()
            .validity()
            .not_before
            .to_system_time()
    }

    pub fn not_after(&self) -> SystemTime {
        self.inner
            .tbs_certificate()
            .validity()
            .not_after
            .to_system_time()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// `issuer` の鍵で署名されているか。
    ///
    /// 判定には catapult の署名の検証を使う。catapult がつなぐときの証明書の署名は
    /// OpenSSL が確かめるので、境界のケースでは判定が少し違いうる。
    pub fn is_signed_by(&self, issuer: &PublicKey) -> bool {
        let Ok(tbs) = self.inner.tbs_certificate().to_der() else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(self.inner.signature().raw_bytes()) else {
            return false;
        };
        issuer.verify(&[&tbs], &Signature(signature))
    }

    /// issuer と subject が同じで、自分の鍵で署名されているか。
    pub fn is_self_signed(&self) -> bool {
        self.issuer() == self.subject() && self.is_signed_by(&self.public_key)
    }
}

/// catapult がつなぐときに確かめるチェーンの条件（`CatapultCertificateProcessor`）。
///
/// ノード、CA の順の2枚で、CA が自己署名、ノードが CA の鍵で署名されていること。
/// 有効期間は catapult では OpenSSL が確かめるので、ここでは見ない。
pub fn check_catapult_chain(chain: &[Certificate]) -> Result<(), ChainError> {
    let [node, ca] = chain else {
        return Err(ChainError::NotTwoCertificates);
    };
    if !ca.is_self_signed() {
        return Err(ChainError::RootNotSelfSigned);
    }
    if node.issuer() != ca.subject() || !node.is_signed_by(ca.public_key()) {
        return Err(ChainError::NotSignedByRoot);
    }
    Ok(())
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("version", &self.version())
            .field("subject", &self.subject())
            .field("issuer", &self.issuer())
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// 証明書を発行する側。
struct Issuer<'a> {
    name: Name,
    key: &'a PrivateKey,
    /// v3 の AKI に入れる鍵の識別子
    key_identifier: Vec<u8>,
}

fn issue(
    issuer: &Issuer,
    subject: Name,
    public_key: &PublicKey,
    ca: bool,
    template: &Template,
) -> Result<Certificate, IssueError> {
    let not_before = to_time(template.not_before)?;
    let not_after = to_time(template.not_after)?;
    if not_before.to_unix_duration() >= not_after.to_unix_duration() {
        return Err(IssueError::InvalidValidity);
    }
    let serial_number =
        SerialNumber::new(template.serial_number).map_err(|_| IssueError::InvalidSerialNumber)?;
    let ed25519 = AlgorithmIdentifierOwned {
        oid: ED25519,
        parameters: None,
    };
    let subject_public_key_info =
        SubjectPublicKeyInfoOwned::from_der(&key::public_key_to_der(public_key))
            .expect("the public key DER is valid");
    let validity = Validity::new(not_before, not_after);
    let tbs = match template.version {
        Version::V1 => TbsCertificateV1 {
            serial_number,
            signature: ed25519.clone(),
            issuer: issuer.name.clone(),
            validity,
            subject,
            subject_public_key_info,
        }
        .to_der(),
        Version::V3 => TbsCertificateV3 {
            version: RawVersion::V3,
            serial_number,
            signature: ed25519.clone(),
            issuer: issuer.name.clone(),
            validity,
            subject,
            subject_public_key_info,
            extensions: extensions(public_key, &issuer.key_identifier, ca),
        }
        .to_der(),
    }
    .expect("a certificate encodes");
    let signature = issuer.key.sign(&[&tbs]);
    let certificate = SignedCertificate {
        tbs_certificate: AnyRef::from_der(&tbs).expect("the TBSCertificate is DER"),
        signature_algorithm: ed25519,
        signature: BitString::from_bytes(&signature.0).expect("64 bytes fit in a bit string"),
    };
    let der = certificate.to_der().expect("a certificate encodes");
    Ok(Certificate::from_der(&der).expect("an issued certificate parses"))
}

/// shoestring が OpenSSL 3 で作るのと同じ並びの拡張。
fn extensions(public_key: &PublicKey, issuer_key_identifier: &[u8], ca: bool) -> Vec<Extension> {
    let mut extensions = Vec::new();
    if ca {
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        extensions.push(extension(&constraints, true));
    }
    let subject_key_identifier = SubjectKeyIdentifier(
        OctetString::new(key_identifier(public_key)).expect("20 bytes fit in an octet string"),
    );
    extensions.push(extension(&subject_key_identifier, false));
    let authority_key_identifier = AuthorityKeyIdentifier {
        key_identifier: Some(
            OctetString::new(issuer_key_identifier).expect("a key identifier fits"),
        ),
        ..Default::default()
    };
    extensions.push(extension(&authority_key_identifier, false));
    extensions
}

fn extension<T: AssociatedOid + Encode>(value: &T, critical: bool) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().expect("an extension encodes"))
            .expect("an extension fits in an octet string"),
    }
}

/// OpenSSL の `subjectKeyIdentifier = hash` と同じく、公開鍵の BIT STRING の中身の SHA-1。
fn key_identifier(public_key: &PublicKey) -> [u8; 20] {
    Sha1::digest(public_key.0).into()
}

/// RFC 4514 の DN を読む。`/` で始まっていれば OpenSSL の `-subj` の形として読む。
fn parse_name(text: &str) -> Result<Name, IssueError> {
    let rfc4514 = match text.strip_prefix('/') {
        Some(openssl) => openssl_to_rfc4514(openssl).ok_or(IssueError::InvalidName)?,
        None => text.to_owned(),
    };
    rfc4514.parse().map_err(|_| IssueError::InvalidName)
}

/// OpenSSL の `-subj` の形（先頭の `/` を除いた `O=example/CN=node`）を、RFC 4514 の形（`CN=node,O=example`）に直す。
///
/// OpenSSL と同じく、`/` で RDN を、`+` で RDN の中の属性を区切り、`\` の次の文字はそのまま値に入れる。
/// OpenSSL の形は DER と同じく上位の RDN から書き、RFC 4514 の形は逆に書く。
/// OpenSSL は値が空の属性を飛ばすが、ここでは読めないものとする。
fn openssl_to_rfc4514(text: &str) -> Option<String> {
    let mut rdns = Vec::new();
    let mut attributes = Vec::new();
    let mut attribute_type = None;
    let mut field = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => field.push(chars.next()?),
            '=' if attribute_type.is_none() => attribute_type = Some(mem::take(&mut field)),
            '+' | '/' => {
                attributes.push((attribute_type.take()?, mem::take(&mut field)));
                if c == '/' {
                    rdns.push(mem::take(&mut attributes));
                }
            }
            _ => field.push(c),
        }
    }
    attributes.push((attribute_type.take()?, field));
    rdns.push(attributes);
    let mut rfc4514 = Vec::new();
    for rdn in rdns.iter().rev() {
        let mut parts = Vec::new();
        for (attribute_type, value) in rdn {
            if attribute_type.is_empty() || value.is_empty() {
                return None;
            }
            parts.push(format!("{attribute_type}={}", escape_rfc4514(value)));
        }
        rfc4514.push(parts.join("+"));
    }
    Some(rfc4514.join(","))
}

/// RFC 4514 の 2.4 節のとおりに値をエスケープする。
fn escape_rfc4514(value: &str) -> String {
    let mut escaped = String::new();
    let last = value.chars().count() - 1;
    for (index, c) in value.chars().enumerate() {
        match c {
            '#' if index == 0 => escaped.push_str("\\#"),
            ' ' if index == 0 || index == last => escaped.push_str("\\ "),
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                escaped.push('\\');
                escaped.push(c);
            }
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// 秒より細かい部分を切り捨てて、2049年までは UTCTime、それより後は GeneralizedTime にする。
fn to_time(time: SystemTime) -> Result<Time, IssueError> {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IssueError::InvalidTime)?
        .as_secs();
    Time::try_from(UNIX_EPOCH + Duration::from_secs(seconds)).map_err(|_| IssueError::InvalidTime)
}

/// 証明書を発行できなかった理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// subject が RFC 4514 の DN としても OpenSSL の形の DN としても読めない
    InvalidName,
    /// 1970年より前か、9999年より後
    InvalidTime,
    /// not_before が not_after より前になっていない
    InvalidValidity,
    /// シリアル番号が20バイトを超える
    InvalidSerialNumber,
    /// 発行に使う秘密鍵が CA の証明書の公開鍵と組でない
    KeyMismatch,
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidName => {
                "subject が DN として読めません（RFC 4514 の CN=node,O=example か、OpenSSL の /O=example/CN=node の形で書いてください）"
            }
            Self::InvalidTime => "有効期間は1970年から9999年までにしてください",
            Self::InvalidValidity => "有効期間の始まりが終わりより前になっていません",
            Self::InvalidSerialNumber => "シリアル番号は20バイトまでです",
            Self::KeyMismatch => "秘密鍵が CA の証明書の公開鍵と組になっていません",
        })
    }
}

impl std::error::Error for IssueError {}

/// 証明書が読めなかった理由。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseCertificateError {
    /// `-----BEGIN CERTIFICATE-----` の PEM として読めない
    InvalidPem,
    /// X.509 の証明書の DER として読めない
    InvalidDer,
    /// 鍵か署名が Ed25519 ではない
    NotEd25519,
}

impl fmt::Display for ParseCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPem => "-----BEGIN CERTIFICATE----- の PEM として読めません",
            Self::InvalidDer => "X.509 の証明書の DER として読めません",
            Self::NotEd25519 => "Ed25519 の鍵と署名の証明書ではありません",
        })
    }
}

impl std::error::Error for ParseCertificateError {}

/// チェーンが catapult の条件を満たさない理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// 2枚ではない
    NotTwoCertificates,
    /// 2枚目が自己署名ではない
    RootNotSelfSigned,
    /// 1枚目が2枚目の鍵で署名されていない
    NotSignedByRoot,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotTwoCertificates => "2枚のチェーンではない",
            Self::RootNotSelfSigned => "2枚目が自己署名ではない",
            Self::NotSignedByRoot => "1枚目が2枚目の鍵で署名されていない",
        })
    }
}

impl std::error::Error for ChainError {}

#[cfg(test)]
mod tests {
    use super::*;

    // OpenSSL 3.5 で shoestring と同じ拡張を付けて作った v3 の CA とノードの証明書。
    //   openssl req -config ca.cnf -key ca.key -new -x509 -days 7300 -set_serial 1 -out ca.crt
    //   openssl x509 -req -in node.csr -CA ca.crt -CAkey ca.key -set_serial 2 -days 375 -out node.crt
    const OPENSSL_V3_CA: &str = include_str!("../testdata/openssl-v3-ca.pem");
    const OPENSSL_V3_NODE: &str = include_str!("../testdata/openssl-v3-node.pem");
    // OpenSSL 3.5 で作った P-256 の自己署名の証明書
    const OPENSSL_P256: &str = include_str!("../testdata/openssl-p256.pem");

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn template(subject: &str) -> Template<'_> {
        Template {
            subject,
            // 2026-01-01T00:00:00Z から 2027-01-01T00:00:00Z
            not_before: at(1_767_225_600),
            not_after: at(1_798_761_600),
            serial_number: &[0x01, 0x23],
            version: Version::V1,
        }
    }

    fn v3(subject: &str) -> Template<'_> {
        Template {
            version: Version::V3,
            ..template(subject)
        }
    }

    fn ca_key() -> PrivateKey {
        PrivateKey::from_bytes(&[1; 32])
    }

    fn node_key() -> PublicKey {
        PublicKey::from_private_key(&PrivateKey::from_bytes(&[2; 32]))
    }

    /// 拡張の OID と critical の並び
    fn extension_kinds(certificate: &Certificate) -> Vec<(ObjectIdentifier, bool)> {
        certificate
            .inner
            .tbs_certificate()
            .extensions()
            .into_iter()
            .flatten()
            .map(|extension| (extension.extn_id, extension.critical))
            .collect()
    }

    fn subject_key_identifier(certificate: &Certificate) -> Vec<u8> {
        let (_, identifier) = certificate
            .inner
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .unwrap()
            .unwrap();
        identifier.0.as_bytes().to_vec()
    }

    fn authority_key_identifier(certificate: &Certificate) -> Vec<u8> {
        let (_, identifier) = certificate
            .inner
            .tbs_certificate()
            .get_extension::<AuthorityKeyIdentifier>()
            .unwrap()
            .unwrap();
        identifier.key_identifier.unwrap().as_bytes().to_vec()
    }

    #[test]
    fn issues_v3_certificates_with_the_same_extensions_as_openssl() {
        let ca = Certificate::self_signed(&ca_key(), &v3("CN=CA heika")).unwrap();
        let node = Certificate::issue(&ca, &ca_key(), &node_key(), &v3("CN=node")).unwrap();
        assert_eq!((ca.version(), node.version()), (3, 3));
        let openssl_ca = Certificate::from_pem(OPENSSL_V3_CA).unwrap();
        let openssl_node = Certificate::from_pem(OPENSSL_V3_NODE).unwrap();
        assert_eq!(extension_kinds(&ca), extension_kinds(&openssl_ca));
        assert_eq!(extension_kinds(&node), extension_kinds(&openssl_node));
        let (critical, constraints) = ca
            .inner
            .tbs_certificate()
            .get_extension::<BasicConstraints>()
            .unwrap()
            .unwrap();
        assert!(critical && constraints.ca);
        assert!(ca.is_signed_by(ca.public_key()));
        assert!(node.is_signed_by(ca.public_key()));
    }

    #[test]
    fn uses_the_sha1_of_the_public_key_as_the_key_identifier_like_openssl() {
        let openssl_ca = Certificate::from_pem(OPENSSL_V3_CA).unwrap();
        let openssl_node = Certificate::from_pem(OPENSSL_V3_NODE).unwrap();
        assert_eq!(
            subject_key_identifier(&openssl_ca),
            key_identifier(openssl_ca.public_key())
        );
        assert_eq!(
            authority_key_identifier(&openssl_node),
            subject_key_identifier(&openssl_ca)
        );
        let ca = Certificate::self_signed(&ca_key(), &v3("CN=CA heika")).unwrap();
        let node = Certificate::issue(&ca, &ca_key(), &node_key(), &v3("CN=node")).unwrap();
        assert_eq!(subject_key_identifier(&ca), key_identifier(ca.public_key()));
        assert_eq!(authority_key_identifier(&ca), subject_key_identifier(&ca));
        assert_eq!(subject_key_identifier(&node), key_identifier(&node_key()));
        assert_eq!(authority_key_identifier(&node), subject_key_identifier(&ca));
    }

    #[test]
    fn issues_a_v3_node_certificate_from_a_v1_ca() {
        // v1 の CA には SKI がないので、AKI には CA の公開鍵の SHA-1 を入れる
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA heika")).unwrap();
        let node = Certificate::issue(&ca, &ca_key(), &node_key(), &v3("CN=node")).unwrap();
        assert_eq!(
            authority_key_identifier(&node),
            key_identifier(ca.public_key())
        );
        assert_eq!(check_catapult_chain(&[node, ca]), Ok(()));
    }

    #[test]
    fn issues_a_self_signed_v1_certificate() {
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA heika")).unwrap();
        assert_eq!(ca.version(), 1);
        assert_eq!(ca.subject(), "CN=CA heika");
        assert_eq!(ca.issuer(), "CN=CA heika");
        assert_eq!(ca.serial_number(), [0x01, 0x23]);
        assert_eq!(ca.not_before(), at(1_767_225_600));
        assert_eq!(ca.not_after(), at(1_798_761_600));
        assert_eq!(*ca.public_key(), PublicKey::from_private_key(&ca_key()));
        assert!(ca.is_signed_by(ca.public_key()));
    }

    #[test]
    fn issues_a_node_certificate_signed_by_the_ca() {
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA heika")).unwrap();
        let node = Certificate::issue(&ca, &ca_key(), &node_key(), &template("CN=node")).unwrap();
        assert_eq!(node.version(), 1);
        assert_eq!(node.subject(), "CN=node");
        assert_eq!(node.issuer(), "CN=CA heika");
        assert_eq!(*node.public_key(), node_key());
        assert!(node.is_signed_by(ca.public_key()));
        assert!(!node.is_signed_by(&node_key()));
    }

    #[test]
    fn round_trips_through_pem_and_der() {
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA heika")).unwrap();
        let pem = ca.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----"));
        assert_eq!(Certificate::from_pem(&pem).unwrap().to_der(), ca.to_der());
        assert_eq!(Certificate::from_der(ca.to_der()).unwrap().to_pem(), pem);
    }

    #[test]
    fn keeps_a_distinguished_name_with_several_attributes() {
        let ca =
            Certificate::self_signed(&ca_key(), &template("CN=CA heika,O=heika,C=JP")).unwrap();
        assert_eq!(ca.subject(), "CN=CA heika,O=heika,C=JP");
    }

    #[test]
    fn uses_generalized_time_after_2049() {
        let mut template = template("CN=CA heika");
        // 2050-01-01T00:00:00Z
        template.not_after = at(2_524_608_000);
        let ca = Certificate::self_signed(&ca_key(), &template).unwrap();
        assert_eq!(ca.not_after(), at(2_524_608_000));
    }

    #[test]
    fn truncates_sub_seconds() {
        let mut template = template("CN=CA heika");
        template.not_before += Duration::from_millis(999);
        let ca = Certificate::self_signed(&ca_key(), &template).unwrap();
        assert_eq!(ca.not_before(), at(1_767_225_600));
    }

    #[test]
    fn refuses_to_issue_with_a_key_other_than_the_ca() {
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA heika")).unwrap();
        let other = PrivateKey::from_bytes(&[3; 32]);
        assert_eq!(
            Certificate::issue(&ca, &other, &node_key(), &template("CN=node")).unwrap_err(),
            IssueError::KeyMismatch
        );
    }

    #[test]
    fn refuses_an_empty_or_reversed_validity() {
        let mut template = template("CN=CA heika");
        template.not_after = template.not_before;
        assert_eq!(
            Certificate::self_signed(&ca_key(), &template).unwrap_err(),
            IssueError::InvalidValidity
        );
    }

    /// subject を `text` にして発行した CA の証明書の、subject の DER
    fn subject_der(text: &str) -> Vec<u8> {
        let ca = Certificate::self_signed(&ca_key(), &template(text)).unwrap();
        ca.inner.tbs_certificate().subject().to_der().unwrap()
    }

    #[test]
    fn reads_an_openssl_style_name_in_reverse_order() {
        let ca = Certificate::self_signed(&ca_key(), &template("/C=JP/O=heika/CN=node")).unwrap();
        assert_eq!(ca.subject(), "CN=node,O=heika,C=JP");
        assert_eq!(
            subject_der("/C=JP/O=heika/CN=node"),
            subject_der("CN=node,O=heika,C=JP")
        );
    }

    #[test]
    fn reads_escapes_and_special_characters_in_an_openssl_style_name() {
        // OpenSSL では `\` の次の文字はそのまま値になる
        assert_eq!(subject_der(r"/CN=a\/b"), subject_der("CN=a/b"));
        assert_eq!(subject_der(r"/CN=a\+b"), subject_der(r"CN=a\+b"));
        // RFC 4514 でエスケープが要る文字も、OpenSSL の形ではそのまま書ける
        assert_eq!(subject_der("/CN=a,b;c"), subject_der(r"CN=a\,b\;c"));
        assert_eq!(subject_der("/CN=#a b "), subject_der(r"CN=\#a b\ "));
        assert_eq!(subject_der("/CN=a=b"), subject_der("CN=a=b"));
    }

    #[test]
    fn reads_a_multi_valued_rdn_in_an_openssl_style_name() {
        assert_eq!(
            subject_der("/O=heika+OU=nodes/CN=node"),
            subject_der("CN=node,O=heika+OU=nodes")
        );
    }

    #[test]
    fn refuses_a_malformed_openssl_style_name() {
        for text in [
            "/",
            "/CN",
            "/CN=",
            "/=node",
            "/CN=node/",
            r"/CN=node\",
            "/CN=a+O",
        ] {
            assert_eq!(
                Certificate::self_signed(&ca_key(), &template(text)).unwrap_err(),
                IssueError::InvalidName,
                "{text}"
            );
        }
    }

    #[test]
    fn refuses_an_invalid_name_and_serial_number() {
        assert_eq!(
            Certificate::self_signed(&ca_key(), &template("not a DN")).unwrap_err(),
            IssueError::InvalidName
        );
        let mut template = template("CN=CA heika");
        template.serial_number = &[0xFF; 21];
        assert_eq!(
            Certificate::self_signed(&ca_key(), &template).unwrap_err(),
            IssueError::InvalidSerialNumber
        );
    }

    #[test]
    fn reads_v3_certificates_made_by_openssl() {
        let ca = Certificate::from_pem(OPENSSL_V3_CA).unwrap();
        let node = Certificate::from_pem(OPENSSL_V3_NODE).unwrap();
        assert_eq!(ca.version(), 3);
        assert_eq!(node.version(), 3);
        assert_eq!(ca.subject(), "CN=CA fixture");
        assert_eq!(node.subject(), "CN=node fixture");
        assert_eq!(node.issuer(), "CN=CA fixture");
        assert_eq!(node.serial_number(), [0x02]);
        assert_eq!(
            ca.public_key().to_string(),
            "9C2AA8EDFAB3C3A3958C6C4D2C5E254BCF9D6E9BE3A1C6FE4144784C7C6CA16A"
        );
        assert!(ca.is_signed_by(ca.public_key()));
        assert!(node.is_signed_by(ca.public_key()));
        assert_eq!(
            Certificate::from_der(node.to_der()).unwrap().to_pem(),
            OPENSSL_V3_NODE.trim()
        );
    }

    #[test]
    fn rejects_a_certificate_of_another_algorithm() {
        assert_eq!(
            Certificate::from_pem(OPENSSL_P256).unwrap_err(),
            ParseCertificateError::NotEd25519
        );
    }

    #[test]
    fn checks_the_catapult_chain() {
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA heika")).unwrap();
        let node = Certificate::issue(&ca, &ca_key(), &node_key(), &template("CN=node")).unwrap();
        assert!(ca.is_self_signed());
        assert!(!node.is_self_signed());
        assert_eq!(check_catapult_chain(&[node.clone(), ca.clone()]), Ok(()));
        assert_eq!(
            check_catapult_chain(std::slice::from_ref(&node)),
            Err(ChainError::NotTwoCertificates)
        );
        assert_eq!(
            check_catapult_chain(&[node.clone(), ca.clone(), ca.clone()]),
            Err(ChainError::NotTwoCertificates)
        );
        assert_eq!(
            check_catapult_chain(&[ca.clone(), node.clone()]),
            Err(ChainError::RootNotSelfSigned)
        );
        // 同じ DN で別の鍵の CA
        let other =
            Certificate::self_signed(&PrivateKey::from_bytes(&[3; 32]), &template("CN=CA heika"))
                .unwrap();
        assert_eq!(
            check_catapult_chain(&[node, other]),
            Err(ChainError::NotSignedByRoot)
        );
    }

    #[test]
    fn reads_a_chain_in_order() {
        let chain = format!("{OPENSSL_V3_NODE}{OPENSSL_V3_CA}");
        let certificates = Certificate::from_pem_chain(&chain).unwrap();
        let subjects: Vec<_> = certificates.iter().map(Certificate::subject).collect();
        assert_eq!(subjects, ["CN=node fixture", "CN=CA fixture"]);
        assert_eq!(Certificate::from_pem_chain(OPENSSL_V3_CA).unwrap().len(), 1);
    }

    #[test]
    fn rejects_a_chain_with_trailing_garbage() {
        let chain = format!("{OPENSSL_V3_NODE}garbage");
        assert_eq!(
            Certificate::from_pem_chain(&chain).unwrap_err(),
            ParseCertificateError::InvalidPem
        );
        assert_eq!(
            Certificate::from_pem_chain(" \n").unwrap_err(),
            ParseCertificateError::InvalidPem
        );
    }

    #[test]
    fn rejects_a_pem_with_another_label() {
        let key = key::public_key_to_pem(&node_key());
        assert_eq!(
            Certificate::from_pem(&key).unwrap_err(),
            ParseCertificateError::InvalidPem
        );
    }

    #[test]
    fn rejects_garbage() {
        // PEM としては読めて、中身が証明書になっていない
        assert_eq!(
            Certificate::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
                .unwrap_err(),
            ParseCertificateError::InvalidDer
        );
        assert_eq!(
            Certificate::from_pem("not a pem").unwrap_err(),
            ParseCertificateError::InvalidPem
        );
        assert_eq!(
            Certificate::from_der(&[0x30, 0x00]).unwrap_err(),
            ParseCertificateError::InvalidDer
        );
    }
}
