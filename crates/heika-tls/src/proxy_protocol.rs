//! PROXY protocol のヘッダー。HAProxy や nginx などの中継が、接続の頭に元の送信元を書いて渡してくる。
//!
//! 中継を通すと、受けた側からは相手がみな中継のアドレスに見える。中継が接続の最初にこのヘッダーを送り、受けた側が
//! それを読めば、元の送信元で数えたり締め出したりできる。誰でも送れるので、信じるのは決めた中継から来たときだけにする
//! （[`IpRange`]）。v1 のテキストの形と v2 のバイナリの形を、最初の 12 バイトで
//! 見分けてどちらも読む。
//!
//! 形は <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt> の 2.1 節（v1）と 2.2 節（v2）。

use std::fmt;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// v2 のヘッダーの最初の 12 バイト
pub const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// v1 のヘッダーの頭
const V1_PREFIX: &[u8] = b"PROXY ";

/// v1 のヘッダーの、行末の CRLF を含めた長さの上限
const V1_MAX_LENGTH: usize = 107;

/// 読んだヘッダーが伝えてきたこと
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header {
    /// 中継が自分の用事（死活の確かめなど）でつないできた。送信元は接続そのもののアドレス
    Local,
    /// 中継した接続。`source` が元の送信元、`destination` が元の宛先。UNIX ソケットや未指定のアドレスの族
    /// なら `None` で、送信元は接続そのもののアドレスとして扱う
    Proxy {
        source: Option<SocketAddr>,
        destination: Option<SocketAddr>,
    },
}

impl Header {
    /// 元の送信元。わからなければ、接続そのもののアドレス `connected`
    pub fn source_or(self, connected: SocketAddr) -> SocketAddr {
        match self {
            Self::Proxy {
                source: Some(source),
                ..
            } => source,
            _ => connected,
        }
    }
}

/// ヘッダーを読めなかったわけ
#[derive(Debug)]
pub enum HeaderError {
    Io(io::Error),
    /// v1 の頭でも v2 の印でもない
    Signature,
    /// v1 の行の形が違う
    Line(&'static str),
    /// 版が 2 でない
    Version(u8),
    /// コマンドが LOCAL でも PROXY でもない
    Command(u8),
    /// TCP 以外（UDP など）を中継した
    Transport(u8),
    /// アドレスの族に足りない長さ
    Length {
        family: u8,
        length: u16,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "PROXY protocol のヘッダーを読めません: {error}"),
            Self::Signature => f.write_str("PROXY protocol のヘッダーで始まっていません"),
            Self::Line(reason) => write!(f, "PROXY protocol v1 の行を読めません: {reason}"),
            Self::Version(version) => write!(
                f,
                "PROXY protocol の版 {version} は読めません（バイナリの形は 2 だけ）"
            ),
            Self::Command(command) => {
                write!(f, "PROXY protocol のコマンド {command:#x} は読めません")
            }
            Self::Transport(protocol) => write!(
                f,
                "PROXY protocol で TCP 以外（{protocol:#x}）を中継してきました"
            ),
            Self::Length { family, length } => write!(
                f,
                "PROXY protocol のアドレスの族 {family:#x} に、長さ {length} は足りません"
            ),
        }
    }
}

impl std::error::Error for HeaderError {}

impl From<io::Error> for HeaderError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// `reader` からヘッダーを 1 つ読む。ヘッダーの後ろは読まないので、続けて TLS を始められる。
/// v2 の TLV（ヘッダーの後ろの付け足し）は読み飛ばす
pub fn read_header(reader: &mut impl Read) -> Result<Header, HeaderError> {
    // v1 はいちばん短くても 15 バイト（`PROXY UNKNOWN\r\n`）あるので、12 バイトまでは読みすぎない
    let mut start = [0; 12];
    reader.read_exact(&mut start)?;
    if start == SIGNATURE {
        read_v2(reader)
    } else if start.starts_with(V1_PREFIX) {
        read_v1(reader, &start)
    } else {
        Err(HeaderError::Signature)
    }
}

/// v1 の行の残りを、CRLF まで 1 バイトずつ読む（その先の TLS を読まないように）
fn read_v1(reader: &mut impl Read, start: &[u8]) -> Result<Header, HeaderError> {
    let mut line = start.to_vec();
    while !line.ends_with(b"\r\n") {
        if line.len() >= V1_MAX_LENGTH {
            return Err(HeaderError::Line("107 バイトのうちに行が終わりません"));
        }
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        line.push(byte[0]);
    }
    let text = std::str::from_utf8(&line[..line.len() - 2])
        .ok()
        .filter(|text| !text.contains(['\r', '\n']))
        .ok_or(HeaderError::Line("ASCII の 1 行でない"))?;
    let mut fields = text.split(' ').skip(1);
    let ipv4 = match fields.next() {
        // 中継にも送信元がわからない。後ろは何が来ても見ない
        Some("UNKNOWN") => {
            return Ok(Header::Proxy {
                source: None,
                destination: None,
            });
        }
        Some("TCP4") => true,
        Some("TCP6") => false,
        _ => return Err(HeaderError::Line("TCP4、TCP6、UNKNOWN のどれでもない")),
    };
    let fields: Vec<&str> = fields.collect();
    let [source, destination, source_port, destination_port] = fields[..] else {
        return Err(HeaderError::Line("アドレスとポートが 2 つずつでない"));
    };
    let ip = |text: &str| {
        text.parse::<IpAddr>()
            .ok()
            .filter(|ip| ip.is_ipv4() == ipv4)
            .ok_or(HeaderError::Line("アドレスが読めないか、族が合わない"))
    };
    let port = |text: &str| {
        text.parse::<u16>()
            .ok()
            .filter(|_| text.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or(HeaderError::Line("ポートが読めない"))
    };
    Ok(Header::Proxy {
        source: Some(SocketAddr::new(ip(source)?, port(source_port)?)),
        destination: Some(SocketAddr::new(ip(destination)?, port(destination_port)?)),
    })
}

/// v2 の印の後ろを読む
fn read_v2(reader: &mut impl Read) -> Result<Header, HeaderError> {
    let mut fixed = [0; 4];
    reader.read_exact(&mut fixed)?;
    let (version, command) = (fixed[0] >> 4, fixed[0] & 0x0f);
    if version != 2 {
        return Err(HeaderError::Version(version));
    }
    let (family, protocol) = (fixed[1] >> 4, fixed[1] & 0x0f);
    let length = u16::from_be_bytes([fixed[2], fixed[3]]);
    let mut rest = vec![0; usize::from(length)];
    reader.read_exact(&mut rest)?;
    match command {
        // LOCAL では、アドレスの族も中身も見ない
        0 => return Ok(Header::Local),
        1 => {}
        _ => return Err(HeaderError::Command(command)),
    }
    // 未指定のアドレスの族は、転送の種類も未指定で来る
    if family != 0 && protocol != 1 {
        return Err(HeaderError::Transport(protocol));
    }
    let short = || HeaderError::Length {
        family: fixed[1],
        length,
    };
    let (source, destination) = match family {
        1 => {
            let address: &[u8; 12] = rest
                .get(..12)
                .and_then(|a| a.try_into().ok())
                .ok_or_else(short)?;
            let ip = |at: usize| {
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&address[at..at + 4]).expect("4 bytes"),
                ))
            };
            let port = |at: usize| u16::from_be_bytes([address[at], address[at + 1]]);
            (
                SocketAddr::new(ip(0), port(8)),
                SocketAddr::new(ip(4), port(10)),
            )
        }
        2 => {
            let address: &[u8; 36] = rest
                .get(..36)
                .and_then(|a| a.try_into().ok())
                .ok_or_else(short)?;
            let ip = |at: usize| {
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(&address[at..at + 16]).expect("16 bytes"),
                ))
            };
            let port = |at: usize| u16::from_be_bytes([address[at], address[at + 1]]);
            (
                SocketAddr::new(ip(0), port(32)),
                SocketAddr::new(ip(16), port(34)),
            )
        }
        // 未指定と UNIX ソケットは、IP のアドレスを持たない
        _ => {
            return Ok(Header::Proxy {
                source: None,
                destination: None,
            });
        }
    };
    Ok(Header::Proxy {
        source: Some(source),
        destination: Some(destination),
    })
}

/// アドレスの範囲。`10.0.0.0/8` や `::1/128` のように書き、`/` がなければそのアドレスだけ
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpRange {
    address: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// `ip` がこの範囲にあるか。IPv4 を IPv6 に埋めたアドレス（`::ffff:a.b.c.d`）は IPv4 として比べる
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        match (self.address, ip) {
            (IpAddr::V4(range), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(range) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(range), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(range) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl FromStr for IpRange {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid =
            || format!("アドレスの範囲 {text:?} を読めません（たとえば 10.0.0.0/8、::1）");
        let (address, prefix) = text
            .split_once('/')
            .map_or((text, None), |(a, p)| (a, Some(p)));
        let address: IpAddr = address.parse().map_err(|_| invalid())?;
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => bits,
            Some(prefix) => prefix
                .parse()
                .ok()
                .filter(|&p| p <= bits)
                .ok_or_else(invalid)?,
        };
        Ok(Self { address, prefix })
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let length = u16::try_from(body.len()).unwrap().to_be_bytes();
        [&SIGNATURE[..], &[0x20 | command, family], &length, body].concat()
    }

    #[test]
    fn reads_ipv4_and_leaves_the_rest() {
        let body = [
            192, 0, 2, 1, // 送信元
            198, 51, 100, 7, // 宛先
            0x1e, 0xdc, // 7900
            0x1e, 0xdc, // TLV（読み飛ばす）
            0x04, 0x00, 0x01, 0x00,
        ];
        let mut bytes = header(1, 0x11, &body);
        bytes.extend_from_slice(b"\x16tls");
        let mut reader = &bytes[..];
        let read = read_header(&mut reader).unwrap();
        assert_eq!(
            read,
            Header::Proxy {
                source: Some("192.0.2.1:7900".parse().unwrap()),
                destination: Some("198.51.100.7:7900".parse().unwrap()),
            }
        );
        assert_eq!(reader, b"\x16tls");
    }

    #[test]
    fn reads_ipv6() {
        let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let body = [
            &source.octets()[..],
            &destination.octets(),
            &[0x30, 0x39, 0x1e, 0xdc],
        ]
        .concat();
        let read = read_header(&mut &header(1, 0x21, &body)[..]).unwrap();
        assert_eq!(
            read.source_or("127.0.0.1:1".parse().unwrap()),
            "[2001:db8::1]:12345".parse().unwrap()
        );
    }

    #[test]
    fn local_and_unspecified_keep_the_connection_address() {
        let connected: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let local = read_header(&mut &header(0, 0x00, &[])[..]).unwrap();
        assert_eq!(local, Header::Local);
        assert_eq!(local.source_or(connected), connected);
        let unspecified = read_header(&mut &header(1, 0x00, &[])[..]).unwrap();
        assert_eq!(unspecified.source_or(connected), connected);
    }

    #[test]
    fn rejects_what_it_cannot_read() {
        let tls = [
            0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 3, 3, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(
            read_header(&mut &tls[..]),
            Err(HeaderError::Signature)
        ));
        let mut v1 = header(1, 0x11, &[0; 12]);
        v1[12] = 0x11;
        assert!(matches!(
            read_header(&mut &v1[..]),
            Err(HeaderError::Version(1))
        ));
        assert!(matches!(
            read_header(&mut &header(2, 0x11, &[0; 12])[..]),
            Err(HeaderError::Command(2))
        ));
        assert!(matches!(
            read_header(&mut &header(1, 0x12, &[0; 12])[..]),
            Err(HeaderError::Transport(2))
        ));
        assert!(matches!(
            read_header(&mut &header(1, 0x11, &[0; 8])[..]),
            Err(HeaderError::Length { .. })
        ));
        // 長さのぶん届く前に閉じた
        let mut cut = header(1, 0x11, &[0; 12]);
        cut.truncate(20);
        assert!(matches!(
            read_header(&mut &cut[..]),
            Err(HeaderError::Io(_))
        ));
    }

    #[test]
    fn reads_v1_and_leaves_the_rest() {
        let mut reader = &b"PROXY TCP4 192.0.2.1 198.51.100.7 40000 7900\r\n\x16tls"[..];
        assert_eq!(
            read_header(&mut reader).unwrap(),
            Header::Proxy {
                source: Some("192.0.2.1:40000".parse().unwrap()),
                destination: Some("198.51.100.7:7900".parse().unwrap()),
            }
        );
        assert_eq!(reader, b"\x16tls");
        let six = read_header(&mut &b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 7900\r\n"[..]);
        assert_eq!(
            six.unwrap().source_or("127.0.0.1:1".parse().unwrap()),
            "[2001:db8::1]:12345".parse().unwrap()
        );
        let connected: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        let unknown = read_header(&mut &b"PROXY UNKNOWN ffff::1 whatever\r\n"[..]).unwrap();
        assert_eq!(unknown.source_or(connected), connected);
    }

    #[test]
    fn rejects_malformed_v1_lines() {
        for line in [
            &b"PROXY TCP4 192.0.2.1 198.51.100.7 40000\r\n"[..],
            b"PROXY TCP4 2001:db8::1 198.51.100.7 40000 7900\r\n",
            b"PROXY TCP6 192.0.2.1 198.51.100.7 40000 7900\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 +4000 7900\r\n",
            b"PROXY TCP4 192.0.2.1 198.51.100.7 70000 7900\r\n",
            b"PROXY UDP4 192.0.2.1 198.51.100.7 40000 7900\r\n",
            b"PROXY TCP4 192.0.2.1\r\n198.51.100.7 40000 7900\r\n",
        ] {
            assert!(
                matches!(read_header(&mut &line[..]), Err(HeaderError::Line(_))),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        // 行が終わらないまま長すぎる
        let long = [&b"PROXY "[..], &[b'x'; 200]].concat();
        assert!(matches!(
            read_header(&mut &long[..]),
            Err(HeaderError::Line(_))
        ));
    }

    #[test]
    fn ranges() {
        let range: IpRange = "10.0.0.0/8".parse().unwrap();
        assert!(range.contains("10.1.2.3".parse().unwrap()));
        assert!(range.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!range.contains("11.0.0.1".parse().unwrap()));
        let one: IpRange = "127.0.0.1".parse().unwrap();
        assert!(one.contains("127.0.0.1".parse().unwrap()));
        assert!(!one.contains("127.0.0.2".parse().unwrap()));
        let v6: IpRange = "fd00::/8".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.0.0.1".parse().unwrap()));
        let all: IpRange = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("203.0.113.9".parse().unwrap()));
        assert_eq!(one.to_string(), "127.0.0.1/32");
        assert!("10.0.0.0/33".parse::<IpRange>().is_err());
        assert!("example".parse::<IpRange>().is_err());
    }
}
