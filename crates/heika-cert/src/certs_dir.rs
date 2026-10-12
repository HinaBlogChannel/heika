//! shoestring と symbol-bootstrap が作る、ノードの証明書のフォルダー。
//!
//! どちらも `node.crt.pem`、`node.full.crt.pem`（ノード、CA の順につないだもの）、`node.key.pem`、
//! `ca.pubkey.pem` と CA の証明書を置く。CA の証明書のファイル名だけが違う。

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use der::DateTime;

use crate::certificate::{self, Certificate, ChainError, ParseCertificateError};

const NODE_CERTIFICATE: &str = "node.crt.pem";
const NODE_FULL_CERTIFICATE: &str = "node.full.crt.pem";

/// どのツールが作ったフォルダーか。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    #[cfg(feature = "shoestring-compat")]
    Shoestring,
    #[cfg(feature = "bootstrap-compat")]
    Bootstrap,
}

impl Layout {
    fn ca_certificate(self) -> &'static str {
        match self {
            #[cfg(feature = "shoestring-compat")]
            Self::Shoestring => "ca.crt.pem",
            #[cfg(feature = "bootstrap-compat")]
            Self::Bootstrap => "ca.cert.pem",
        }
    }
}

/// ノードの証明書のフォルダー。
#[derive(Clone, Debug)]
pub struct CertsDir {
    path: PathBuf,
    layout: Layout,
}

impl CertsDir {
    pub fn new(path: impl Into<PathBuf>, layout: Layout) -> Self {
        Self {
            path: path.into(),
            layout,
        }
    }

    pub fn ca_certificate(&self) -> Result<Certificate, CertsDirError> {
        self.read_certificate(self.layout.ca_certificate())
    }

    pub fn node_certificate(&self) -> Result<Certificate, CertsDirError> {
        self.read_certificate(NODE_CERTIFICATE)
    }

    /// CA の証明書のファイル。
    pub fn ca_certificate_path(&self) -> PathBuf {
        self.path.join(self.layout.ca_certificate())
    }

    /// ノードの証明書のファイル。
    pub fn node_certificate_path(&self) -> PathBuf {
        self.path.join(NODE_CERTIFICATE)
    }

    /// 置き換える前のファイルをコピーしておく既定の場所。
    /// フォルダーの隣の `<フォルダーの名前>.<UTC の日時>.bak`。
    ///
    /// shoestring はフォルダーの中に決まったファイルしかないことを確かめるので、中には置かない。
    pub fn default_backup_dir(&self, now: SystemTime) -> io::Result<PathBuf> {
        let path = fs::canonicalize(&self.path)?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("フォルダーの名前がありません"))?
            .to_string_lossy()
            .into_owned();
        let time = DateTime::from_system_time(now).map_err(io::Error::other)?;
        let stamp = format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            time.year(),
            time.month(),
            time.day(),
            time.hour(),
            time.minutes(),
            time.seconds()
        );
        Ok(path.with_file_name(format!("{name}.{stamp}.bak")))
    }

    /// `node.crt.pem` と `node.full.crt.pem` を `certificate` に置き換える。
    ///
    /// 置き換える前に、`certificate` とフォルダーの CA の証明書が catapult の条件を満たすことを確かめ、
    /// 元の2つのファイルを同じ名前のまま `backup_dir` にコピーする。`backup_dir` にすでに同じ名前のファイルがあれば何もしない。
    /// 新しいファイルは同じフォルダーの一時ファイルに書いてから名前を変えるので、途中で失敗しても書きかけのファイルは残らない。
    /// 権限は元のファイルに合わせる。
    pub fn replace_node_certificate(
        &self,
        certificate: &Certificate,
        backup_dir: &Path,
    ) -> Result<(), CertsDirError> {
        let ca_path = self.path.join(self.layout.ca_certificate());
        let ca_pem =
            fs::read(&ca_path).map_err(|error| CertsDirError::Read(ca_path.clone(), error))?;
        let ca = str::from_utf8(&ca_pem)
            .map_err(|_| ParseCertificateError::InvalidPem)
            .and_then(Certificate::from_pem)
            .map_err(|error| CertsDirError::Parse(ca_path.clone(), error))?;
        certificate::check_catapult_chain(&[certificate.clone(), ca])
            .map_err(CertsDirError::Chain)?;

        // shoestring のヘルスチェックは node.full.crt.pem が node.crt.pem と CA の証明書をそのままつないだものかを見る
        let node_pem = format!("{}\n", certificate.to_pem()).into_bytes();
        let full_pem = [node_pem.as_slice(), ca_pem.as_slice()].concat();
        let files = [
            (NODE_CERTIFICATE, node_pem),
            (NODE_FULL_CERTIFICATE, full_pem),
        ];

        fs::create_dir_all(backup_dir)
            .map_err(|error| CertsDirError::Backup(backup_dir.to_owned(), error))?;
        for (name, _) in &files {
            let backup = backup_dir.join(name);
            copy_new(&self.path.join(name), &backup)
                .map_err(|error| CertsDirError::Backup(backup, error))?;
        }

        let mut temporaries = Vec::new();
        for (name, contents) in &files {
            let target = self.path.join(name);
            let temporary = self.path.join(format!(".{name}.heika-tmp"));
            write_new(&temporary, contents, &target)
                .map_err(|error| CertsDirError::Write(temporary.clone(), error))?;
            temporaries.push((temporary, target));
        }
        for (temporary, target) in temporaries {
            fs::rename(&temporary, &target).map_err(|error| CertsDirError::Write(target, error))?;
        }
        // 名前の変更をディスクに残す。できない環境もあるので失敗は無視する
        let _ = File::open(&self.path).and_then(|dir| dir.sync_all());
        Ok(())
    }

    fn read_certificate(&self, name: &str) -> Result<Certificate, CertsDirError> {
        let path = self.path.join(name);
        let pem =
            fs::read_to_string(&path).map_err(|error| CertsDirError::Read(path.clone(), error))?;
        Certificate::from_pem(&pem).map_err(|error| CertsDirError::Parse(path, error))
    }
}

/// `source` を、権限ごと、新しいファイル `destination` にコピーする。
fn copy_new(source: &Path, destination: &Path) -> io::Result<()> {
    let contents = fs::read(source)?;
    write_new(destination, &contents, source)
}

/// `path` に新しいファイルを作って書き、ディスクに残す。権限は `like` に合わせる。
fn write_new(path: &Path, contents: &[u8], like: &Path) -> io::Result<()> {
    let permissions = fs::metadata(like)?.permissions();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(permissions.mode());
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    // umask で絞られた分を元に戻す
    fs::set_permissions(path, permissions)
}

/// フォルダーの証明書を読めない、または置き換えられない理由。
#[derive(Debug)]
pub enum CertsDirError {
    Read(PathBuf, io::Error),
    Parse(PathBuf, ParseCertificateError),
    /// 新しい証明書とフォルダーの CA の証明書が catapult の条件を満たさない
    Chain(ChainError),
    Backup(PathBuf, io::Error),
    Write(PathBuf, io::Error),
}

impl fmt::Display for CertsDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(path, error) => write!(f, "{} を読めませんでした: {error}", path.display()),
            Self::Parse(path, error) => write!(f, "{}: {error}", path.display()),
            Self::Chain(error) => write!(
                f,
                "新しい証明書とフォルダーの CA の証明書が catapult の条件を満たしません（{error}）"
            ),
            Self::Backup(path, error) => {
                write!(f, "{} にコピーできませんでした: {error}", path.display())
            }
            Self::Write(path, error) => write!(f, "{} に書けませんでした: {error}", path.display()),
        }
    }
}

impl std::error::Error for CertsDirError {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    use heika_core::key::{PrivateKey, PublicKey};

    use super::*;
    use crate::certificate::{Template, Version};

    /// テストごとの一時フォルダー。drop で消す
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "heika-certs-dir-{}-{}",
                std::process::id(),
                COUNT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn template<'a>(subject: &'a str, serial_number: &'a [u8]) -> Template<'a> {
        Template {
            subject,
            not_before: UNIX_EPOCH + Duration::from_secs(1_767_225_600),
            not_after: UNIX_EPOCH + Duration::from_secs(1_798_761_600),
            serial_number,
            version: Version::V3,
        }
    }

    fn ca_key() -> PrivateKey {
        PrivateKey::from_bytes(&[1; 32])
    }

    fn node_key() -> PublicKey {
        PublicKey::from_private_key(&PrivateKey::from_bytes(&[2; 32]))
    }

    /// shoestring か bootstrap と同じ5つのファイルを置いたフォルダーを作り、CA の証明書を返す
    fn populate(dir: &Path, layout: Layout) -> Certificate {
        let ca = Certificate::self_signed(&ca_key(), &template("CN=CA", &[1])).unwrap();
        let node =
            Certificate::issue(&ca, &ca_key(), &node_key(), &template("CN=node", &[2])).unwrap();
        let ca_pem = format!("{}\n", ca.to_pem());
        let node_pem = format!("{}\n", node.to_pem());
        for (name, contents) in [
            (layout.ca_certificate(), ca_pem.clone()),
            (NODE_CERTIFICATE, node_pem.clone()),
            (NODE_FULL_CERTIFICATE, node_pem + &ca_pem),
            ("node.key.pem", "dummy\n".to_owned()),
            ("ca.pubkey.pem", "dummy\n".to_owned()),
        ] {
            fs::write(dir.join(name), contents).unwrap();
            read_only(&dir.join(name));
        }
        ca
    }

    fn read_only(path: &Path) {
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn layouts() -> Vec<Layout> {
        vec![
            #[cfg(feature = "shoestring-compat")]
            Layout::Shoestring,
            #[cfg(feature = "bootstrap-compat")]
            Layout::Bootstrap,
        ]
    }

    #[test]
    fn replaces_the_node_certificate_and_keeps_a_backup() {
        for layout in layouts() {
            let dir = TempDir::new();
            let backup = TempDir::new();
            let ca = populate(&dir.0, layout);
            let certs_dir = CertsDir::new(&dir.0, layout);
            let before = names(&dir.0);
            let old_node = fs::read(dir.0.join(NODE_CERTIFICATE)).unwrap();
            let old_full = fs::read(dir.0.join(NODE_FULL_CERTIFICATE)).unwrap();

            let renewed = certs_dir
                .node_certificate()
                .unwrap()
                .renew(
                    &ca,
                    &ca_key(),
                    UNIX_EPOCH + Duration::from_secs(1_798_761_600),
                    UNIX_EPOCH + Duration::from_secs(1_831_248_000),
                    &[3],
                )
                .unwrap();
            certs_dir
                .replace_node_certificate(&renewed, &backup.0)
                .unwrap();

            // 一時ファイルは残らず、ファイルの顔ぶれは変わらない
            assert_eq!(names(&dir.0), before);
            assert_eq!(
                certs_dir.node_certificate().unwrap().to_der(),
                renewed.to_der()
            );
            let node = fs::read(dir.0.join(NODE_CERTIFICATE)).unwrap();
            let ca_pem = fs::read(dir.0.join(layout.ca_certificate())).unwrap();
            assert_eq!(
                fs::read(dir.0.join(NODE_FULL_CERTIFICATE)).unwrap(),
                [node, ca_pem].concat()
            );
            assert!(
                fs::metadata(dir.0.join(NODE_CERTIFICATE))
                    .unwrap()
                    .permissions()
                    .readonly()
            );
            assert!(
                fs::metadata(dir.0.join(NODE_FULL_CERTIFICATE))
                    .unwrap()
                    .permissions()
                    .readonly()
            );
            // 元のファイルは同じ名前のままコピーされている
            assert_eq!(names(&backup.0), [NODE_CERTIFICATE, NODE_FULL_CERTIFICATE]);
            assert_eq!(fs::read(backup.0.join(NODE_CERTIFICATE)).unwrap(), old_node);
            assert_eq!(
                fs::read(backup.0.join(NODE_FULL_CERTIFICATE)).unwrap(),
                old_full
            );
        }
    }

    #[test]
    fn refuses_a_certificate_from_another_ca_without_touching_anything() {
        for layout in layouts() {
            let dir = TempDir::new();
            let backup = TempDir::new();
            populate(&dir.0, layout);
            let other_key = PrivateKey::from_bytes(&[5; 32]);
            let other = Certificate::self_signed(&other_key, &template("CN=CA", &[1])).unwrap();
            let node =
                Certificate::issue(&other, &other_key, &node_key(), &template("CN=node", &[2]))
                    .unwrap();
            let old_node = fs::read(dir.0.join(NODE_CERTIFICATE)).unwrap();

            let error = CertsDir::new(&dir.0, layout)
                .replace_node_certificate(&node, &backup.0)
                .unwrap_err();
            assert!(
                matches!(error, CertsDirError::Chain(ChainError::NotSignedByRoot)),
                "{error}"
            );
            assert_eq!(fs::read(dir.0.join(NODE_CERTIFICATE)).unwrap(), old_node);
            assert!(names(&backup.0).is_empty());
        }
    }

    #[test]
    fn refuses_to_overwrite_a_backup() {
        for layout in layouts() {
            let dir = TempDir::new();
            let backup = TempDir::new();
            let ca = populate(&dir.0, layout);
            fs::write(backup.0.join(NODE_FULL_CERTIFICATE), "older backup\n").unwrap();
            let certs_dir = CertsDir::new(&dir.0, layout);
            let old_node = fs::read(dir.0.join(NODE_CERTIFICATE)).unwrap();
            let renewed = certs_dir
                .node_certificate()
                .unwrap()
                .renew(
                    &ca,
                    &ca_key(),
                    UNIX_EPOCH + Duration::from_secs(1_798_761_600),
                    UNIX_EPOCH + Duration::from_secs(1_831_248_000),
                    &[3],
                )
                .unwrap();

            let error = certs_dir
                .replace_node_certificate(&renewed, &backup.0)
                .unwrap_err();
            assert!(matches!(error, CertsDirError::Backup(..)), "{error}");
            assert_eq!(fs::read(dir.0.join(NODE_CERTIFICATE)).unwrap(), old_node);
            assert_eq!(
                fs::read_to_string(backup.0.join(NODE_FULL_CERTIFICATE)).unwrap(),
                "older backup\n"
            );
        }
    }

    #[test]
    fn puts_the_default_backup_next_to_the_folder() {
        let parent = TempDir::new();
        let dir = parent.0.join("certificates");
        fs::create_dir(&dir).unwrap();
        // 2026-10-11T12:34:56Z
        let now = UNIX_EPOCH + Duration::from_secs(1_791_722_096);
        let backup = CertsDir::new(&dir, layouts()[0])
            .default_backup_dir(now)
            .unwrap();
        assert_eq!(
            backup,
            fs::canonicalize(&parent.0)
                .unwrap()
                .join("certificates.20261011T123456Z.bak")
        );
    }
}
