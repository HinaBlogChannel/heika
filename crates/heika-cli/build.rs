use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Unix 以外では、書き出す秘密鍵のファイルを自分だけが読めるようにできない。
    // Unix と Windows のほかでは、標準入力から読む秘密鍵も std のバッファを通るのでメモリに残る
    let unix = env::var_os("CARGO_CFG_UNIX").is_some();
    let windows = env::var_os("CARGO_CFG_WINDOWS").is_some();
    if windows {
        println!(
            "cargo::warning=Windows では、書き出す秘密鍵のファイルの権限が絞られません（置いたフォルダーの権限を引き継ぎます）"
        );
    } else if !unix {
        println!(
            "cargo::warning=Unix と Windows のほかでは、標準入力から読んだ秘密鍵が std のバッファに残り、書き出す秘密鍵のファイルも権限が絞られません"
        );
    }

    embed_source();
}

/// ビルドする作業ツリーを git archive で ZIP にして、heika legal source で出せるようにする。
///
/// コミットしていない変更も入れるために、OUT_DIR に写した index に追跡しているファイルを足して、
/// 作業ツリーの tree を作ってまとめる。リポジトリの index と参照は変えない。
/// 追跡していないファイルは、置いたままの秘密鍵などを入れないように、無視されていなくても入れない。
/// git がないときや、heika のリポジトリの外でビルドするときは、空の ZIP を置いて警告する。
fn embed_source() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.join("../..");
    let (zip, description) = match archive(&workspace, &out_dir) {
        Ok(archived) => archived,
        Err(reason) => {
            println!("cargo::warning=ソースを埋め込めませんでした（{reason}）");
            println!("cargo::rerun-if-changed=build.rs");
            (Vec::new(), String::new())
        }
    };
    fs::write(out_dir.join("source.zip"), zip).expect("OUT_DIR is writable");
    println!("cargo::rustc-env=HEIKA_SOURCE_DESCRIPTION={description}");
}

/// ZIP と、それがどのコミットから作ったものかの説明を返す。
fn archive(workspace: &Path, out_dir: &Path) -> Result<(Vec<u8>, String), String> {
    // ほかのリポジトリの中に置かれたこのクレートを、そのリポジトリごとまとめないようにする
    let toplevel = git_text(workspace, &["rev-parse", "--show-toplevel"])?;
    let same = |a: &Path, b: &Path| a.canonicalize().ok() == b.canonicalize().ok();
    if !same(Path::new(toplevel.trim()), workspace) {
        return Err("heika のリポジトリの外でビルドしています".to_owned());
    }

    // 作り直すのは、追跡しているファイルか、HEAD か index が変わったとき
    for file in git_text(workspace, &["ls-files", "-z"])?.split('\0') {
        if !file.is_empty() {
            println!("cargo::rerun-if-changed={}", workspace.join(file).display());
        }
    }
    let git_path = |path| -> Result<PathBuf, String> {
        let path = git_text(workspace, &["rev-parse", "--git-path", path])?;
        Ok(workspace.join(path.trim()))
    };
    let index = git_path("index")?;
    for path in [git_path("HEAD")?, index.clone(), git_path("logs/HEAD")?] {
        // ないファイルを渡すと、毎回作り直すことになる
        if path.exists() {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }

    let untracked = git_text(workspace, &["ls-files", "--others", "--exclude-standard"])?;
    if !untracked.is_empty() {
        println!(
            "cargo::warning=追跡していないファイルは、埋め込むソースに入りません: {}",
            untracked.lines().collect::<Vec<_>>().join(", ")
        );
    }

    let temporary_index = out_dir.join("index");
    fs::copy(&index, &temporary_index)
        .map_err(|error| format!("{} を写せません: {error}", index.display()))?;
    let with_index = |args: &[&str]| git_with_index(workspace, &temporary_index, args);
    with_index(&["add", "--update"])?;
    let tree = String::from_utf8_lossy(&with_index(&["write-tree"])?)
        .trim()
        .to_owned();
    let head = git_text(workspace, &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    let head_tree = git_text(workspace, &["rev-parse", "HEAD^{tree}"])?;
    // 変更がなければ、コミットの時刻とハッシュが入るように HEAD をまとめる
    let (treeish, description) = if tree == head_tree.trim() {
        (head.clone(), head)
    } else {
        (
            tree,
            format!("{head} に、コミットしていない変更を加えたもの"),
        )
    };
    let version = env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");
    let prefix = format!("--prefix=heika-{version}/");
    let zip = git(workspace, &["archive", "--format=zip", &prefix, &treeish])?;
    Ok((zip, description))
}

/// git を実行して、標準出力を返す。
fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    run(Command::new("git").current_dir(dir).args(args), args)
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String, String> {
    String::from_utf8(git(dir, args)?).map_err(|_| "git の出力が UTF-8 ではありません".to_owned())
}

/// リポジトリの index の代わりに `index` を使って、git を実行する。
fn git_with_index(dir: &Path, index: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    run(
        Command::new("git")
            .current_dir(dir)
            .env("GIT_INDEX_FILE", index)
            .args(args),
        args,
    )
}

fn run(command: &mut Command, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = command
        .output()
        .map_err(|error| format!("git を実行できません: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} が失敗しました: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output.stdout)
}
