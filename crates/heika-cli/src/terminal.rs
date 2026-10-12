//! 端末から秘密を読むための、打った文字を画面に出さない仕組みと、1行のパスフレーズの聞き方。

use std::fs::{File, OpenOptions};
use std::io;

use zeroize::Zeroizing;

/// パスフレーズの長さの上限（バイト）
const MAX_LINE: usize = 1024;

/// 端末から秘密を読むあいだ、打った文字を画面に出さないようにする。drop すると元に戻す。
///
/// ISIG も切って、Ctrl-C で落ちないようにする。落ちると、文字を出さないままの端末が残るためである。
/// Ctrl-C は ^C の文字として入るので、読む側で取りやめにするか、読めない入力として弾く。
#[cfg(unix)]
pub struct EchoOff {
    fd: std::os::fd::RawFd,
    original: libc::termios,
}

#[cfg(unix)]
impl EchoOff {
    pub fn stdin(stdin: &io::Stdin) -> Result<Self, String> {
        use std::os::fd::AsRawFd;
        Self::new(stdin.as_raw_fd())
    }

    fn new(fd: std::os::fd::RawFd) -> Result<Self, String> {
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: fd は開いている端末で、tcgetattr は成功したときに original を埋める
        if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
            return Err(format!(
                "端末の設定を読めませんでした: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: tcgetattr が成功したので埋まっている
        let original = unsafe { original.assume_init() };
        let mut hidden = original;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ISIG);
        // SAFETY: hidden は tcgetattr で読んだものを書き換えた、有効な termios
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(format!(
                "端末の設定を変えられませんでした: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: original は new で tcgetattr が読んだ、有効な termios
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
    }
}

/// Windows のコンソールから秘密を読むあいだ、打った文字を画面に出さないようにする。drop すると元に戻す。
///
/// Unix で ISIG を切るのと同じく、ENABLE_PROCESSED_INPUT も切って Ctrl-C で落ちないようにする。
#[cfg(windows)]
pub struct EchoOff {
    handle: windows_sys::Win32::Foundation::HANDLE,
    original: windows_sys::Win32::System::Console::CONSOLE_MODE,
}

#[cfg(windows)]
impl EchoOff {
    pub fn stdin(stdin: &io::Stdin) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        Self::new(stdin.as_raw_handle())
    }

    fn new(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<Self, String> {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode, SetConsoleMode,
        };

        let mut original = 0;
        // SAFETY: handle は開いているコンソールの入力で、GetConsoleMode は成功したときに original を埋める
        if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
            return Err(format!(
                "コンソールの設定を読めませんでした: {}",
                io::Error::last_os_error()
            ));
        }
        let hidden = original & !(ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        // SAFETY: handle は GetConsoleMode が読めたコンソールの入力
        if unsafe { SetConsoleMode(handle, hidden) } == 0 {
            return Err(format!(
                "コンソールの設定を変えられませんでした: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(Self { handle, original })
    }
}

#[cfg(windows)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: original は new で GetConsoleMode が読んだ、同じハンドルのモード
        unsafe { windows_sys::Win32::System::Console::SetConsoleMode(self.handle, self.original) };
    }
}

/// Unix と Windows のほかでは文字を出さずに読む方法を用意していない。
#[cfg(not(any(unix, windows)))]
pub struct EchoOff;

#[cfg(not(any(unix, windows)))]
impl EchoOff {
    pub fn stdin(_stdin: &io::Stdin) -> Result<Self, String> {
        Err("この OS では、端末から打った文字を隠せません".to_owned())
    }
}

/// 標準入力で秘密を読み終える操作の案内
#[cfg(windows)]
pub const END_OF_INPUT: &str = "Enter のあと Ctrl-Z と Enter";
#[cfg(not(windows))]
pub const END_OF_INPUT: &str = "改行してから Ctrl-D";

/// 端末から1行を、打った文字を画面に出さずに読む。標準入力とは別に、端末そのものを開いて読むので、
/// 標準入力をリダイレクトしていても聞ける。Enter で終わり、Ctrl-C で取りやめる。
pub fn prompt_line(prompt: &str) -> Result<Zeroizing<String>, String> {
    let mut terminal = Terminal::open()?;
    let _echo_off = terminal.echo_off()?;
    eprint!("{prompt}");
    let line = terminal.read_line();
    // 打った Enter も画面に出ていないので、次の出力が同じ行に続かないようにする
    eprintln!();
    line
}

#[cfg(unix)]
struct Terminal(File);

#[cfg(unix)]
impl Terminal {
    fn open() -> Result<Self, String> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map(Self)
            .map_err(|error| format!("端末を開けませんでした（端末から動かしてください）: {error}"))
    }

    fn echo_off(&self) -> Result<EchoOff, String> {
        use std::os::fd::AsRawFd;
        EchoOff::new(self.0.as_raw_fd())
    }

    /// 端末は行ごとに渡してくるので、改行まで1バイトずつ読む。
    fn read_line(&mut self) -> Result<Zeroizing<String>, String> {
        use std::io::Read;
        let mut buffer = Zeroizing::new([0; MAX_LINE]);
        let mut length = 0;
        loop {
            let mut byte = Zeroizing::new([0]);
            match self.0.read(&mut *byte) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("端末から読めませんでした: {error}")),
            }
            match byte[0] {
                b'\n' => break,
                0x03 => return Err("取りやめました".to_owned()),
                _ if length == buffer.len() => return Err("入力が長すぎます".to_owned()),
                value => {
                    buffer[length] = value;
                    length += 1;
                }
            }
        }
        let text = std::str::from_utf8(&buffer[..length])
            .map_err(|_| "UTF-8 として読めない文字が含まれています".to_owned())?;
        let mut line = Zeroizing::new(String::with_capacity(text.len()));
        line.push_str(text);
        Ok(line)
    }
}

#[cfg(windows)]
struct Terminal(File);

#[cfg(windows)]
impl Terminal {
    fn open() -> Result<Self, String> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .map(Self)
            .map_err(|error| {
                format!("コンソールを開けませんでした（コンソールから動かしてください）: {error}")
            })
    }

    fn echo_off(&self) -> Result<EchoOff, String> {
        use std::os::windows::io::AsRawHandle;
        EchoOff::new(self.0.as_raw_handle())
    }

    /// コードページによらずに読めるように、ReadConsoleW で UTF-16 のまま読んで UTF-8 にする。
    fn read_line(&mut self) -> Result<Zeroizing<String>, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::ReadConsoleW;

        let mut buffer = Zeroizing::new([0u16; MAX_LINE]);
        let mut length = 0;
        loop {
            if length == buffer.len() {
                return Err("入力が長すぎます".to_owned());
            }
            let mut read = 0;
            // SAFETY: ハンドルは開いているコンソールの入力で、書き込む先は buffer の残りの範囲
            let ok = unsafe {
                ReadConsoleW(
                    self.0.as_raw_handle(),
                    buffer[length..].as_mut_ptr().cast(),
                    (buffer.len() - length) as u32,
                    &mut read,
                    std::ptr::null(),
                )
            };
            if ok == 0 {
                return Err(format!(
                    "コンソールから読めませんでした: {}",
                    io::Error::last_os_error()
                ));
            }
            length += read as usize;
            if read == 0 || buffer[..length].contains(&u16::from(b'\n')) {
                break;
            }
        }
        let units = &buffer[..length];
        if units.contains(&0x03) {
            return Err("取りやめました".to_owned());
        }
        let end = units
            .iter()
            .position(|&unit| unit == u16::from(b'\r') || unit == u16::from(b'\n'))
            .unwrap_or(units.len());
        // 1つの UTF-16 の単位は、UTF-8 で3バイトまで
        let mut line = Zeroizing::new(String::with_capacity(end * 3));
        for character in char::decode_utf16(units[..end].iter().copied()) {
            line.push(character.map_err(|_| "読めない文字が含まれています".to_owned())?);
        }
        Ok(line)
    }
}

#[cfg(not(any(unix, windows)))]
struct Terminal;

#[cfg(not(any(unix, windows)))]
impl Terminal {
    fn open() -> Result<Self, String> {
        Err(
            "この OS では、端末からパスフレーズを聞けません。--passphrase-file を使ってください"
                .to_owned(),
        )
    }

    fn echo_off(&self) -> Result<EchoOff, String> {
        unreachable!()
    }

    fn read_line(&mut self) -> Result<Zeroizing<String>, String> {
        unreachable!()
    }
}
