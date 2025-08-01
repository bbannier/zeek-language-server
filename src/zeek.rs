use itertools::Itertools;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Stdio,
    str,
    sync::LazyLock,
};

use eyre::{Result, eyre};
use path_clean::PathClean;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use walkdir::WalkDir;

async fn zeek_config<I, S>(args: I) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    tokio::process::Command::new("zeek-config")
        .args(args)
        .output()
        .await
        .map_err(|_| eyre!("zeek-config not found in PATH"))
}

#[derive(Copy, Debug, Clone)]
enum ZeekDir {
    Script,
    Plugin,
    Site,
}

async fn dir(dir: ZeekDir) -> Result<PathBuf> {
    let flag = match dir {
        ZeekDir::Script => "--script_dir",
        ZeekDir::Plugin => "--plugin_dir",
        ZeekDir::Site => "--site_dir",
    };

    let output = zeek_config(&[flag]).await?;

    let dir = str::from_utf8(&output.stdout)?
        .lines()
        .next()
        .ok_or_else(|| eyre!("'zeek-config {flag}' returned no output"))?;

    Ok(dir.into())
}

/// Get all prefixes understood by Zeek.
///
/// # Arguments
///
/// * `zeekpath` - value of `ZEEKPATH` to use; if unset read from the environment
///
/// # Errors
///
/// Will return `Err` if Zeek cannot be queried.
pub async fn prefixes(zeekpath: Option<String>) -> Result<impl Iterator<Item = PathBuf>> {
    let zeekpath = zeekpath.or_else(|| std::env::var("ZEEKPATH").ok());
    let xs = if let Some(path) = zeekpath {
        let cwd = std::env::current_dir()?;
        path.split(':')
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .map(|p| if p.is_absolute() { p } else { cwd.join(p) })
            .map(|p| p.clean())
            .collect::<Vec<_>>()
    } else {
        futures::future::join_all(
            [ZeekDir::Script, ZeekDir::Plugin, ZeekDir::Site]
                .into_iter()
                .map(|d| tokio::spawn(async move { dir(d).await })),
        )
        .await
        .into_iter()
        .flatten()
        .collect::<Result<_>>()?
    };

    // Minimize the list of prefixes so each prefix is seen at most once. Order still matters.
    Ok(xs.into_iter().unique())
}

#[derive(Debug)]
pub struct CheckResult {
    pub file: String,
    pub line: u32,
    pub message: String,
    pub kind: ErrorKind,
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
    Warning,
    Error,
}

/// Check the file for with Zeek from the given directory.
///
/// # Errors
///
/// Will return `Err` if `zeek` cannot be run.
///
/// # Panics
///
pub async fn check<P1: AsRef<Path>, P2: AsRef<Path>>(
    file: P1,
    cwd: P2,
) -> Result<Vec<CheckResult>> {
    static ERRLINE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(error|warning) in (\S*), line (\d+): (.*)$").expect("valid regex")
    });

    let check = tokio::process::Command::new("zeek")
        .current_dir(cwd)
        .arg("--parse-only")
        .arg(file.as_ref())
        .output()
        .await?;

    let stderr = str::from_utf8(&check.stderr)?;

    Ok(stderr
        .lines()
        .filter_map(|l| {
            ERRLINE.captures(l).and_then(|cap| {
                let kind = match &cap[1] {
                    "warning" => ErrorKind::Warning,
                    "error" => ErrorKind::Error,
                    _ => unreachable!(),
                };

                Some(CheckResult {
                    file: cap[2].to_string(),
                    line: cap[3].parse().ok()?,
                    message: cap[4].to_string(),
                    kind,
                })
            })
        })
        .collect())
}

#[derive(Debug, PartialEq)]
pub struct SystemFile {
    /// Full path of the file.
    pub path: PathBuf,

    /// Prefix under which the file was discovered.
    prefix: PathBuf,
}

impl SystemFile {
    #[must_use]
    pub fn new(path: PathBuf, prefix: PathBuf) -> Self {
        Self { path, prefix }
    }
}

pub async fn system_files() -> Result<impl Iterator<Item = SystemFile>> {
    Ok(prefixes(None).await?.flat_map(|dir| {
        WalkDir::new(dir.clone())
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| !e.file_type().is_dir())
            .filter_map(|f| {
                if f.path().extension()? != "zeek" {
                    return None;
                }

                Some(SystemFile::new(f.path().into(), dir.clone()))
            })
            .collect::<Vec<_>>()
    }))
}

pub(crate) fn essential_input_files() -> impl Iterator<Item = &'static str> {
    // TODO(bbannier): does this function need a flag for bare mode?
    [
        "base/init-bare.zeek",
        "base/init-frameworks-and-bifs.zeek",
        "base/init-default.zeek",
        "builtin-plugins/__preload__.zeek",
        "builtin-plugins/__load__.zeek",
    ]
    .into_iter()
}

pub(crate) async fn has_format() -> bool {
    format("").await.is_ok()
}

pub(crate) async fn format(doc: &str) -> Result<String> {
    let mut fmt = tokio::process::Command::new("zeek-format")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    fmt.stdin
        .take()
        .ok_or_else(|| eyre!("could not pass file data to zeek-format"))?
        .write_all(doc.as_bytes())
        .await?;

    let mut stdout = fmt
        .stdout
        .take()
        .ok_or_else(|| eyre!("could not read result from zeek-format"))?;

    if !tokio::spawn(async move { fmt.wait().await })
        .await??
        .success()
    {
        return Err(eyre!("failed to run zeek-format"));
    }

    let mut buffer = String::new();
    stdout.read_to_string(&mut buffer).await?;

    Ok(buffer)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]

    use crate::zeek;
    use std::{io::Write, path::PathBuf};

    #[tokio::test]
    async fn script_dir() {
        assert!(
            zeek::dir(zeek::ZeekDir::Script)
                .await
                .expect("script_dir failed")
                .join("base/init-default.zeek")
                .exists()
        );
    }

    #[tokio::test]
    async fn system_files() {
        let files: Vec<_> = zeek::system_files()
            .await
            .expect("can read system files")
            .collect();

        assert_ne!(files, vec![]);
    }

    #[tokio::test]
    async fn check_error() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "invalid code").unwrap();

        let checks = zeek::check(&file, std::env::current_dir().unwrap())
            .await
            .unwrap();

        assert_eq!(checks.len(), 1);
        let check = &checks[0];
        assert_eq!(check.file, file.path().to_string_lossy().to_string());
        assert_eq!(check.line, 1);
        assert!(!check.message.is_empty());
        assert_eq!(check.kind, zeek::ErrorKind::Error);
    }

    #[tokio::test]
    async fn check_warning() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "{}",
            "event http_stats(c: connection, stats: http_stats_rec) { c$removal_hooks; }"
        )
        .unwrap();

        let checks = zeek::check(&file, std::env::current_dir().unwrap())
            .await
            .unwrap();

        assert_eq!(checks.len(), 1);
        let check = &checks[0];
        assert_eq!(check.file, file.path().to_string_lossy().to_string());
        assert_eq!(check.line, 1);
        assert!(!check.message.is_empty());
        assert_eq!(check.kind, zeek::ErrorKind::Warning);
    }

    #[tokio::test]
    async fn format() {
        if !zeek::has_format().await {
            return;
        }

        assert_eq!(
            zeek::format(" global   foo  : event(  c: count, s : string)  ; ")
                .await
                .unwrap(),
            String::from("global foo: event(c: count, s: string);\n")
        );
    }

    #[tokio::test]
    async fn prefixes_from_env() {
        assert_eq!(
            zeek::prefixes(Some(String::new())).await.unwrap().count(),
            0
        );

        assert_eq!(zeek::prefixes(Some(":".into())).await.unwrap().count(), 0);

        assert_eq!(zeek::prefixes(Some("::".into())).await.unwrap().count(), 0);

        assert_eq!(
            zeek::prefixes(Some("/A".into()))
                .await
                .unwrap()
                .collect::<Vec<_>>(),
            vec![PathBuf::from("/A")]
        );

        assert_eq!(
            zeek::prefixes(Some("/A:/B".into()))
                .await
                .unwrap()
                .collect::<Vec<_>>(),
            vec![PathBuf::from("/A"), PathBuf::from("/B")]
        );

        assert_eq!(
            zeek::prefixes(Some("/A::/B".into()))
                .await
                .unwrap()
                .collect::<Vec<_>>(),
            vec![PathBuf::from("/A"), PathBuf::from("/B")]
        );

        assert_eq!(
            zeek::prefixes(Some(".".into()))
                .await
                .unwrap()
                .collect::<Vec<_>>(),
            vec![std::env::current_dir().unwrap()]
        );

        assert_eq!(
            zeek::prefixes(Some("/A:/B:/A:/C".into()))
                .await
                .unwrap()
                .collect::<Vec<_>>(),
            vec![
                PathBuf::from("/A"),
                PathBuf::from("/B"),
                PathBuf::from("/C")
            ]
        );
    }
}
