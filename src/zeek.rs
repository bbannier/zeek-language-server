use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    str,
};

use eyre::{eyre, Result};
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
        .ok_or_else(|| eyre!("'zeek-config --script_dir' returned no output"))?;

    Ok(dir.into())
}

/// Get all prefixes understood by Zeek.
///
/// # Errors
///
/// Will return `Err` if Zeek cannot be queried.
pub async fn prefixes() -> Result<Vec<PathBuf>> {
    Ok(vec![
        dir(ZeekDir::Script).await?,
        dir(ZeekDir::Plugin).await?,
        dir(ZeekDir::Site).await?,
    ])
}

#[derive(Debug)]
pub struct CheckResult {
    pub file: String,
    pub line: u32,
    pub error: String,
}

/// Check the file for with Zeek from the given directory.
///
/// # Errors
///
/// Will return `Err` if `zeek` cannot be run.
pub async fn check<P1: AsRef<Path>, P2: AsRef<Path>>(
    file: P1,
    cwd: P2,
) -> Result<Vec<CheckResult>> {
    let check = tokio::process::Command::new("zeek")
        .current_dir(cwd)
        .arg("--parse-only")
        .arg(file.as_ref())
        .output()
        .await?;

    let errline = regex::Regex::new(r"error in (\S*), line (\d+): (.*)$").expect("valid regex");

    let stderr = str::from_utf8(&check.stderr)?;

    Ok(stderr
        .lines()
        .filter_map(|l| {
            errline.captures(l).and_then(|cap| {
                Some(CheckResult {
                    file: cap[1].to_string(),
                    line: cap[2].parse().ok()?,
                    error: cap[3].to_string(),
                })
            })
        })
        .collect())
}

#[derive(Debug, PartialEq)]
pub(crate) struct SystemFile {
    /// Full path of the file.
    pub path: PathBuf,

    /// Prefix under which the file was discovered.
    prefix: PathBuf,
}

impl SystemFile {
    pub fn new(path: PathBuf, prefix: PathBuf) -> Self {
        Self { path, prefix }
    }
}

pub(crate) async fn system_files() -> Result<Vec<SystemFile>> {
    Ok(prefixes()
        .await?
        .into_iter()
        .flat_map(|dir| {
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
        })
        .collect())
}

pub(crate) fn essential_input_files() -> Vec<&'static str> {
    // TODO(bbannier): does this function need a flag for bare mode?
    vec![
        "base/init-bare.zeek",
        "base/init-frameworks-and-bifs.zeek",
        "base/init-default.zeek",
    ]
}

#[cfg(test)]
mod test {
    use crate::zeek;
    use std::io::Write;

    #[tokio::test]
    async fn script_dir() {
        assert!(zeek::dir(zeek::ZeekDir::Script)
            .await
            .expect("script_dir failed")
            .join("base/init-default.zeek")
            .exists());
    }

    #[tokio::test]
    async fn system_files() {
        let files = zeek::system_files().await.expect("can read system files");

        assert_ne!(files, vec![]);
    }

    #[tokio::test]
    async fn check() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "invalid code").unwrap();

        let checks = zeek::check(&file, std::env::current_dir().unwrap())
            .await
            .unwrap();
        assert_eq!(checks.len(), 1);
        let check = &checks[0];
        assert_eq!(check.file, file.path().to_string_lossy().to_string());
        assert_eq!(check.line, 1);
        assert!(!check.error.is_empty());
    }
}
