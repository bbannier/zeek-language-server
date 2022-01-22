use std::path::PathBuf;
use std::str;

use eyre::{eyre, Result};
use walkdir::WalkDir;

async fn script_dir() -> Result<PathBuf> {
    let output = tokio::process::Command::new("zeek-config")
        .arg("--script_dir")
        .output()
        .await?;

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
    let mut prefixes = Vec::new();
    prefixes.push(script_dir().await?);
    Ok(prefixes)
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
    let dir = script_dir().await?;

    Ok(WalkDir::new(dir.clone())
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| !e.file_type().is_dir())
        .filter_map(|f| {
            if f.path().extension()? != "zeek" {
                return None;
            }

            Some(SystemFile::new(f.path().into(), dir.clone()))
        })
        .collect())
}

pub(crate) fn init_script_filename() -> &'static str {
    // TODO(bbannier): does this function need a flag for bare mode?
    "base/init-default.zeek"
}

#[cfg(test)]
mod test {
    use super::{script_dir, system_files};

    #[tokio::test]
    async fn test_script_dir() {
        assert!(script_dir()
            .await
            .expect("script_dir failed")
            .join("base/init-default.zeek")
            .exists());
    }

    #[tokio::test]
    async fn test_system_files() {
        let files = system_files().await.expect("can read system files");

        assert_ne!(files, vec![]);
    }
}
