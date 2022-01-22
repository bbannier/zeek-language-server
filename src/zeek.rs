use std::str;
use std::sync::Arc;
use std::{ffi::OsStr, path::PathBuf};

use eyre::{eyre, Result};
use tower_lsp::lsp_types::Url;
use walkdir::WalkDir;

use crate::parse::Parse;
use crate::query;

async fn zeek_config<I, S>(args: I) -> Result<std::process::Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    tokio::process::Command::new("zeek-config")
        .args(args)
        .output()
        .await
        .map_err(Into::into)
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

pub(crate) fn init_script_filename() -> &'static str {
    // TODO(bbannier): does this function need a flag for bare mode?
    "base/init-default.zeek"
}

#[salsa::query_group(ZeekStorage)]
pub trait Zeek: salsa::Database + Parse {
    #[must_use]
    fn loaded_files(&self, url: Arc<Url>) -> Arc<Vec<Url>>;
}

fn loaded_files(db: &dyn Zeek, url: Arc<Url>) -> Arc<Vec<Url>> {
    let file = db.file(url);

    let tree = match db.parse(file.clone()) {
        Some(t) => t,
        None => return Arc::new(Vec::new()),
    };

    query::loads(tree.root_node(), &file.source);

    todo!()
}

#[cfg(test)]
mod test {
    use crate::zeek;

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
}
