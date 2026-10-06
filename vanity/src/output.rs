//! Private backups with an atomic checkpoint after each verified match.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub struct KeyOutput {
    path: PathBuf,
    file: File,
    continuous: bool,
    count: u64,
}

impl KeyOutput {
    /// Reserve a new output. Existing files, including symlinks, are rejected.
    pub fn create(path: &Path, continuous: bool) -> io::Result<Self> {
        let path = std::path::absolute(path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        if continuous {
            file.write_all(b"[]\n")?;
        }
        file.sync_all()?;
        sync_parent(&path)?;
        Ok(Self {
            path,
            file,
            continuous,
            count: 0,
        })
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Copy the committed array into a private sibling file, append one item,
    /// sync its data, replace the checkpoint atomically, then sync the directory.
    /// A failed write leaves the previous checkpoint intact.
    pub fn save(&mut self, json: &str) -> io::Result<()> {
        if !self.continuous && self.count != 0 {
            return Err(io::Error::other(
                "single-result backup already contains a key",
            ));
        }
        let mut pending = tempfile::NamedTempFile::new_in(self.path.parent().unwrap())?;
        if self.continuous {
            let length = self.file.metadata()?.len();
            let prefix_len = length
                .checked_sub(2)
                .ok_or_else(|| io::Error::other("invalid array checkpoint"))?;
            self.file.seek(SeekFrom::Start(0))?;
            let copied = io::copy(&mut (&mut self.file).take(prefix_len), &mut pending)?;
            if copied != prefix_len {
                return Err(io::Error::other("incomplete array checkpoint"));
            }
            if self.count > 0 {
                pending.write_all(b",\n")?;
            }
            pending.write_all(json.trim().as_bytes())?;
            pending.write_all(b"]\n")?;
        } else {
            pending.write_all(json.as_bytes())?;
        }
        pending.as_file().sync_all()?;
        // NamedTempFile uses 0600 permissions on Unix and creates exclusively.
        self.file = pending.persist(&self.path).map_err(|error| error.error)?;
        self.count += 1;
        sync_parent(&self.path)
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoints_are_complete_private_arrays_and_existing_files_are_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let mut output = KeyOutput::create(&path, true).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[]\n");
        for i in 0..3 {
            output.save(&format!("{{\"key\":{i}}}\n")).unwrap();
            let saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved.as_array().unwrap().len(), i + 1);
            assert_eq!(saved[i]["key"], i);
            assert!(KeyOutput::create(&path, true).is_err());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn replacement_failure_preserves_the_committed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let mut output = KeyOutput::create(&path, true).unwrap();
        output.save("{\"key\":1}").unwrap();
        let previous = std::fs::read(&path).unwrap();
        // Force a replacement error after the pending checkpoint is written.
        output.path = dir.path().join("directory");
        std::fs::create_dir(&output.path).unwrap();
        assert!(output.save("{\"key\":2}").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), previous);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
