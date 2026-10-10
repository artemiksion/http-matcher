use anyhow::{bail, Context, Result};
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use crate::corpus::collect_json_files;

pub fn validate_output_paths(input: &Path, patterns: &Path, output: &Path) -> Result<()> {
    let input_path = input
        .canonicalize()
        .with_context(|| format!("could not find input {}", input.display()))?;
    let destinations = [output.to_owned(), output.with_extension("skipped.jsonl")];
    let output_paths = destinations
        .iter()
        .map(|path| resolve_destination(path))
        .collect::<Result<Vec<_>>>()?;
    let output_metadata = destinations
        .iter()
        .map(|path| existing_metadata(path))
        .collect::<Result<Vec<_>>>()?;

    if output_paths[0] == output_paths[1] || same_file(&output_metadata[0], &output_metadata[1]) {
        bail!("output and skipped-pattern report must be separate files");
    }

    let mut protected_files = Vec::new();
    collect_json_files(&input_path, &mut protected_files)?;
    protected_files.push(patterns.to_owned());
    for path in protected_files {
        let protected_path = resolve_destination(&path)?;
        let protected_metadata = existing_metadata(&path)?;
        for (index, output_path) in output_paths.iter().enumerate() {
            if *output_path == protected_path
                || same_file(&output_metadata[index], &protected_metadata)
            {
                bail!(
                    "output {} would overwrite input or patterns {}",
                    destinations[index].display(),
                    path.display()
                );
            }
        }
    }

    if input_path.is_dir() {
        for path in output_paths {
            if path == input_path {
                bail!("output must be a file separate from the input directory");
            }
            if path.starts_with(&input_path)
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
            {
                bail!("use a .jsonl output file inside the JSON corpus directory");
            }
        }
    }
    Ok(())
}

// Resolve existing parents too, so a new file behind a directory symlink is
// checked against the actual corpus directory before any files are created.
fn resolve_destination(path: &Path) -> Result<PathBuf> {
    let mut ancestor = path.to_owned();
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut symlinks = 0;
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                for component in missing.into_iter().rev() {
                    match component.to_str() {
                        Some(".") => {}
                        Some("..") => {
                            resolved.pop();
                        }
                        _ => resolved.push(component),
                    }
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if fs::symlink_metadata(&ancestor)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    symlinks += 1;
                    if symlinks > 40 {
                        bail!("too many symlinks in {}", path.display());
                    }
                    let target = fs::read_link(&ancestor)?;
                    ancestor = if target.is_absolute() {
                        target
                    } else {
                        ancestor.parent().unwrap_or(Path::new("")).join(target)
                    };
                    continue;
                }
                let component = ancestor
                    .components()
                    .next_back()
                    .with_context(|| format!("could not resolve {}", path.display()))?;
                // Own each missing component because ancestor changes below.
                missing.push(component.as_os_str().to_owned());
                ancestor.pop();
                if ancestor.as_os_str().is_empty() {
                    ancestor = std::env::current_dir()?;
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", path.display()));
            }
        }
    }
}

fn existing_metadata(path: &Path) -> Result<Option<Metadata>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn same_file(left: &Option<Metadata>, right: &Option<Metadata>) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Some(left), Some(right)) = (left, right) {
            return left.dev() == right.dev() && left.ino() == right.ino();
        }
    }
    #[cfg(not(unix))]
    let _ = (left, right);
    false
}
