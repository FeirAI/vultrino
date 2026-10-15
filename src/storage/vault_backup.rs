//! Consistent vault backup and restore (VUL-11).
//!
//! A v10 vault is several files that only mean something together: the snapshot, its `.wal`, the
//! outbox, and (when the durable averin tier is on) the averin queue directory, PoP-key store and
//! dead-letter store. A copy of the snapshot alone is refused at restore, and a `.wal` from a
//! different moment can silently drop recent writes, including a kill. `backup` copies the whole
//! set while holding the vault lock (through the writer-intent gate) exclusively, writes a manifest
//! with a SHA-256 per file, and checks the copy by re-reading it and, when a password is given, by
//! opening it. `restore` verifies the manifest and every checksum (and opens the copy) before it
//! touches the target, refuses a backup that lacks the snapshot or the log, refuses to replace an
//! existing vault without `force`, and stages every file (the averin queue as one sibling directory) before any rename. A restore that is
//! interrupted leaves `<vault>.restore-pending`, which makes the vault refuse to open until
//! `restore` is re-run.
//!
//! Not covered: rollback of the vault directory by someone with write access (accepted, see
//! LIMITATIONS), and a running durable averin queue (its owner lock makes both commands refuse:
//! stop the service first).

use super::{FileStorage, StorageError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

type BackupResult<T> = Result<T, Box<dyn std::error::Error>>;

const MANIFEST: &str = "manifest.json";
const FORMAT: u32 = 1;
const QUEUE_PREFIX: &str = "averin-queue/";
/// How long to wait for the vault locks before telling the operator to stop the service.
const LOCK_WAIT: Duration = Duration::from_secs(30);

#[derive(Serialize, Deserialize)]
struct Manifest {
    format: u32,
    files: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    /// Logical name inside the backup directory (`vault.enc`, `vault.wal`, `outbox.enc`, ...).
    path: String,
    sha256: String,
    size: u64,
}

/// Marker file beside the vault while a restore is half-applied.
pub fn restore_pending_path(vault: &Path) -> PathBuf {
    vault.with_extension("restore-pending")
}

fn flat_layout(vault: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("vault.enc", vault.to_path_buf()),
        ("vault.wal", vault.with_extension("wal")),
        ("outbox.enc", vault.with_file_name("outbox.enc")),
        (
            "averin-popkeys.enc",
            vault.with_file_name("averin-popkeys.enc"),
        ),
        (
            "averin-deadletter.enc",
            vault.with_file_name("averin-deadletter.enc"),
        ),
    ]
}

fn queue_dir(vault: &Path) -> PathBuf {
    vault.with_file_name("averin-queue")
}

fn sha_of(path: &Path) -> BackupResult<(String, u64)> {
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

fn write_private(path: &Path, bytes: &[u8]) -> BackupResult<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn fsync_dir(dir: &Path) -> BackupResult<()> {
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn mkdir_private(dir: &Path) -> BackupResult<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    Ok(())
}

/// The held locks. Dropping releases them.
struct Held {
    _files: Vec<std::fs::File>,
}

fn open_sidecar(path: &Path) -> BackupResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?)
}

fn flock_exclusive(file: &std::fs::File, what: &str, wait: Duration) -> BackupResult<()> {
    let deadline = Instant::now() + wait;
    loop {
        match rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Ok(()),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "{what} is in use by a running process; stop the vultrino service and retry"
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(std::io::Error::from_raw_os_error(e.raw_os_error()).into()),
        }
    }
}

/// Take, in the same order as every writer (gate, vault, outbox), the exclusive locks, then the
/// durable averin queue's owner lock if that directory exists. All are non-blocking after
/// `LOCK_WAIT`: a held lock means a process is running and the caller must stop it first.
fn lock_everything(vault: &Path) -> BackupResult<Held> {
    let gate = open_sidecar(&vault.with_extension("gate"))?;
    flock_exclusive(&gate, "the vault", LOCK_WAIT)?;
    let vlock = open_sidecar(&vault.with_extension("lock"))?;
    flock_exclusive(&vlock, "the vault", LOCK_WAIT)?;
    // The gate is only a turnstile for waiting readers; with the vault lock held it can go.
    drop(gate);
    let mut files = vec![vlock];
    let outbox = vault.with_file_name("outbox.enc");
    files.push({
        let f = open_sidecar(&outbox.with_extension("lock"))?;
        flock_exclusive(&f, "the outbox", LOCK_WAIT)?;
        f
    });
    let qd = queue_dir(vault);
    if qd.is_dir() {
        let f = open_sidecar(&qd.join("queue.owner.lock"))?;
        flock_exclusive(&f, "the durable averin queue", Duration::ZERO)?;
        files.push(f);
    }
    Ok(Held { _files: files })
}

fn collect(vault: &Path) -> BackupResult<Vec<(String, PathBuf)>> {
    let mut out = vec![];
    for (name, p) in flat_layout(vault) {
        if p.is_file() {
            out.push((name.to_string(), p));
        } else if name == "vault.enc" || name == "vault.wal" {
            return Err(format!(
                "{} is missing: a v10 vault is a snapshot plus its .wal, refusing a partial backup",
                p.display()
            )
            .into());
        }
    }
    let qd = queue_dir(vault);
    if qd.is_dir() {
        let mut names: Vec<_> = std::fs::read_dir(&qd)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|e| e.file_name() != "queue.owner.lock")
            .collect();
        names.sort_by_key(|e| e.file_name());
        for e in names {
            if !e.path().is_file() {
                return Err(format!(
                    "unexpected non-file {} in the averin queue",
                    e.path().display()
                )
                .into());
            }
            out.push((
                format!("{QUEUE_PREFIX}{}", e.file_name().to_string_lossy()),
                e.path(),
            ));
        }
    }
    Ok(out)
}

async fn open_check(files: &[(String, PathBuf)], password: &SecretString) -> BackupResult<()> {
    let tmp = tempfile::tempdir()?;
    let vault = tmp.path().join("vault.enc");
    for (name, src) in files {
        let dst = match name.as_str() {
            "vault.enc" => vault.clone(),
            "vault.wal" => vault.with_extension("wal"),
            n if n.starts_with(QUEUE_PREFIX) => continue,
            n => tmp.path().join(n),
        };
        std::fs::copy(src, dst)?;
    }
    FileStorage::new(&vault, password)
        .await
        .map(|_| ())
        .map_err(|e: StorageError| format!("the copy does not open with this password: {e}").into())
}

/// Copy the vault set from `vault` into the new, empty directory `dest`. Returns the file count.
pub async fn backup(
    vault: &Path,
    dest: &Path,
    password: Option<&SecretString>,
) -> BackupResult<usize> {
    if !vault.is_file() {
        return Err(format!("no vault at {}", vault.display()).into());
    }
    if dest.exists() && std::fs::read_dir(dest)?.next().is_some() {
        return Err(format!("{} is not empty; backups never overwrite", dest.display()).into());
    }
    // The locks are held only for the copy. The password open check below runs the Argon2 KDF
    // and would otherwise block every dispatch and kill write for that long; it reads the copy,
    // not the live vault, so it needs no lock.
    let held = lock_everything(vault)?;
    let files = collect(vault)?;
    mkdir_private(dest)?;
    let mut entries = vec![];
    for (name, src) in &files {
        let dst = dest.join(name);
        if let Some(parent) = dst.parent() {
            mkdir_private(parent)?;
        }
        write_private(&dst, &std::fs::read(src)?)?;
        let (sha256, size) = sha_of(&dst)?;
        entries.push(Entry {
            path: name.clone(),
            sha256,
            size,
        });
    }
    let json = serde_json::to_vec_pretty(&Manifest {
        format: FORMAT,
        files: entries,
    })?;
    write_private(&dest.join(MANIFEST), &json)?;
    fsync_dir(dest)?;
    drop(held);
    // Verify the copy itself, not the source.
    let copied: Vec<_> = files
        .iter()
        .map(|(n, _)| (n.clone(), dest.join(n)))
        .collect();
    verify_manifest(dest)?;
    if let Some(pw) = password {
        open_check(&copied, pw).await?;
    }
    Ok(files.len())
}

fn verify_manifest(src: &Path) -> BackupResult<Manifest> {
    let raw = std::fs::read(src.join(MANIFEST))
        .map_err(|e| format!("{}: cannot read {MANIFEST}: {e}", src.display()))?;
    let m: Manifest = serde_json::from_slice(&raw)?;
    if m.format != FORMAT {
        return Err(format!("unsupported backup format {}", m.format).into());
    }
    for need in ["vault.enc", "vault.wal"] {
        if !m.files.iter().any(|e| e.path == need) {
            return Err(format!("backup is partial: {need} is not in the manifest").into());
        }
    }
    for e in &m.files {
        if e.path.contains("..") || e.path.starts_with('/') {
            return Err(format!("backup manifest has an unsafe path {}", e.path).into());
        }
        target_for(Path::new("v/vault.enc"), &e.path)?;
        let p = src.join(&e.path);
        let (sha, size) = sha_of(&p).map_err(|err| format!("{}: {err}", e.path))?;
        if sha != e.sha256 || size != e.size {
            return Err(format!(
                "{} does not match its checksum; refusing this backup",
                e.path
            )
            .into());
        }
    }
    // Nothing may sit in the backup that the manifest does not vouch for.
    let known: std::collections::HashSet<&str> = m.files.iter().map(|e| e.path.as_str()).collect();
    let mut stack = vec![src.to_path_buf()];
    while let Some(d) = stack.pop() {
        for ent in std::fs::read_dir(&d)? {
            let ent = ent?;
            let p = ent.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p.strip_prefix(src)?.to_string_lossy().to_string();
            if rel != MANIFEST && !known.contains(rel.as_str()) {
                return Err(format!("{rel} is in the backup but not in its manifest").into());
            }
        }
    }
    Ok(m)
}

/// Where a manifest name lands. Only the names a backup can contain are accepted: a manifest is
/// a file someone could edit, and it must not make restore write an arbitrary name into the vault
/// directory.
fn target_for(vault: &Path, name: &str) -> BackupResult<PathBuf> {
    if let Some(f) = name.strip_prefix(QUEUE_PREFIX) {
        if f.is_empty() || f.contains('/') || f.contains("..") || f == "queue.owner.lock" {
            return Err(format!("backup manifest has an unsafe queue name {name}").into());
        }
        return Ok(queue_dir(vault).join(f));
    }
    flat_layout(vault)
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, p)| p)
        .ok_or_else(|| format!("backup manifest names an unknown file {name}").into())
}

/// Restore the backup in `src` over `vault`. Existing files are only replaced with `force`, and
/// then moved aside (`.pre-restore-<nanos>`), never deleted.
pub async fn restore(
    src: &Path,
    vault: &Path,
    force: bool,
    password: Option<&SecretString>,
) -> BackupResult<usize> {
    let manifest = verify_manifest(src)?;
    let copied: Vec<_> = manifest
        .files
        .iter()
        .map(|e| (e.path.clone(), src.join(&e.path)))
        .collect();
    if let Some(pw) = password {
        open_check(&copied, pw).await?;
    }
    let dir = vault
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    mkdir_private(&dir)?;
    let _held = lock_everything(vault)?;
    let existing: Vec<PathBuf> = flat_layout(vault)
        .into_iter()
        .map(|(_, p)| p)
        .chain(std::iter::once(queue_dir(vault)))
        .filter(|p| p.exists())
        .collect();
    if !existing.is_empty() && !force {
        return Err(format!(
            "{} already holds a vault; pass --force to move it aside and restore",
            vault.display()
        )
        .into());
    }
    let marker = restore_pending_path(vault);
    if marker.exists() {
        std::fs::remove_file(&marker)?;
    }
    write_private(&marker, src.display().to_string().as_bytes())?;
    // Stage every file next to its target first, so nothing is renamed until all are on disk. The
    // averin queue is staged as a whole sibling directory (never inside the live one, which is
    // about to be moved aside) and put in place with one directory rename.
    let mut staged = vec![];
    let mut staged_queue = false;
    let stage_suffix = ".restore-tmp";
    let queue_stage = {
        let mut q = queue_dir(vault).into_os_string();
        q.push(stage_suffix);
        PathBuf::from(q)
    };
    if queue_stage.exists() {
        std::fs::remove_dir_all(&queue_stage)?;
    }
    for e in &manifest.files {
        let dst = target_for(vault, &e.path)?;
        let tmp = if let Some(f) = e.path.strip_prefix(QUEUE_PREFIX) {
            mkdir_private(&queue_stage)?;
            staged_queue = true;
            queue_stage.join(f)
        } else {
            let mut t = dst.clone().into_os_string();
            t.push(stage_suffix);
            PathBuf::from(t)
        };
        if !e.path.starts_with(QUEUE_PREFIX) {
            if tmp.exists() {
                std::fs::remove_file(&tmp)?;
            }
            staged.push((tmp.clone(), dst));
        }
        write_private(&tmp, &std::fs::read(src.join(&e.path))?)?;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    for p in &existing {
        let mut aside = p.clone().into_os_string();
        aside.push(format!(".pre-restore-{nanos}"));
        std::fs::rename(p, PathBuf::from(aside))?;
    }
    // A crash between these renames can pair files from two moments; the marker (removed only
    // after the last rename) makes the vault refuse to open until the restore is re-run.
    for (tmp, dst) in &staged {
        std::fs::rename(tmp, dst)?;
    }
    if staged_queue {
        std::fs::rename(&queue_stage, queue_dir(vault))?;
    }
    fsync_dir(&dir)?;
    std::fs::remove_file(&marker)?;
    fsync_dir(&dir)?;
    Ok(manifest.files.len())
}

/// What `vault check` found.
#[derive(Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The vault opens as it is.
    Healthy,
    /// The vault does not open, and removing exactly the final complete `.wal` line makes it open.
    /// That line is a committed record (possibly a kill or an approval): the operator decides.
    /// `saved_to` is set when the line was cut out (`--truncate-final`) and kept in a side file.
    FinalRecordDamaged {
        removed_bytes: usize,
        saved_to: Option<PathBuf>,
    },
}

/// Open the snapshot plus the given log bytes in a scratch directory.
async fn opens_with_log(vault: &Path, wal: &[u8], password: &SecretString) -> Result<(), String> {
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    let v = tmp.path().join("vault.enc");
    std::fs::copy(vault, &v).map_err(|e| e.to_string())?;
    std::fs::write(v.with_extension("wal"), wal).map_err(|e| e.to_string())?;
    FileStorage::new(&v, password)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// `vault check`: tell a healthy vault from one with a damaged FINAL `.wal` record, and with
/// `truncate_final` cut that one record out (keeping it in `<wal>.damaged-<nanos>`). It never
/// guesses: the cut is made only when the vault opens without that record, so damage anywhere else
/// (a middle line, the snapshot, a wrong password) is refused and nothing is touched. Cutting a
/// committed record loses that mutation; if it was a kill or a revocation, redo it afterwards.
/// Takes the exclusive locks, so stop the service first.
pub async fn check(
    vault: &Path,
    password: &SecretString,
    truncate_final: bool,
) -> BackupResult<CheckOutcome> {
    if !vault.is_file() {
        return Err(format!("no vault at {}", vault.display()).into());
    }
    let _held = lock_everything(vault)?;
    let wal_path = vault.with_extension("wal");
    let wal = std::fs::read(&wal_path)
        .map_err(|e| format!("{}: cannot read the log: {e}", wal_path.display()))?;
    let first = match opens_with_log(vault, &wal, password).await {
        Ok(()) => return Ok(CheckOutcome::Healthy),
        Err(e) => e,
    };
    // Only complete (newline-terminated) lines can be cut: a torn tail is already ignored.
    let Some(last_nl) = wal.iter().rposition(|b| *b == b'\n') else {
        return Err(
            format!("the vault does not open and its log has no record to cut: {first}").into(),
        );
    };
    let start = wal[..last_nl]
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    let kept = &wal[..start];
    if let Err(e) = opens_with_log(vault, kept, password).await {
        return Err(format!(
            "the vault does not open, and removing the final log record does not fix it, so the \
             damage is elsewhere (or the password is wrong); refusing to cut anything. open error: \
             {first}; without the final record: {e}"
        )
        .into());
    }
    let removed = wal.len() - start;
    if !truncate_final {
        return Ok(CheckOutcome::FinalRecordDamaged {
            removed_bytes: removed,
            saved_to: None,
        });
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let mut side = wal_path.clone().into_os_string();
    side.push(format!(".damaged-{nanos}"));
    let side = PathBuf::from(side);
    write_private(&side, &wal[start..])?;
    let f = std::fs::OpenOptions::new().write(true).open(&wal_path)?;
    f.set_len(start as u64)?;
    f.sync_all()?;
    if let Some(dir) = wal_path.parent() {
        fsync_dir(dir)?;
    }
    Ok(CheckOutcome::FinalRecordDamaged {
        removed_bytes: removed,
        saved_to: Some(side),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::NewUseToken;
    use crate::auth::UseToken;
    use crate::policy::{KillFenceQuery, KillFenceVerdict, Policy};
    use crate::storage::StorageBackend;
    use tempfile::tempdir;

    fn pw() -> SecretString {
        SecretString::from("pw")
    }

    async fn vault_with_a_kill(path: &Path) -> FileStorage {
        let s = FileStorage::new(path, &pw()).await.unwrap();
        let (_p, t) = UseToken::create(NewUseToken {
            name: "tok".into(),
            credential_scope: "*".into(),
            action_scope: None,
            max_uses: Some(5),
            require_approval: false,
            expires_in: None,
        });
        s.store_use_token(&t).await.unwrap();
        let mut p = Policy::allow_all("k1", "gh-*");
        p.id = "k1".into();
        p.kill = true;
        s.store_policy(&p).await.unwrap();
        s
    }

    fn halted(v: KillFenceVerdict) -> bool {
        matches!(v, KillFenceVerdict::Halted { .. })
    }

    async fn is_halted(path: &Path) -> bool {
        let s = FileStorage::new(path, &pw()).await.unwrap();
        halted(
            s.kill_fence_check(&KillFenceQuery {
                credential_alias: "gh-main",
                principal: None,
                admitted_epoch: 0,
            })
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn backup_then_restore_brings_back_the_snapshot_and_the_log_together() {
        let src = tempdir().unwrap();
        let vault = src.path().join("credentials.enc");
        let s = vault_with_a_kill(&vault).await;
        s.set_compact_min_bytes(u64::MAX); // keep the kill in the .wal, not folded into the snapshot
        drop(s);
        let bk = tempdir().unwrap().keep().join("bk");
        let n = backup(&vault, &bk, Some(&pw())).await.unwrap();
        assert!(n >= 2, "snapshot and log at least, got {n}");
        assert!(bk.join("vault.wal").is_file() && bk.join("manifest.json").is_file());

        let dst = tempdir().unwrap();
        let target = dst.path().join("restored.enc");
        restore(&bk, &target, false, Some(&pw())).await.unwrap();
        assert!(target.with_extension("wal").is_file());
        assert!(!restore_pending_path(&target).exists());
        assert!(
            is_halted(&target).await,
            "the kill made before the backup survives the restore"
        );
    }

    #[tokio::test]
    async fn restore_refuses_a_backup_without_its_log_or_with_a_changed_file() {
        let src = tempdir().unwrap();
        let vault = src.path().join("credentials.enc");
        drop(vault_with_a_kill(&vault).await);
        let bk = tempdir().unwrap().keep().join("bk");
        backup(&vault, &bk, None).await.unwrap();
        let dst = tempdir().unwrap();
        let target = dst.path().join("v.enc");

        // A flipped byte in the log: checksum mismatch, nothing written.
        let wal = bk.join("vault.wal");
        let good = std::fs::read(&wal).unwrap();
        let mut bad = good.clone();
        let last = bad.len() - 2;
        bad[last] ^= 1;
        std::fs::write(&wal, &bad).unwrap();
        let err = restore(&bk, &target, false, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("checksum"), "{err}");
        assert!(!target.exists());
        std::fs::write(&wal, &good).unwrap();

        // The log removed from the backup: refused, not restored as a bare snapshot.
        std::fs::remove_file(&wal).unwrap();
        let err = restore(&bk, &target, false, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("vault.wal"), "{err}");
        assert!(!target.exists());

        // A manifest that does not list the log at all: partial.
        std::fs::write(&wal, &good).unwrap();
        let mut m: Manifest =
            serde_json::from_slice(&std::fs::read(bk.join(MANIFEST)).unwrap()).unwrap();
        m.files.retain(|e| e.path != "vault.wal");
        std::fs::write(bk.join(MANIFEST), serde_json::to_vec(&m).unwrap()).unwrap();
        let err = restore(&bk, &target, false, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("partial"), "{err}");
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn restore_replaces_an_existing_vault_only_with_force_and_keeps_the_old_files() {
        let src = tempdir().unwrap();
        let vault = src.path().join("credentials.enc");
        drop(vault_with_a_kill(&vault).await);
        let bk = tempdir().unwrap().keep().join("bk");
        backup(&vault, &bk, None).await.unwrap();

        let dst = tempdir().unwrap();
        let target = dst.path().join("credentials.enc");
        drop(FileStorage::new(&target, &pw()).await.unwrap());
        let err = restore(&bk, &target, false, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("--force"), "{err}");
        assert!(
            !is_halted(&target).await,
            "a refused restore changes nothing"
        );
        restore(&bk, &target, true, None).await.unwrap();
        assert!(is_halted(&target).await);
        let aside = std::fs::read_dir(dst.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".pre-restore-")
            })
            .count();
        assert!(
            aside >= 2,
            "the old snapshot and log are moved aside, got {aside}"
        );
    }

    #[tokio::test]
    async fn backup_refuses_a_non_empty_destination_and_a_vault_without_its_log() {
        let src = tempdir().unwrap();
        let vault = src.path().join("credentials.enc");
        drop(vault_with_a_kill(&vault).await);
        let occupied = tempdir().unwrap();
        std::fs::write(occupied.path().join("x"), b"1").unwrap();
        assert!(backup(&vault, occupied.path(), None).await.is_err());
        std::fs::remove_file(vault.with_extension("wal")).unwrap();
        let bk = tempdir().unwrap().keep().join("bk");
        let err = backup(&vault, &bk, None).await.unwrap_err().to_string();
        assert!(err.contains("partial backup"), "{err}");
        assert!(!bk.exists(), "nothing is created for a refused backup");
    }

    /// A vault with several committed records after the last snapshot.
    async fn vault_with_records(path: &Path, n: usize) {
        let s = FileStorage::new(path, &pw()).await.unwrap();
        s.set_compact_min_bytes(u64::MAX);
        for i in 0..n {
            let (_p, t) = UseToken::create(NewUseToken {
                name: format!("tok{i}"),
                credential_scope: "*".into(),
                action_scope: None,
                max_uses: Some(5),
                require_approval: false,
                expires_in: None,
            });
            s.store_use_token(&t).await.unwrap();
        }
    }

    fn damage_line(wal: &mut [u8], line_from_end: usize) {
        // Flip one ciphertext byte inside the Nth complete line from the end, keep the newline.
        let mut ends: Vec<usize> = wal
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'\n')
            .map(|(i, _)| i)
            .collect();
        ends.reverse();
        let end = ends[line_from_end];
        wal[end - 3] = if wal[end - 3] == b'A' { b'B' } else { b'A' };
    }

    #[tokio::test]
    async fn check_cuts_only_a_damaged_final_record_and_refuses_damage_elsewhere() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("credentials.enc");
        vault_with_records(&vault, 3).await;
        let wal_path = vault.with_extension("wal");
        let good = std::fs::read(&wal_path).unwrap();
        assert_eq!(
            check(&vault, &pw(), false).await.unwrap(),
            CheckOutcome::Healthy
        );

        // Damage in the MIDDLE: refused, nothing touched.
        let mut mid = good.clone();
        damage_line(&mut mid, 1);
        std::fs::write(&wal_path, &mid).unwrap();
        let err = check(&vault, &pw(), true).await.unwrap_err().to_string();
        assert!(err.contains("damage is elsewhere"), "{err}");
        assert_eq!(std::fs::read(&wal_path).unwrap(), mid);

        // Damage in the FINAL line: reported without --truncate-final, unchanged.
        let mut last = good.clone();
        damage_line(&mut last, 0);
        std::fs::write(&wal_path, &last).unwrap();
        assert!(FileStorage::new(&vault, &pw()).await.is_err());
        let out = check(&vault, &pw(), false).await.unwrap();
        assert!(
            matches!(out, CheckOutcome::FinalRecordDamaged { saved_to: None, .. }),
            "{out:?}"
        );
        assert_eq!(std::fs::read(&wal_path).unwrap(), last);

        // A wrong password must not be mistaken for a damaged record.
        let err = check(&vault, &SecretString::from("nope"), true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("damage is elsewhere"), "{err}");
        assert_eq!(std::fs::read(&wal_path).unwrap(), last);

        // With the flag: cut, kept aside, and the vault opens with the earlier records.
        let out = check(&vault, &pw(), true).await.unwrap();
        let CheckOutcome::FinalRecordDamaged {
            saved_to: Some(side),
            removed_bytes,
        } = out
        else {
            panic!("{out:?}");
        };
        assert!(side.is_file());
        assert_eq!(std::fs::read(&side).unwrap().len(), removed_bytes);
        assert!(FileStorage::new(&vault, &pw()).await.is_ok());
        assert_eq!(
            std::fs::read(&wal_path).unwrap().len(),
            good.len() - removed_bytes
        );
    }

    #[tokio::test]
    async fn restore_over_an_existing_vault_with_an_averin_queue_succeeds_first_time() {
        let src = tempdir().unwrap();
        let vault = src.path().join("credentials.enc");
        drop(vault_with_a_kill(&vault).await);
        let q = queue_dir(&vault);
        std::fs::create_dir_all(&q).unwrap();
        std::fs::write(q.join("seg-0001.log"), b"from-the-backup").unwrap();
        let bk = tempdir().unwrap().keep().join("bk");
        backup(&vault, &bk, None).await.unwrap();
        assert!(bk.join("averin-queue/seg-0001.log").is_file());

        // The target already has a vault AND a queue directory holding different content.
        let dst = tempdir().unwrap();
        let target = dst.path().join("credentials.enc");
        drop(FileStorage::new(&target, &pw()).await.unwrap());
        let tq = queue_dir(&target);
        std::fs::create_dir_all(&tq).unwrap();
        std::fs::write(tq.join("seg-0009.log"), b"old").unwrap();

        restore(&bk, &target, true, Some(&pw())).await.unwrap();
        assert!(!restore_pending_path(&target).exists());
        assert_eq!(
            std::fs::read(tq.join("seg-0001.log")).unwrap(),
            b"from-the-backup"
        );
        assert!(!tq.join("seg-0009.log").exists());
        assert!(is_halted(&target).await);
        let kept_old_queue = std::fs::read_dir(dst.path()).unwrap().any(|e| {
            let p = e.unwrap().path();
            p.to_string_lossy().contains("averin-queue.pre-restore-")
                && p.join("seg-0009.log").is_file()
        });
        assert!(kept_old_queue, "the old queue is moved aside, not deleted");
    }

    #[tokio::test]
    async fn restore_refuses_a_manifest_that_names_an_unknown_file() {
        let src = tempdir().unwrap();
        let vault = src.path().join("credentials.enc");
        drop(vault_with_a_kill(&vault).await);
        let bk = tempdir().unwrap().keep().join("bk");
        backup(&vault, &bk, None).await.unwrap();
        std::fs::write(bk.join("evil.sh"), b"x").unwrap();
        let (sha, size) = sha_of(&bk.join("evil.sh")).unwrap();
        let mut m: Manifest =
            serde_json::from_slice(&std::fs::read(bk.join(MANIFEST)).unwrap()).unwrap();
        m.files.push(Entry {
            path: "evil.sh".into(),
            sha256: sha,
            size,
        });
        std::fs::write(bk.join(MANIFEST), serde_json::to_vec(&m).unwrap()).unwrap();
        let target = tempdir().unwrap().keep().join("v.enc");
        let err = restore(&bk, &target, false, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown file"), "{err}");
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn an_interrupted_restore_makes_the_vault_refuse_to_open() {
        let dir = tempdir().unwrap();
        let vault = dir.path().join("credentials.enc");
        drop(FileStorage::new(&vault, &pw()).await.unwrap());
        std::fs::write(restore_pending_path(&vault), b"x").unwrap();
        let err = FileStorage::new(&vault, &pw())
            .await
            .err()
            .expect("must refuse");
        assert!(err.to_string().contains("vault restore"), "{err}");
    }
}
