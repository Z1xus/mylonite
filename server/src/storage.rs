use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, bail};
use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata, Table,
    TableDefinition,
};
use serde::{Deserialize, Serialize};

use crate::util::{now_unix, random_hex};

const VAULTS: TableDefinition<&str, &[u8]> = TableDefinition::new("vaults");
const DEVICES: TableDefinition<&str, &[u8]> = TableDefinition::new("devices");
const PAIRING_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("pairing_tokens");
const OPLOG: TableDefinition<&str, &[u8]> = TableDefinition::new("oplog");
const CLIENT_OPS: TableDefinition<&str, u64> = TableDefinition::new("client_ops");
const BLOB_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_index");
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");

/// Op format written by plugin 0.1.x. The server cannot read payloads, so the
/// format is declared by the client and enforced per vault.
pub const LEGACY_FORMAT: u8 = 2;
pub const CURRENT_FORMAT: u8 = 3;

pub const PLUGIN_UPDATE_REQUIRED: &str = "plugin update required";
pub const VAULT_UPGRADE_REQUIRED: &str = "vault upgrade required";

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<Database>,
    data_dir: Arc<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedVault {
    pub id: String,
    pub name: String,
    pub created_at_unix: u64,
    pub pairing_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub id: String,
    pub name: String,
    pub created_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
    pub current_seq: u64,
    #[serde(default = "legacy_format")]
    pub format: u8,
    /// Last op of the legacy format. Ops after it use the current format.
    #[serde(default)]
    pub upgrade_seq: u64,
    /// Sequence the upgrading device had applied when it upgraded the vault.
    #[serde(default)]
    pub upgrade_base: u64,
    /// Total indexed blob bytes. `None` until first computed for older vaults.
    #[serde(default)]
    pub blob_bytes: Option<u64>,
}

fn legacy_format() -> u8 {
    LEGACY_FORMAT
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    pub format: u8,
    pub head_seq: u64,
    pub upgrade_seq: u64,
    pub upgrade_base: u64,
}

impl From<&VaultRecord> for VaultInfo {
    fn from(vault: &VaultRecord) -> Self {
        Self {
            format: vault.format,
            head_seq: vault.current_seq,
            upgrade_seq: vault.upgrade_seq,
            upgrade_base: vault.upgrade_base,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingTokenRecord {
    pub token: String,
    pub vault_id: String,
    pub expires_at_unix: u64,
    pub consumed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub vault_id: String,
    pub device_id: String,
    pub label: String,
    pub verifying_key: String,
    pub created_at_unix: u64,
    pub revoked_at_unix: Option<u64>,
    pub last_seen_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedOpRecord {
    pub vault_id: String,
    pub server_seq: u64,
    pub client_op_id: String,
    pub device_id: String,
    pub lamport: u64,
    pub kind: u8,
    pub key_version: u32,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub accepted_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct AppendedOp {
    pub op: EncryptedOpRecord,
    pub inserted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRecord {
    pub vault_id: String,
    pub blob_id: String,
    pub size: u64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub vault_id: String,
    pub snapshot_id: String,
    pub device_id: String,
    pub covers_through_seq: u64,
    pub key_version: u32,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub created_at_unix: u64,
}

/// Reads only the sequence of a snapshot row, so the large ciphertext is skipped.
#[derive(Deserialize)]
struct SnapshotSeq {
    covers_through_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub vault_count: u64,
    pub device_count: u64,
    pub active_device_count: u64,
    pub revoked_device_count: u64,
    pub pairing_token_count: u64,
    pub active_pairing_token_count: u64,
    pub consumed_pairing_token_count: u64,
    pub expired_pairing_token_count: u64,
    pub op_count: u64,
    pub blob_count: u64,
    pub indexed_blob_bytes: u64,
    pub snapshot_count: u64,
    pub database_bytes: u64,
    pub blob_file_bytes: u64,
    pub total_storage_bytes: u64,
    pub data_dir: String,
}

#[derive(Debug, Default)]
struct DeviceStats {
    total: u64,
    active: u64,
    revoked: u64,
}

#[derive(Debug, Default)]
struct PairingTokenStats {
    total: u64,
    active: u64,
    consumed: u64,
    expired: u64,
}

#[derive(Debug, Default)]
struct BlobStats {
    count: u64,
    indexed_bytes: u64,
}

impl Storage {
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(data_dir).with_context(|| format!("create {}", data_dir.display()))?;
        fs::create_dir_all(data_dir.join("blobs"))
            .with_context(|| format!("create {}", data_dir.join("blobs").display()))?;
        let db_path = data_dir.join("mylonite.redb");
        let db = match Database::create(&db_path) {
            Ok(db) => db,
            Err(redb::DatabaseError::UpgradeRequired(_)) => {
                upgrade_v2_database(&db_path)?;
                Database::create(&db_path).context("open redb database after format upgrade")?
            }
            Err(error) => return Err(error).context("open redb database"),
        };
        let storage = Self {
            db: Arc::new(db),
            data_dir: Arc::new(data_dir.to_path_buf()),
        };
        storage.ensure_tables()?;
        Ok(storage)
    }

    pub fn create_vault(&self, name: &str) -> anyhow::Result<CreatedVault> {
        let name = validate_vault_name(name)?;
        let now = now_unix()?;
        let id = format!("v{}", random_hex(16));
        let pairing_token = format!("p{}", random_hex(24));
        let record = VaultRecord {
            id: id.clone(),
            name: name.clone(),
            created_at_unix: now,
            revoked_at_unix: None,
            current_seq: 0,
            format: CURRENT_FORMAT,
            upgrade_seq: 0,
            upgrade_base: 0,
            blob_bytes: Some(0),
        };
        let token = PairingTokenRecord {
            token: pairing_token.clone(),
            vault_id: id.clone(),
            expires_at_unix: now + 15 * 60,
            consumed_at_unix: None,
        };

        let write = self.db.begin_write().context("begin write")?;
        {
            let mut vaults = write.open_table(VAULTS).context("open vault table")?;
            reject_duplicate_vault_name(&vaults, &record.name)?;
            write_json(&mut vaults, record.id.as_str(), &record)?;
            let mut tokens = write
                .open_table(PAIRING_TOKENS)
                .context("open pairing token table")?;
            write_json(&mut tokens, token.token.as_str(), &token)?;
        }
        write.commit().context("commit vault")?;
        Ok(CreatedVault {
            id,
            name,
            created_at_unix: now,
            pairing_token,
        })
    }

    pub fn list_vaults(&self) -> anyhow::Result<Vec<CreatedVault>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(VAULTS).context("open vault table")?;
        let mut vaults = Vec::new();
        for item in table.iter().context("iterate vaults")? {
            let (key, value) = item.context("read vault row")?;
            let record: VaultRecord =
                serde_json::from_slice(value.value()).context("decode vault row")?;
            vaults.push(CreatedVault {
                id: key.value().to_string(),
                name: record.name,
                created_at_unix: record.created_at_unix,
                pairing_token: String::new(),
            });
        }
        Ok(vaults)
    }

    pub fn vault_info(&self, vault_id: &str) -> anyhow::Result<VaultInfo> {
        let read = self.db.begin_read().context("begin read")?;
        let vaults = read.open_table(VAULTS).context("open vault table")?;
        Ok(VaultInfo::from(&read_vault(&vaults, vault_id)?))
    }

    /// Switches a vault to the current op format. The first caller wins, later
    /// callers get the recorded upgrade point.
    pub fn upgrade_vault(&self, vault_id: &str, base: u64) -> anyhow::Result<VaultInfo> {
        let write = self.db.begin_write().context("begin write")?;
        let info = {
            let mut vaults = write.open_table(VAULTS).context("open vault table")?;
            let mut vault = read_vault(&vaults, vault_id)?;
            if vault.format < CURRENT_FORMAT {
                vault.format = CURRENT_FORMAT;
                vault.upgrade_seq = vault.current_seq;
                vault.upgrade_base = base.min(vault.current_seq);
                write_json(&mut vaults, vault_id, &vault)?;
            }
            VaultInfo::from(&vault)
        };
        write.commit().context("commit vault upgrade")?;
        Ok(info)
    }

    pub fn delete_vault(&self, vault_id: &str) -> anyhow::Result<()> {
        let write = self.db.begin_write().context("begin write")?;
        {
            let mut vaults = write.open_table(VAULTS).context("open vault table")?;
            if vaults
                .remove(vault_id)
                .context("remove vault row")?
                .is_none()
            {
                bail!("vault not found");
            }
            remove_vault_rows(
                &mut write.open_table(DEVICES).context("open device table")?,
                vault_id,
            )?;
            remove_vault_rows(
                &mut write.open_table(OPLOG).context("open oplog")?,
                vault_id,
            )?;
            remove_vault_rows(
                &mut write
                    .open_table(CLIENT_OPS)
                    .context("open client ops table")?,
                vault_id,
            )?;
            remove_vault_rows(
                &mut write.open_table(BLOB_INDEX).context("open blob index")?,
                vault_id,
            )?;
            remove_vault_rows(
                &mut write.open_table(SNAPSHOTS).context("open snapshots")?,
                vault_id,
            )?;

            let mut tokens = write
                .open_table(PAIRING_TOKENS)
                .context("open pairing token table")?;
            let mut stale_tokens = Vec::new();
            for item in tokens.iter().context("iterate pairing tokens")? {
                let (key, value) = item.context("read pairing token row")?;
                let record: PairingTokenRecord =
                    serde_json::from_slice(value.value()).context("decode pairing token row")?;
                if record.vault_id == vault_id {
                    stale_tokens.push(key.value().to_string());
                }
            }
            for key in stale_tokens {
                tokens
                    .remove(key.as_str())
                    .context("remove pairing token")?;
            }
        }
        write.commit().context("commit vault delete")?;

        let blob_root = self.data_dir.join("blobs").join(vault_id);
        if blob_root.exists() {
            fs::remove_dir_all(&blob_root)
                .with_context(|| format!("remove {}", blob_root.display()))?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn issue_pairing_token(&self, vault_id: &str) -> anyhow::Result<PairingTokenRecord> {
        let token = PairingTokenRecord {
            token: format!("p{}", random_hex(24)),
            vault_id: vault_id.to_string(),
            expires_at_unix: now_unix()? + 15 * 60,
            consumed_at_unix: None,
        };
        let write = self.db.begin_write().context("begin write")?;
        {
            read_vault(
                &write.open_table(VAULTS).context("open vault table")?,
                vault_id,
            )?;
            let mut tokens = write
                .open_table(PAIRING_TOKENS)
                .context("open pairing token table")?;
            write_json(&mut tokens, token.token.as_str(), &token)?;
        }
        write.commit().context("commit pairing token")?;
        Ok(token)
    }

    pub fn register_first_device(
        &self,
        token: &str,
        label: &str,
        verifying_key: &str,
    ) -> anyhow::Result<DeviceRecord> {
        let now = now_unix()?;
        let write = self.db.begin_write().context("begin write")?;
        let device = {
            let mut tokens = write
                .open_table(PAIRING_TOKENS)
                .context("open pairing token table")?;
            let Some(mut token_record) = read_json::<PairingTokenRecord>(&tokens, token)? else {
                bail!("pairing token not found");
            };
            if token_record.consumed_at_unix.is_some() {
                bail!("pairing token already consumed");
            }
            if token_record.expires_at_unix < now {
                bail!("pairing token expired");
            }
            let mut devices = write.open_table(DEVICES).context("open device table")?;
            if vault_rows(&devices, &token_record.vault_id)?
                .next()
                .is_some()
            {
                bail!(
                    "vault already has a paired device; use the Request / Authorize flow from an existing device instead of a pairing token"
                );
            }
            token_record.consumed_at_unix = Some(now);
            write_json(&mut tokens, token, &token_record)?;

            let device = DeviceRecord {
                vault_id: token_record.vault_id,
                device_id: format!("d{}", random_hex(16)),
                label: label.to_string(),
                verifying_key: verifying_key.to_string(),
                created_at_unix: now,
                revoked_at_unix: None,
                last_seen_at_unix: None,
            };
            write_json(
                &mut devices,
                device_key(&device.vault_id, &device.device_id),
                &device,
            )?;
            device
        };
        write.commit().context("commit device")?;
        Ok(device)
    }

    pub fn register_authorized_device(
        &self,
        vault_id: &str,
        label: &str,
        verifying_key: &str,
        max_active_devices: usize,
    ) -> anyhow::Result<DeviceRecord> {
        let now = now_unix()?;
        let write = self.db.begin_write().context("begin write")?;
        let device = {
            read_vault(
                &write.open_table(VAULTS).context("open vault table")?,
                vault_id,
            )?;
            let mut devices = write.open_table(DEVICES).context("open device table")?;
            let mut active = 0;
            for item in vault_rows(&devices, vault_id)? {
                let (_, value) = item.context("read device row")?;
                let device: DeviceRecord =
                    serde_json::from_slice(value.value()).context("decode device row")?;
                if device.revoked_at_unix.is_none() {
                    active += 1;
                }
            }
            if active >= max_active_devices {
                bail!("vault device limit reached");
            }
            let device = DeviceRecord {
                vault_id: vault_id.to_string(),
                device_id: format!("d{}", random_hex(16)),
                label: label.to_string(),
                verifying_key: verifying_key.to_string(),
                created_at_unix: now,
                revoked_at_unix: None,
                last_seen_at_unix: None,
            };
            write_json(
                &mut devices,
                device_key(&device.vault_id, &device.device_id),
                &device,
            )?;
            device
        };
        write.commit().context("commit authorized device")?;
        Ok(device)
    }

    pub fn list_devices(&self, vault_id: &str) -> anyhow::Result<Vec<DeviceRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(DEVICES).context("open device table")?;
        let mut out = Vec::new();
        for item in vault_rows(&table, vault_id)? {
            let (_, value) = item.context("read device row")?;
            out.push(serde_json::from_slice(value.value()).context("decode device row")?);
        }
        Ok(out)
    }

    pub fn get_active_device(
        &self,
        vault_id: &str,
        device_id: &str,
    ) -> anyhow::Result<DeviceRecord> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(DEVICES).context("open device table")?;
        let Some(device) = read_json::<DeviceRecord>(&table, &device_key(vault_id, device_id))?
        else {
            bail!("device not found");
        };
        if device.revoked_at_unix.is_some() {
            bail!("device revoked");
        }
        Ok(device)
    }

    pub fn revoke_device(&self, vault_id: &str, device_id: &str) -> anyhow::Result<()> {
        let now = now_unix()?;
        let key = device_key(vault_id, device_id);
        let write = self.db.begin_write().context("begin write")?;
        {
            let mut table = write.open_table(DEVICES).context("open device table")?;
            let Some(mut device) = read_json::<DeviceRecord>(&table, &key)? else {
                bail!("device not found");
            };
            device.revoked_at_unix = Some(now);
            write_json(&mut table, key, &device)?;
        }
        write.commit().context("commit device revoke")
    }

    /// Appends ops in one transaction. Ops with a known client op id are not
    /// stored again and keep their original sequence.
    pub fn append_ops(
        &self,
        vault_id: &str,
        format: u8,
        ops: Vec<EncryptedOpRecord>,
    ) -> anyhow::Result<Vec<AppendedOp>> {
        let now = now_unix()?;
        let write = self.db.begin_write().context("begin write")?;
        let appended = {
            let mut vaults = write.open_table(VAULTS).context("open vault table")?;
            let mut client_ops = write.open_table(CLIENT_OPS).context("open client ops")?;
            let mut oplog = write.open_table(OPLOG).context("open oplog")?;
            let mut vault = read_vault(&vaults, vault_id)?;
            if vault.format >= CURRENT_FORMAT && format < CURRENT_FORMAT {
                bail!(PLUGIN_UPDATE_REQUIRED);
            }
            if vault.format < CURRENT_FORMAT && format >= CURRENT_FORMAT {
                bail!(VAULT_UPGRADE_REQUIRED);
            }
            let mut appended = Vec::with_capacity(ops.len());
            for mut op in ops {
                let client_key = client_op_key(vault_id, &op.client_op_id);
                let existing = client_ops
                    .get(client_key.as_str())
                    .context("read client op")?
                    .map(|seq| seq.value());
                if let Some(seq) = existing {
                    op.server_seq = seq;
                    appended.push(AppendedOp {
                        op,
                        inserted: false,
                    });
                    continue;
                }
                vault.current_seq += 1;
                op.vault_id = vault_id.to_string();
                op.server_seq = vault.current_seq;
                op.accepted_at_unix = now;
                client_ops
                    .insert(client_key.as_str(), op.server_seq)
                    .context("insert client op")?;
                write_json(&mut oplog, op_key(vault_id, op.server_seq), &op)?;
                appended.push(AppendedOp { op, inserted: true });
            }
            write_json(&mut vaults, vault_id, &vault)?;
            appended
        };
        write.commit().context("commit ops")?;
        Ok(appended)
    }

    pub fn list_ops_after(
        &self,
        vault_id: &str,
        after_seq: u64,
        limit: u64,
    ) -> anyhow::Result<Vec<EncryptedOpRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(OPLOG).context("open oplog")?;
        let start = op_key(vault_id, after_seq.saturating_add(1));
        let end = vault_range(vault_id).1;
        let mut out = Vec::new();
        for item in table
            .range(start.as_str()..end.as_str())
            .context("range oplog")?
        {
            if u64::try_from(out.len()).unwrap_or(u64::MAX) >= limit {
                break;
            }
            let (_, value) = item.context("read op row")?;
            out.push(serde_json::from_slice(value.value()).context("decode op row")?);
        }
        Ok(out)
    }

    pub fn put_blob_with_vault_limit(
        &self,
        vault_id: &str,
        blob_id: &str,
        bytes: &[u8],
        max_vault_size_bytes: u64,
    ) -> anyhow::Result<BlobRecord> {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let key = blob_key(vault_id, blob_id);
        let path = self.blob_path(vault_id, blob_id);
        {
            let read = self.db.begin_read().context("begin read")?;
            let vault = read_vault(
                &read.open_table(VAULTS).context("open vault table")?,
                vault_id,
            )?;
            let index = read.open_table(BLOB_INDEX).context("open blob index")?;
            let existing = read_json::<BlobRecord>(&index, &key)?;
            let existing_size = existing.as_ref().map_or(0, |record| record.size);
            let usage = match vault.blob_bytes {
                Some(bytes) => bytes,
                None => sum_blob_bytes(&index, vault_id)?,
            };
            if usage.saturating_sub(existing_size).saturating_add(size) > max_vault_size_bytes {
                bail!("vault exceeds configured size limit");
            }
        }

        write_file_atomic(&path, bytes)?;

        let record = BlobRecord {
            vault_id: vault_id.to_string(),
            blob_id: blob_id.to_string(),
            size,
            created_at_unix: now_unix()?,
        };
        let write = self.db.begin_write().context("begin write")?;
        {
            let mut vaults = write.open_table(VAULTS).context("open vault table")?;
            let mut index = write.open_table(BLOB_INDEX).context("open blob index")?;
            let mut vault = read_vault(&vaults, vault_id)?;
            let previous_size = read_json::<BlobRecord>(&index, &key)?.map_or(0, |old| old.size);
            let usage = match vault.blob_bytes {
                Some(bytes) => bytes,
                None => sum_blob_bytes(&index, vault_id)?,
            };
            vault.blob_bytes = Some(usage.saturating_sub(previous_size).saturating_add(size));
            write_json(&mut index, key, &record)?;
            write_json(&mut vaults, vault_id, &vault)?;
        }
        write.commit().context("commit blob")?;
        Ok(record)
    }

    pub fn get_blob(&self, vault_id: &str, blob_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.blob_path(vault_id, blob_id);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn missing_blobs(
        &self,
        vault_id: &str,
        blob_ids: &[String],
    ) -> anyhow::Result<Vec<String>> {
        let read = self.db.begin_read().context("begin read")?;
        let index = read.open_table(BLOB_INDEX).context("open blob index")?;
        let mut missing = Vec::new();
        for blob_id in blob_ids {
            let key = blob_key(vault_id, blob_id);
            if index.get(key.as_str()).context("read blob row")?.is_none() {
                missing.push(blob_id.clone());
            }
        }
        Ok(missing)
    }

    pub fn put_snapshot(&self, mut snapshot: SnapshotRecord) -> anyhow::Result<()> {
        snapshot.created_at_unix = now_unix()?;
        let write = self.db.begin_write().context("begin write")?;
        {
            let mut table = write.open_table(SNAPSHOTS).context("open snapshots")?;
            write_json(
                &mut table,
                snapshot_key(&snapshot.vault_id, &snapshot.snapshot_id),
                &snapshot,
            )?;
        }
        write.commit().context("commit snapshot")
    }

    pub fn list_snapshots(&self, vault_id: &str) -> anyhow::Result<Vec<SnapshotRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(SNAPSHOTS).context("open snapshots")?;
        let mut out = Vec::new();
        for item in vault_rows(&table, vault_id)? {
            let (_, value) = item.context("read snapshot row")?;
            out.push(serde_json::from_slice(value.value()).context("decode snapshot row")?);
        }
        out.sort_by_key(|snapshot: &SnapshotRecord| snapshot.covers_through_seq);
        Ok(out)
    }

    pub fn latest_snapshot(&self, vault_id: &str) -> anyhow::Result<Option<SnapshotRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(SNAPSHOTS).context("open snapshots")?;
        let mut latest: Option<(u64, String)> = None;
        for item in vault_rows(&table, vault_id)? {
            let (key, value) = item.context("read snapshot row")?;
            let seq = serde_json::from_slice::<SnapshotSeq>(value.value())
                .context("decode snapshot row")?
                .covers_through_seq;
            if latest.as_ref().is_none_or(|(best, _)| seq >= *best) {
                latest = Some((seq, key.value().to_string()));
            }
        }
        match latest {
            Some((_, key)) => read_json(&table, &key),
            None => Ok(None),
        }
    }

    pub fn prune_snapshots(&self, vault_id: &str, retain: usize) -> anyhow::Result<()> {
        let snapshots = self.list_snapshots(vault_id)?;
        let remove_count = snapshots.len().saturating_sub(retain);
        if remove_count == 0 {
            return Ok(());
        }
        let write = self.db.begin_write().context("begin write")?;
        {
            let mut table = write.open_table(SNAPSHOTS).context("open snapshots")?;
            for snapshot in snapshots.into_iter().take(remove_count) {
                table
                    .remove(snapshot_key(vault_id, &snapshot.snapshot_id).as_str())
                    .context("remove old snapshot")?;
            }
        }
        write.commit().context("commit snapshot prune")
    }

    pub fn stats(&self) -> anyhow::Result<StorageStats> {
        let read = self.db.begin_read().context("begin read")?;
        let vault_count = count_rows(&read, VAULTS, "vaults")?;
        let devices = collect_device_stats(&read)?;
        let pairing_tokens = collect_pairing_token_stats(&read, now_unix()?)?;
        let op_count = count_rows(&read, OPLOG, "oplog")?;
        let snapshot_count = count_rows(&read, SNAPSHOTS, "snapshots")?;
        let blobs = collect_blob_stats(&read)?;

        let database_bytes =
            fs::metadata(self.data_dir.join("mylonite.redb")).map_or(0, |metadata| metadata.len());
        let blob_file_bytes = dir_size(&self.data_dir.join("blobs"))?;
        let total_storage_bytes = dir_size(&self.data_dir)?;

        Ok(StorageStats {
            vault_count,
            device_count: devices.total,
            active_device_count: devices.active,
            revoked_device_count: devices.revoked,
            pairing_token_count: pairing_tokens.total,
            active_pairing_token_count: pairing_tokens.active,
            consumed_pairing_token_count: pairing_tokens.consumed,
            expired_pairing_token_count: pairing_tokens.expired,
            op_count,
            blob_count: blobs.count,
            indexed_blob_bytes: blobs.indexed_bytes,
            snapshot_count,
            database_bytes,
            blob_file_bytes,
            total_storage_bytes,
            data_dir: self.data_dir.display().to_string(),
        })
    }

    fn ensure_tables(&self) -> anyhow::Result<()> {
        let write = self.db.begin_write().context("begin schema write")?;
        {
            write.open_table(VAULTS).context("create vault table")?;
            write.open_table(DEVICES).context("create device table")?;
            write
                .open_table(PAIRING_TOKENS)
                .context("create pairing token table")?;
            write.open_table(OPLOG).context("create oplog table")?;
            write
                .open_table(CLIENT_OPS)
                .context("create client ops table")?;
            write
                .open_table(BLOB_INDEX)
                .context("create blob index table")?;
            write
                .open_table(SNAPSHOTS)
                .context("create snapshots table")?;
        }
        write.commit().context("commit schema")
    }

    fn blob_path(&self, vault_id: &str, blob_id: &str) -> PathBuf {
        let blob_prefix = blob_id.get(..2).unwrap_or(blob_id);
        self.data_dir
            .join("blobs")
            .join(vault_id)
            .join(blob_prefix)
            .join(blob_id)
    }
}

fn upgrade_v2_database(db_path: &Path) -> anyhow::Result<()> {
    let mut db = redb2::Database::open(db_path)
        .with_context(|| format!("open {} for format upgrade", db_path.display()))?;
    db.upgrade()
        .with_context(|| format!("upgrade {} to the v3 file format", db_path.display()))?;
    Ok(())
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().context("blob path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let temp = parent.join(format!(".tmp-{}", random_hex(8)));
    fs::write(&temp, bytes).with_context(|| format!("write {}", temp.display()))?;
    fs::rename(&temp, path).with_context(|| format!("rename {}", path.display()))
}

fn validate_vault_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty() {
        bail!("vault name is required");
    }
    if name.len() > 128 {
        bail!("vault name is too long");
    }
    Ok(name.to_string())
}

fn reject_duplicate_vault_name(vaults: &Table<'_, &str, &[u8]>, name: &str) -> anyhow::Result<()> {
    for item in vaults.iter().context("iterate vaults")? {
        let (_, value) = item.context("read vault row")?;
        let record: VaultRecord =
            serde_json::from_slice(value.value()).context("decode vault row")?;
        if record.revoked_at_unix.is_none() && record.name.eq_ignore_ascii_case(name) {
            bail!("vault name already exists");
        }
    }
    Ok(())
}

fn read_vault(
    vaults: &impl ReadableTable<&'static str, &'static [u8]>,
    vault_id: &str,
) -> anyhow::Result<VaultRecord> {
    read_json(vaults, vault_id)?.context("vault not found")
}

fn read_json<T: serde::de::DeserializeOwned>(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> anyhow::Result<Option<T>> {
    let Some(value) = table.get(key).context("read row")? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_slice(value.value()).context("decode row")?,
    ))
}

fn write_json<T: Serialize>(
    table: &mut Table<'_, &str, &[u8]>,
    key: impl AsRef<str>,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value).context("encode json record")?;
    table
        .insert(key.as_ref(), bytes.as_slice())
        .context("insert json record")?;
    Ok(())
}

/// Keys of one vault are `"{vault_id}:..."`, so they sort between these bounds.
fn vault_range(vault_id: &str) -> (String, String) {
    (format!("{vault_id}:"), format!("{vault_id};"))
}

fn vault_rows<'a, V: redb::Value + 'static>(
    table: &'a impl ReadableTable<&'static str, V>,
    vault_id: &str,
) -> anyhow::Result<redb::Range<'a, &'static str, V>> {
    let (start, end) = vault_range(vault_id);
    table
        .range(start.as_str()..end.as_str())
        .context("range vault rows")
}

fn remove_vault_rows<V: redb::Value + 'static>(
    table: &mut Table<'_, &str, V>,
    vault_id: &str,
) -> anyhow::Result<()> {
    let (start, end) = vault_range(vault_id);
    table
        .retain_in(start.as_str()..end.as_str(), |_, _| false)
        .context("remove vault rows")
}

fn sum_blob_bytes(
    index: &impl ReadableTable<&'static str, &'static [u8]>,
    vault_id: &str,
) -> anyhow::Result<u64> {
    let mut total = 0_u64;
    for item in vault_rows(index, vault_id)? {
        let (_, value) = item.context("read blob row")?;
        let record: BlobRecord =
            serde_json::from_slice(value.value()).context("decode blob row")?;
        total = total.saturating_add(record.size);
    }
    Ok(total)
}

fn count_rows<V>(
    read: &ReadTransaction,
    table: TableDefinition<&str, V>,
    table_name: &str,
) -> anyhow::Result<u64>
where
    V: redb::Value + 'static,
{
    read.open_table(table)
        .with_context(|| format!("open {table_name} table"))?
        .len()
        .with_context(|| format!("count {table_name}"))
}

fn collect_device_stats(read: &ReadTransaction) -> anyhow::Result<DeviceStats> {
    let mut stats = DeviceStats::default();
    for item in read
        .open_table(DEVICES)
        .context("open device table")?
        .iter()
        .context("iterate devices")?
    {
        let (_, value) = item.context("read device row")?;
        let device: DeviceRecord =
            serde_json::from_slice(value.value()).context("decode device row")?;
        stats.total = stats.total.saturating_add(1);
        if device.revoked_at_unix.is_some() {
            stats.revoked = stats.revoked.saturating_add(1);
        } else {
            stats.active = stats.active.saturating_add(1);
        }
    }
    Ok(stats)
}

fn collect_pairing_token_stats(
    read: &ReadTransaction,
    now: u64,
) -> anyhow::Result<PairingTokenStats> {
    let mut stats = PairingTokenStats::default();
    for item in read
        .open_table(PAIRING_TOKENS)
        .context("open pairing token table")?
        .iter()
        .context("iterate pairing tokens")?
    {
        let (_, value) = item.context("read pairing token row")?;
        let token: PairingTokenRecord =
            serde_json::from_slice(value.value()).context("decode pairing token row")?;
        stats.total = stats.total.saturating_add(1);
        if token.consumed_at_unix.is_some() {
            stats.consumed = stats.consumed.saturating_add(1);
        } else if token.expires_at_unix < now {
            stats.expired = stats.expired.saturating_add(1);
        } else {
            stats.active = stats.active.saturating_add(1);
        }
    }
    Ok(stats)
}

fn collect_blob_stats(read: &ReadTransaction) -> anyhow::Result<BlobStats> {
    let mut stats = BlobStats::default();
    for item in read
        .open_table(BLOB_INDEX)
        .context("open blob index")?
        .iter()
        .context("iterate blob index")?
    {
        let (_, value) = item.context("read blob row")?;
        let blob: BlobRecord = serde_json::from_slice(value.value()).context("decode blob row")?;
        stats.count = stats.count.saturating_add(1);
        stats.indexed_bytes = stats.indexed_bytes.saturating_add(blob.size);
    }
    Ok(stats)
}

fn dir_size(path: &Path) -> anyhow::Result<u64> {
    let mut total = 0_u64;
    if !path.exists() {
        return Ok(total);
    }
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
        let metadata = entry
            .metadata()
            .with_context(|| format!("read metadata for {}", entry.path().display()))?;
        if metadata.is_dir() {
            total = total.saturating_add(dir_size(&entry.path())?);
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn device_key(vault_id: &str, device_id: &str) -> String {
    format!("{vault_id}:{device_id}")
}

fn client_op_key(vault_id: &str, client_op_id: &str) -> String {
    format!("{vault_id}:{client_op_id}")
}

fn op_key(vault_id: &str, seq: u64) -> String {
    format!("{vault_id}:{seq:020}")
}

fn blob_key(vault_id: &str, blob_id: &str) -> String {
    format!("{vault_id}:{blob_id}")
}

fn snapshot_key(vault_id: &str, snapshot_id: &str) -> String {
    format!("{vault_id}:{snapshot_id}")
}

#[cfg(test)]
mod tests {
    use super::{EncryptedOpRecord, LEGACY_FORMAT, SnapshotRecord, Storage};
    use std::{fs, path::PathBuf};

    #[test]
    fn create_vault_creates_vault_and_first_pairing_token() {
        let storage = test_storage();

        let vault = storage.create_vault("test vault").expect("create vault");
        let vaults = storage.list_vaults().expect("list vaults");
        let device = storage
            .register_first_device(&vault.pairing_token, "laptop", &"a".repeat(64))
            .expect("register first device");

        assert_eq!(vault.name, "test vault");
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].id, vault.id);
        assert_eq!(device.vault_id, vault.id);
    }

    #[test]
    fn create_vault_rejects_blank_and_duplicate_names() {
        let storage = test_storage();

        assert!(storage.create_vault(" ").is_err());
        storage.create_vault("Notes").expect("create vault");
        assert!(storage.create_vault("notes").is_err());
    }

    #[test]
    fn issue_pairing_token_rejects_missing_vaults_and_creates_usable_tokens() {
        let storage = test_storage();

        assert!(storage.issue_pairing_token("missing").is_err());

        let vault = storage.create_vault("test vault").expect("create vault");
        let token = storage
            .issue_pairing_token(&vault.id)
            .expect("issue pairing token");
        let device = storage
            .register_first_device(&token.token, "phone", &"b".repeat(64))
            .expect("register issued token");

        assert_eq!(token.vault_id, vault.id);
        assert_eq!(device.vault_id, vault.id);
    }

    #[test]
    fn register_first_device_consumes_tokens_exactly_once() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");

        storage
            .register_first_device(&vault.pairing_token, "laptop", &"c".repeat(64))
            .expect("register first device");

        assert!(
            storage
                .register_first_device(&vault.pairing_token, "phone", &"d".repeat(64))
                .is_err()
        );
    }

    #[test]
    fn register_first_device_rejects_pairing_token_when_vault_already_has_a_device() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");
        storage
            .register_first_device(&vault.pairing_token, "laptop", &"c".repeat(64))
            .expect("register first device");
        let second_token = storage
            .issue_pairing_token(&vault.id)
            .expect("issue second pairing token");

        let error = storage
            .register_first_device(&second_token.token, "phone", &"d".repeat(64))
            .expect_err("second pair-token registration must be rejected");

        assert!(error.to_string().contains("Request"));
    }

    #[test]
    fn register_authorized_device_rejects_missing_vaults_and_adds_device() {
        let storage = test_storage();

        assert!(
            storage
                .register_authorized_device("missing", "phone", &"e".repeat(64), 16)
                .is_err()
        );

        let vault = storage.create_vault("test vault").expect("create vault");
        let device = storage
            .register_authorized_device(&vault.id, "phone", &"f".repeat(64), 16)
            .expect("register authorized device");
        let devices = storage.list_devices(&vault.id).expect("list devices");

        assert_eq!(device.vault_id, vault.id);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, device.device_id);
    }

    #[test]
    fn register_authorized_device_rejects_when_active_device_limit_is_reached() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");
        let first = storage
            .register_first_device(&vault.pairing_token, "laptop", &"1".repeat(64))
            .expect("register first device");

        assert!(
            storage
                .register_authorized_device(&vault.id, "phone", &"2".repeat(64), 1)
                .is_err()
        );

        storage
            .revoke_device(&vault.id, &first.device_id)
            .expect("revoke first device");
        storage
            .register_authorized_device(&vault.id, "phone", &"3".repeat(64), 1)
            .expect("register after revoke");
    }

    #[test]
    fn append_op_is_idempotent_by_vault_and_client_op_id() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");

        let first = append(&storage, &vault.id, "op-a");
        let second = append(&storage, &vault.id, "op-a");
        let next = append(&storage, &vault.id, "op-b");
        let ops = storage.list_ops_after(&vault.id, 0, 10).expect("list ops");

        assert_eq!(first.op.server_seq, 1);
        assert!(first.inserted);
        assert_eq!(second.op.server_seq, first.op.server_seq);
        assert!(!second.inserted);
        assert_eq!(next.op.server_seq, 2);
        assert!(next.inserted);
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn prune_snapshots_keeps_configured_newest_snapshots() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");
        for seq in 1..=5 {
            storage
                .put_snapshot(test_snapshot(&vault.id, seq))
                .expect("put snapshot");
        }

        storage
            .prune_snapshots(&vault.id, 2)
            .expect("prune snapshots");

        let snapshots = storage.list_snapshots(&vault.id).expect("list snapshots");
        let seqs = snapshots
            .iter()
            .map(|snapshot| snapshot.covers_through_seq)
            .collect::<Vec<_>>();
        assert_eq!(seqs, vec![4, 5]);
    }

    #[test]
    fn prune_snapshots_with_zero_retain_removes_all_snapshots() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");
        for seq in 1..=3 {
            storage
                .put_snapshot(test_snapshot(&vault.id, seq))
                .expect("put snapshot");
        }

        storage
            .prune_snapshots(&vault.id, 0)
            .expect("prune snapshots");

        assert!(
            storage
                .list_snapshots(&vault.id)
                .expect("list snapshots")
                .is_empty()
        );
    }

    #[test]
    fn put_blob_with_vault_limit_rejects_when_vault_quota_is_exceeded() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");

        storage
            .put_blob_with_vault_limit(&vault.id, "blob-a", b"1234", 6)
            .expect("first blob fits");

        assert!(
            storage
                .put_blob_with_vault_limit(&vault.id, "blob-b", b"123", 6)
                .is_err()
        );
    }

    #[test]
    fn put_blob_with_vault_limit_counts_overwrites_as_replacements() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");

        storage
            .put_blob_with_vault_limit(&vault.id, "blob-a", b"1234", 4)
            .expect("initial blob fits");
        storage
            .put_blob_with_vault_limit(&vault.id, "blob-a", b"12", 4)
            .expect("smaller replacement fits");
        storage
            .put_blob_with_vault_limit(&vault.id, "blob-b", b"12", 4)
            .expect("remaining quota is available after replacement");
    }

    #[test]
    fn stats_reports_counts_and_storage_size() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");
        let device = storage
            .register_first_device(&vault.pairing_token, "laptop", &"1".repeat(64))
            .expect("register first device");
        storage
            .revoke_device(&vault.id, &device.device_id)
            .expect("revoke device");
        storage
            .issue_pairing_token(&vault.id)
            .expect("issue active pairing token");
        append(&storage, &vault.id, "op-a");
        storage
            .put_blob_with_vault_limit(&vault.id, "blob-a", b"1234", 1024)
            .expect("put blob");
        storage
            .put_snapshot(test_snapshot(&vault.id, 1))
            .expect("put snapshot");

        let stats = storage.stats().expect("read stats");

        assert_eq!(stats.vault_count, 1);
        assert_eq!(stats.device_count, 1);
        assert_eq!(stats.active_device_count, 0);
        assert_eq!(stats.revoked_device_count, 1);
        assert_eq!(stats.pairing_token_count, 2);
        assert_eq!(stats.active_pairing_token_count, 1);
        assert_eq!(stats.consumed_pairing_token_count, 1);
        assert_eq!(stats.expired_pairing_token_count, 0);
        assert_eq!(stats.op_count, 1);
        assert_eq!(stats.blob_count, 1);
        assert_eq!(stats.indexed_blob_bytes, 4);
        assert_eq!(stats.snapshot_count, 1);
        assert_eq!(stats.blob_file_bytes, 4);
        assert!(stats.database_bytes > 0);
        assert!(stats.total_storage_bytes >= stats.database_bytes + stats.blob_file_bytes);
        assert_eq!(stats.data_dir, storage.data_dir.display().to_string());
    }

    #[test]
    fn delete_vault_removes_all_per_vault_state_and_blob_files() {
        let storage = test_storage();
        let kept = storage.create_vault("kept").expect("create kept vault");
        let doomed = storage.create_vault("doomed").expect("create doomed vault");
        storage
            .register_first_device(&doomed.pairing_token, "laptop", &"1".repeat(64))
            .expect("register first device");
        storage
            .issue_pairing_token(&doomed.id)
            .expect("issue extra token");
        append(&storage, &doomed.id, "op-a");
        storage
            .put_blob_with_vault_limit(&doomed.id, "blob-a", b"1234", 1024)
            .expect("put blob");
        storage
            .put_snapshot(test_snapshot(&doomed.id, 1))
            .expect("put snapshot");

        storage.delete_vault(&doomed.id).expect("delete vault");

        let vaults = storage.list_vaults().expect("list vaults");
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].id, kept.id);
        assert!(
            storage
                .list_devices(&doomed.id)
                .expect("list devices")
                .is_empty()
        );
        assert!(
            storage
                .list_ops_after(&doomed.id, 0, 100)
                .expect("list ops")
                .is_empty()
        );
        assert!(
            storage
                .list_snapshots(&doomed.id)
                .expect("list snapshots")
                .is_empty()
        );
        assert!(storage.delete_vault(&doomed.id).is_err());
        assert!(
            storage
                .register_first_device(&doomed.pairing_token, "phone", &"2".repeat(64))
                .is_err(),
            "old pairing tokens for the deleted vault must no longer resolve"
        );
    }

    #[test]
    fn open_upgrades_v2_format_database_in_place() {
        let dir = unique_temp_dir();
        let db_path = dir.join("mylonite.redb");
        {
            let vaults: redb2::TableDefinition<'_, &str, &[u8]> =
                redb2::TableDefinition::new("vaults");
            let record = super::VaultRecord {
                id: "v-legacy".to_string(),
                name: "legacy vault".to_string(),
                created_at_unix: 0,
                revoked_at_unix: None,
                current_seq: 0,
                format: LEGACY_FORMAT,
                upgrade_seq: 0,
                upgrade_base: 0,
                blob_bytes: None,
            };
            let db = redb2::Database::create(&db_path).expect("create v2 database");
            let write = db.begin_write().expect("begin v2 write");
            {
                let mut table = write.open_table(vaults).expect("open v2 vaults table");
                table
                    .insert(
                        "v-legacy",
                        serde_json::to_vec(&record)
                            .expect("encode vault")
                            .as_slice(),
                    )
                    .expect("insert v2 vault row");
            }
            write.commit().expect("commit v2 write");
        }

        let storage = Storage::open(&dir).expect("open storage over v2 database");
        let vaults = storage.list_vaults().expect("list vaults");

        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].id, "v-legacy");
        assert_eq!(vaults[0].name, "legacy vault");
    }

    fn append(storage: &Storage, vault_id: &str, client_op_id: &str) -> super::AppendedOp {
        storage
            .append_ops(
                vault_id,
                super::CURRENT_FORMAT,
                vec![test_op(vault_id, client_op_id)],
            )
            .expect("append op")
            .remove(0)
    }

    fn test_storage() -> Storage {
        let dir = unique_temp_dir();
        Storage::open(&dir).expect("open storage")
    }

    fn unique_temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mylonite-storage-test-{}-{}",
            std::process::id(),
            super::random_hex(8)
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn test_op(vault_id: &str, client_op_id: &str) -> EncryptedOpRecord {
        EncryptedOpRecord {
            vault_id: vault_id.to_string(),
            server_seq: 0,
            client_op_id: client_op_id.to_string(),
            device_id: "device-a".to_string(),
            lamport: 1,
            kind: 1,
            key_version: 1,
            nonce_hex: "00".repeat(24),
            ciphertext_hex: "11".repeat(32),
            accepted_at_unix: 0,
        }
    }

    fn test_snapshot(vault_id: &str, covers_through_seq: u64) -> SnapshotRecord {
        SnapshotRecord {
            vault_id: vault_id.to_string(),
            snapshot_id: format!("snapshot-{covers_through_seq}"),
            device_id: "device-a".to_string(),
            covers_through_seq,
            key_version: 1,
            nonce_hex: "00".repeat(24),
            ciphertext_hex: "11".repeat(32),
            created_at_unix: 0,
        }
    }
}
