use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use rand::RngCore;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const VAULTS: TableDefinition<&str, &[u8]> = TableDefinition::new("vaults");
const DEVICES: TableDefinition<&str, &[u8]> = TableDefinition::new("devices");
const PAIRING_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("pairing_tokens");
const OPLOG: TableDefinition<&str, &[u8]> = TableDefinition::new("oplog");
const CLIENT_OPS: TableDefinition<&str, u64> = TableDefinition::new("client_ops");
const BLOB_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("blob_index");
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");

#[derive(Debug, Clone)]
pub struct Storage {
    db: Arc<Database>,
    data_dir: Arc<PathBuf>,
}

#[derive(Debug, Clone)]
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
pub struct AppendOpResult {
    pub server_seq: u64,
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

#[derive(Debug, Clone)]
pub struct StorageStats {
    pub vault_count: u64,
}

impl Storage {
    pub fn open(data_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(data_dir).with_context(|| format!("create {}", data_dir.display()))?;
        fs::create_dir_all(data_dir.join("blobs"))
            .with_context(|| format!("create {}", data_dir.join("blobs").display()))?;
        let db = Database::create(data_dir.join("mylonite.redb")).context("open redb database")?;
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
        let vault = CreatedVault {
            id: id.clone(),
            name: name.clone(),
            created_at_unix: now,
            pairing_token: pairing_token.clone(),
        };
        let record = VaultRecord {
            id: id.clone(),
            name,
            created_at_unix: now,
            revoked_at_unix: None,
            current_seq: 0,
        };
        let token = PairingTokenRecord {
            token: pairing_token.clone(),
            vault_id: id,
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
        Ok(vault)
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

    pub fn issue_pairing_token(&self, vault_id: &str) -> anyhow::Result<PairingTokenRecord> {
        let now = now_unix()?;
        let read = self.db.begin_read().context("begin read")?;
        {
            let vaults = read.open_table(VAULTS).context("open vault table")?;
            if vaults.get(vault_id).context("read vault")?.is_none() {
                bail!("vault not found");
            }
        }
        drop(read);

        let token = PairingTokenRecord {
            token: format!("p{}", random_hex(24)),
            vault_id: vault_id.to_string(),
            expires_at_unix: now + 15 * 60,
            consumed_at_unix: None,
        };
        let write = self.db.begin_write().context("begin write")?;
        {
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
            let Some(stored) = tokens.get(token).context("read pairing token")? else {
                bail!("pairing token not found");
            };
            let stored_bytes = stored.value().to_vec();
            drop(stored);
            let mut token_record: PairingTokenRecord =
                serde_json::from_slice(&stored_bytes).context("decode pairing token")?;
            if token_record.consumed_at_unix.is_some() {
                bail!("pairing token already consumed");
            }
            if token_record.expires_at_unix < now {
                bail!("pairing token expired");
            }
            token_record.consumed_at_unix = Some(now);
            write_json(&mut tokens, token, &token_record)?;

            DeviceRecord {
                vault_id: token_record.vault_id,
                device_id: format!("d{}", random_hex(16)),
                label: label.to_string(),
                verifying_key: verifying_key.to_string(),
                created_at_unix: now,
                revoked_at_unix: None,
                last_seen_at_unix: None,
            }
        };
        {
            let mut devices = write.open_table(DEVICES).context("open device table")?;
            write_json(
                &mut devices,
                device_key(&device.vault_id, &device.device_id),
                &device,
            )?;
        }
        write.commit().context("commit device")?;
        Ok(device)
    }

    pub fn register_authorized_device_with_limit(
        &self,
        vault_id: &str,
        label: &str,
        verifying_key: &str,
        max_active_devices: usize,
    ) -> anyhow::Result<DeviceRecord> {
        let now = now_unix()?;
        let write = self.db.begin_write().context("begin write")?;
        {
            let vaults = write.open_table(VAULTS).context("open vault table")?;
            if vaults.get(vault_id).context("read vault")?.is_none() {
                bail!("vault not found");
            }
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
        {
            let mut devices = write.open_table(DEVICES).context("open device table")?;
            if active_device_count(&devices, vault_id)? >= max_active_devices {
                bail!("vault device limit reached");
            }
            write_json(
                &mut devices,
                device_key(&device.vault_id, &device.device_id),
                &device,
            )?;
        }
        write.commit().context("commit authorized device")?;
        Ok(device)
    }

    pub fn list_devices(&self, vault_id: &str) -> anyhow::Result<Vec<DeviceRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(DEVICES).context("open device table")?;
        let prefix = format!("{vault_id}:");
        let mut out = Vec::new();
        for item in table.iter().context("iterate devices")? {
            let (key, value) = item.context("read device row")?;
            if key.value().starts_with(&prefix) {
                out.push(serde_json::from_slice(value.value()).context("decode device row")?);
            }
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
        let key = device_key(vault_id, device_id);
        let Some(stored) = table.get(key.as_str()).context("read device")? else {
            bail!("device not found");
        };
        let device: DeviceRecord =
            serde_json::from_slice(stored.value()).context("decode device")?;
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
            let Some(stored) = table.get(key.as_str()).context("read device")? else {
                bail!("device not found");
            };
            let stored_bytes = stored.value().to_vec();
            drop(stored);
            let mut device: DeviceRecord =
                serde_json::from_slice(&stored_bytes).context("decode device")?;
            device.revoked_at_unix = Some(now);
            write_json(&mut table, key, &device)?;
        }
        write.commit().context("commit device revoke")
    }

    pub fn append_op(&self, mut op: EncryptedOpRecord) -> anyhow::Result<AppendOpResult> {
        let write = self.db.begin_write().context("begin write")?;
        let seq = {
            let mut client_ops = write.open_table(CLIENT_OPS).context("open client ops")?;
            let client_key = client_op_key(&op.vault_id, &op.client_op_id);
            if let Some(existing) = client_ops
                .get(client_key.as_str())
                .context("read client op")?
            {
                return Ok(AppendOpResult {
                    server_seq: existing.value(),
                    inserted: false,
                });
            }

            let mut vaults = write.open_table(VAULTS).context("open vault table")?;
            let Some(stored_vault) = vaults.get(op.vault_id.as_str()).context("read vault")? else {
                bail!("vault not found");
            };
            let stored_bytes = stored_vault.value().to_vec();
            drop(stored_vault);
            let mut vault: VaultRecord =
                serde_json::from_slice(&stored_bytes).context("decode vault")?;
            vault.current_seq += 1;
            op.server_seq = vault.current_seq;
            op.accepted_at_unix = now_unix()?;
            write_json(&mut vaults, vault.id.as_str(), &vault)?;
            client_ops
                .insert(client_key.as_str(), op.server_seq)
                .context("insert client op")?;

            let mut oplog = write.open_table(OPLOG).context("open oplog")?;
            write_json(&mut oplog, op_key(&op.vault_id, op.server_seq), &op)?;
            op.server_seq
        };
        write.commit().context("commit op")?;
        Ok(AppendOpResult {
            server_seq: seq,
            inserted: true,
        })
    }

    pub fn list_ops_after(
        &self,
        vault_id: &str,
        after_seq: u64,
        limit: u64,
    ) -> anyhow::Result<Vec<EncryptedOpRecord>> {
        let read = self.db.begin_read().context("begin read")?;
        let table = read.open_table(OPLOG).context("open oplog")?;
        let prefix = format!("{vault_id}:");
        let mut out = Vec::new();
        for item in table.iter().context("iterate oplog")? {
            let (key, value) = item.context("read op row")?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            let op: EncryptedOpRecord =
                serde_json::from_slice(value.value()).context("decode op row")?;
            if op.server_seq > after_seq {
                out.push(op);
            }
            if u64::try_from(out.len()).unwrap_or(u64::MAX) >= limit {
                break;
            }
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
        self.ensure_blob_fits_vault_limit(vault_id, blob_id, bytes, max_vault_size_bytes)?;
        let path = self.blob_path(vault_id, blob_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        let record = BlobRecord {
            vault_id: vault_id.to_string(),
            blob_id: blob_id.to_string(),
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            created_at_unix: now_unix()?,
        };
        let write = self.db.begin_write().context("begin write")?;
        {
            let mut table = write.open_table(BLOB_INDEX).context("open blob index")?;
            write_json(&mut table, blob_key(vault_id, blob_id), &record)?;
        }
        write.commit().context("commit blob")?;
        Ok(record)
    }

    fn ensure_blob_fits_vault_limit(
        &self,
        vault_id: &str,
        blob_id: &str,
        bytes: &[u8],
        max_vault_size_bytes: u64,
    ) -> anyhow::Result<()> {
        let read = self.db.begin_read().context("begin read")?;
        {
            let vaults = read.open_table(VAULTS).context("open vault table")?;
            if vaults.get(vault_id).context("read vault")?.is_none() {
                bail!("vault not found");
            }
        }

        let table = read.open_table(BLOB_INDEX).context("open blob index")?;
        let prefix = format!("{vault_id}:");
        let current_key = blob_key(vault_id, blob_id);
        let mut current_total = 0_u64;
        let mut existing_size = 0_u64;
        for item in table.iter().context("iterate blob index")? {
            let (key, value) = item.context("read blob row")?;
            if !key.value().starts_with(&prefix) {
                continue;
            }
            let record: BlobRecord =
                serde_json::from_slice(value.value()).context("decode blob row")?;
            current_total = current_total.saturating_add(record.size);
            if key.value() == current_key {
                existing_size = record.size;
            }
        }

        let next_total = current_total
            .saturating_sub(existing_size)
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if next_total > max_vault_size_bytes {
            bail!("vault exceeds configured size limit");
        }
        Ok(())
    }

    pub fn get_blob(&self, vault_id: &str, blob_id: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.blob_path(vault_id, blob_id);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(
            fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        ))
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
        let prefix = format!("{vault_id}:");
        let mut out = Vec::new();
        for item in table.iter().context("iterate snapshots")? {
            let (key, value) = item.context("read snapshot row")?;
            if key.value().starts_with(&prefix) {
                out.push(serde_json::from_slice(value.value()).context("decode snapshot row")?);
            }
        }
        out.sort_by_key(|snapshot: &SnapshotRecord| snapshot.covers_through_seq);
        Ok(out)
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
        Ok(StorageStats {
            vault_count: u64::try_from(self.list_vaults()?.len()).unwrap_or(u64::MAX),
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

fn now_unix() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

fn random_hex(byte_len: usize) -> String {
    let mut bytes = vec![0; byte_len];
    rand::rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
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

fn reject_duplicate_vault_name(
    vaults: &redb::Table<'_, &str, &[u8]>,
    name: &str,
) -> anyhow::Result<()> {
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

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn write_json<T: Serialize>(
    table: &mut redb::Table<'_, &str, &[u8]>,
    key: impl AsRef<str>,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value).context("encode json record")?;
    table
        .insert(key.as_ref(), bytes.as_slice())
        .context("insert json record")?;
    Ok(())
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

fn active_device_count(
    devices: &redb::Table<'_, &str, &[u8]>,
    vault_id: &str,
) -> anyhow::Result<usize> {
    let prefix = format!("{vault_id}:");
    let mut count = 0;
    for item in devices.iter().context("iterate devices")? {
        let (key, value) = item.context("read device row")?;
        if key.value().starts_with(&prefix) {
            let device: DeviceRecord =
                serde_json::from_slice(value.value()).context("decode device row")?;
            if device.revoked_at_unix.is_none() {
                count += 1;
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::{EncryptedOpRecord, SnapshotRecord, Storage};
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
    fn register_authorized_device_rejects_missing_vaults_and_adds_device() {
        let storage = test_storage();

        assert!(
            storage
                .register_authorized_device_with_limit("missing", "phone", &"e".repeat(64), 16)
                .is_err()
        );

        let vault = storage.create_vault("test vault").expect("create vault");
        let device = storage
            .register_authorized_device_with_limit(&vault.id, "phone", &"f".repeat(64), 16)
            .expect("register authorized device");
        let devices = storage.list_devices(&vault.id).expect("list devices");

        assert_eq!(device.vault_id, vault.id);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, device.device_id);
    }

    #[test]
    fn register_authorized_device_with_limit_rejects_when_active_device_limit_is_reached() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");
        let first = storage
            .register_first_device(&vault.pairing_token, "laptop", &"1".repeat(64))
            .expect("register first device");

        assert!(
            storage
                .register_authorized_device_with_limit(&vault.id, "phone", &"2".repeat(64), 1)
                .is_err()
        );

        storage
            .revoke_device(&vault.id, &first.device_id)
            .expect("revoke first device");
        storage
            .register_authorized_device_with_limit(&vault.id, "phone", &"3".repeat(64), 1)
            .expect("register after revoke");
    }

    #[test]
    fn append_op_is_idempotent_by_vault_and_client_op_id() {
        let storage = test_storage();
        let vault = storage.create_vault("test vault").expect("create vault");

        let first = storage
            .append_op(test_op(&vault.id, "op-a"))
            .expect("append op");
        let second = storage
            .append_op(test_op(&vault.id, "op-a"))
            .expect("append op again");
        let next = storage
            .append_op(test_op(&vault.id, "op-b"))
            .expect("append next op");
        let ops = storage.list_ops_after(&vault.id, 0, 10).expect("list ops");

        assert_eq!(first.server_seq, 1);
        assert!(first.inserted);
        assert_eq!(second.server_seq, first.server_seq);
        assert!(!second.inserted);
        assert_eq!(next.server_seq, 2);
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
