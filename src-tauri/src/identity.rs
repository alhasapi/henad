//! Long-lived SSH identities.
//!
//! Two ed25519 keypairs are generated on first launch and kept in the app data
//! directory as OpenSSH private key files:
//!
//! * `identity_host` identifies this machine as an SSH server (the pairing code binds it).
//! * `identity_client` authenticates outbound connections (the peer stores its public half).
use russh::keys::{
    key::{parse_public_key, safe_rng},
    ssh_key::{LineEnding, SshSig},
    Algorithm, HashAlg, PrivateKey, PublicKey, PublicKeyBase64,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;

/// Namespace binding signatures to pairing, so they can never be replayed as SSH auth.
pub const SIGN_NAMESPACE: &str = "henad-pairing-v2";

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("could not read or write identity file {0}")]
    Io(#[from] std::io::Error),
    #[error("identity file is corrupt")]
    Corrupt,
    #[error("identity file has the wrong permissions")]
    Permissions,
    #[error("signature failed")]
    Sign,
}

#[derive(Clone)]
pub struct Identity {
    pub device_id: String,
    pub name: String,
    pub host: Arc<PrivateKey>,
    pub client: Arc<PrivateKey>,
}

impl Identity {
    pub fn load_or_create(
        dir: &Path,
        device_id: String,
        name: String,
    ) -> Result<Self, IdentityError> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            device_id,
            name,
            host: Arc::new(load_or_generate(&dir.join("identity_host"))?),
            client: Arc::new(load_or_generate(&dir.join("identity_client"))?),
        })
    }

    pub fn host_public(&self) -> &PublicKey {
        self.host.public_key()
    }

    pub fn client_public(&self) -> &PublicKey {
        self.client.public_key()
    }

    pub fn host_public_bytes(&self) -> Vec<u8> {
        self.host_public().public_key_bytes()
    }

    pub fn client_public_bytes(&self) -> Vec<u8> {
        self.client_public().public_key_bytes()
    }

    pub fn host_fingerprint(&self) -> String {
        crate::core::fingerprint(&self.host_public_bytes())
    }

    /// Sign a pairing transcript hash with the client key.
    pub fn sign(&self, message: &[u8]) -> Result<String, IdentityError> {
        self.client
            .sign(SIGN_NAMESPACE, HashAlg::Sha512, message)
            .and_then(|sig| sig.to_pem(LineEnding::LF))
            .map_err(|_| IdentityError::Sign)
    }
}

/// Verify a pairing signature against a peer's client public key.
pub fn verify(public_key: &[u8], message: &[u8], signature_pem: &str) -> bool {
    let Ok(key) = parse_public_key(public_key) else {
        return false;
    };
    let Ok(sig) = SshSig::from_pem(signature_pem) else {
        return false;
    };
    key.verify(SIGN_NAMESPACE, message, &sig).is_ok()
}

fn load_or_generate(path: &PathBuf) -> Result<PrivateKey, IdentityError> {
    if path.exists() {
        let bytes = fs::read(path)?;
        let key = PrivateKey::from_openssh(&bytes).map_err(|_| IdentityError::Corrupt)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        return Ok(key);
    }

    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
        .map_err(|_| IdentityError::Corrupt)?;
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|_| IdentityError::Corrupt)?;
    write_private(path, pem.as_bytes())?;
    Ok(key)
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "henad-identity-{tag}-{}-{}",
            std::process::id(),
            crate::core::fingerprint(&crate::core::fresh_nonce())
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn keys_are_stable_across_restarts() {
        let dir = temp_dir("stable");
        let first = Identity::load_or_create(&dir, "dev".into(), "Henad".into()).unwrap();
        let second = Identity::load_or_create(&dir, "dev".into(), "Henad".into()).unwrap();
        assert_eq!(first.host_public_bytes(), second.host_public_bytes());
        assert_eq!(first.client_public_bytes(), second.client_public_bytes());
        assert_eq!(first.host_fingerprint(), second.host_fingerprint());
        assert_eq!(first.host_fingerprint().len(), 16);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn signatures_verify_only_with_the_client_key() {
        let dir_a = temp_dir("sign-a");
        let dir_b = temp_dir("sign-b");
        let a = Identity::load_or_create(&dir_a, "a".into(), "A".into()).unwrap();
        let b = Identity::load_or_create(&dir_b, "b".into(), "B".into()).unwrap();
        let message = b"pairing transcript hash";
        let signature = a.sign(message).unwrap();
        assert!(verify(&a.client_public_bytes(), message, &signature));
        assert!(!verify(&b.client_public_bytes(), message, &signature));
        assert!(!verify(&a.client_public_bytes(), b"other", &signature));
        fs::remove_dir_all(&dir_a).ok();
        fs::remove_dir_all(&dir_b).ok();
    }
}
