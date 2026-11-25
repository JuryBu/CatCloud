use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::agreement::{self, ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey};
use ring::hkdf::{self, HKDF_SHA256};
use ring::hmac::{self, HMAC_SHA256};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Host, Url};

use crate::{CatError, CatResult};

/// Fixed 8-byte ASCII magic header for CatCloud E2EE sync envelopes.
pub const ENVELOPE_MAGIC: &[u8; 8] = b"CCSYNC01";
/// `kdf_mode` for direct 256-bit key (QR master key, ECDH session key, relay URL, `.ccsync` file key).
pub const KDF_MODE_RAW_KEY: u8 = 0x01;
/// `kdf_mode` for PBKDF2-HMAC-SHA256 password-derived 256-bit key.
pub const KDF_MODE_PBKDF2_SHA256: u8 = 0x02;
/// Default PBKDF2-HMAC-SHA256 iteration count.
pub const DEFAULT_PBKDF2_ITERS: u32 = 100_000;
/// Minimum accepted PBKDF2 iteration count (also used by cross-platform golden test vectors).
pub const MIN_PBKDF2_ITERS: u32 = 1_000;
/// Maximum accepted PBKDF2 iteration count to defend against CPU DoS.
pub const MAX_PBKDF2_ITERS: u32 = 2_000_000;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const MAX_SID_LEN: usize = 64;
pub const HEADER_FIXED_LEN: usize = 30; // 8(magic) + 1(mode) + 4(iters) + 16(salt) + 1(sid_len)
pub const P256_UNCOMPRESSED_PUB_LEN: usize = 65;
pub const MAX_SYNC_ENVELOPE_BYTES: usize = 17 * 1024 * 1024;

const PIN_HKDF_INFO_PREFIX: &[u8] = b"catcloud-lan-pin-v1:";

/// Parsed non-secret header of a `CCSYNC01` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub kdf_mode: u8,
    pub kdf_iters: u32,
    pub salt: [u8; SALT_LEN],
    pub sid: String,
    pub header_len: usize,
}

/// Secret material accepted by convenience envelope wrappers.
#[derive(Debug, Clone, Copy)]
pub enum SyncSecret<'a> {
    RawKey(&'a [u8; KEY_LEN]),
    Password(&'a str),
}

/// Sync URI role matching `catcloud://sync/v1?role=...`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRole {
    Pull,
    Push,
    RelayUrl,
    FileKey,
}

impl SyncRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::RelayUrl => "relay_url",
            Self::FileKey => "file_key",
        }
    }

    pub fn parse_str(value: &str) -> CatResult<Self> {
        match value {
            "pull" => Ok(Self::Pull),
            "push" => Ok(Self::Push),
            "relay_url" => Ok(Self::RelayUrl),
            "file_key" => Ok(Self::FileKey),
            other => Err(CatError::Validation(format!(
                "unsupported sync role '{other}'"
            ))),
        }
    }
}

/// Parsed representation of `catcloud://sync/v1?<non-secret>#k=<b64url-nopad-32B>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncUri {
    pub role: SyncRole,
    pub endpoint: Option<String>,
    pub hosts: Vec<String>,
    pub port: Option<u16>,
    pub sid: Option<String>,
    pub url: Option<String>,
    pub fingerprint: Option<String>,
    pub key: [u8; KEY_LEN],
}

/// Ephemeral NIST P-256 ECDH keypair (65-byte uncompressed SEC1 public key `0x04||X||Y`).
pub struct EphemeralP256KeyPair {
    private_key: EphemeralPrivateKey,
    public_key_bytes: [u8; P256_UNCOMPRESSED_PUB_LEN],
}

impl std::fmt::Debug for EphemeralP256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralP256KeyPair")
            .field("public_key_b64", &self.public_key_b64())
            .finish_non_exhaustive()
    }
}

impl EphemeralP256KeyPair {
    pub fn generate() -> CatResult<Self> {
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng)
            .map_err(|_| CatError::Security("failed to generate ephemeral P-256 keypair".into()))?;
        let pub_key = private_key
            .compute_public_key()
            .map_err(|_| CatError::Security("failed to compute P-256 public key".into()))?;
        let bytes = pub_key.as_ref();
        if bytes.len() != P256_UNCOMPRESSED_PUB_LEN || bytes[0] != 0x04 {
            return Err(CatError::Security(
                "unexpected P-256 uncompressed public key format".into(),
            ));
        }
        let mut public_key_bytes = [0u8; P256_UNCOMPRESSED_PUB_LEN];
        public_key_bytes.copy_from_slice(bytes);
        Ok(Self {
            private_key,
            public_key_bytes,
        })
    }

    pub fn public_key_bytes(&self) -> &[u8; P256_UNCOMPRESSED_PUB_LEN] {
        &self.public_key_bytes
    }

    pub fn public_key_b64(&self) -> String {
        STANDARD.encode(self.public_key_bytes)
    }

    pub fn derive_session_key(
        self,
        peer_pub_65b: &[u8],
        challenge_bytes: &[u8],
        sid: &str,
    ) -> CatResult<[u8; KEY_LEN]> {
        derive_ecdh_session_key(self, peer_pub_65b, challenge_bytes, sid)
    }
}

struct HkdfKeyLen32;

impl hkdf::KeyType for HkdfKeyLen32 {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

/// Fill a fixed-size byte array with cryptographically secure random bytes.
pub fn generate_random_bytes<const N: usize>() -> CatResult<[u8; N]> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| CatError::Security("CSPRNG failed to generate random bytes".into()))?;
    Ok(out)
}

/// Generate a fresh 256-bit master sync key.
pub fn generate_random_key() -> CatResult<[u8; KEY_LEN]> {
    generate_random_bytes::<KEY_LEN>()
}

/// Generate a 16-char lowercase hex session ID (64 bits of entropy).
pub fn generate_session_id() -> CatResult<String> {
    let bytes = generate_random_bytes::<8>()?;
    Ok(hex::encode(bytes))
}

/// Generate a uniformly distributed 6-digit numeric PIN (`000000`..=`999999`) via rejection sampling.
pub fn generate_pin_6() -> CatResult<String> {
    const MODULO: u32 = 1_000_000;
    const LIMIT: u32 = (u32::MAX / MODULO) * MODULO;
    loop {
        let raw = u32::from_be_bytes(generate_random_bytes::<4>()?);
        if raw < LIMIT {
            return Ok(format!("{:06}", raw % MODULO));
        }
    }
}

/// Decode base64 accepting standard/url-safe with or without padding.
pub fn decode_base64_flex(input: &str) -> CatResult<Vec<u8>> {
    let trimmed = input.trim();
    STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|err| CatError::Validation(format!("invalid base64 payload: {err}")))
}

/// Parse and validate the unencrypted header prefix of a `CCSYNC01` envelope.
pub fn inspect_envelope_header(envelope: &[u8]) -> CatResult<EnvelopeHeader> {
    if envelope.len() > MAX_SYNC_ENVELOPE_BYTES {
        return Err(CatError::Validation(format!(
            "sync envelope exceeds {} byte limit",
            MAX_SYNC_ENVELOPE_BYTES
        )));
    }
    if envelope.len() < HEADER_FIXED_LEN + NONCE_LEN + TAG_LEN {
        return Err(CatError::Validation(
            "sync envelope is truncated before minimum header/tag size".into(),
        ));
    }
    if &envelope[0..8] != ENVELOPE_MAGIC {
        return Err(CatError::Validation(
            "invalid sync envelope magic (expected CCSYNC01)".into(),
        ));
    }

    let kdf_mode = envelope[8];
    let kdf_iters = u32::from_be_bytes([envelope[9], envelope[10], envelope[11], envelope[12]]);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&envelope[13..29]);
    let sid_len = envelope[29] as usize;

    if sid_len > MAX_SID_LEN {
        return Err(CatError::Validation(format!(
            "sync envelope sid length {sid_len} exceeds max {MAX_SID_LEN}"
        )));
    }

    let header_len = HEADER_FIXED_LEN + sid_len;
    if envelope.len() < header_len + NONCE_LEN + TAG_LEN {
        return Err(CatError::Validation(
            "sync envelope truncated inside sid/nonce/tag section".into(),
        ));
    }

    let sid = std::str::from_utf8(&envelope[HEADER_FIXED_LEN..header_len])
        .map_err(|_| CatError::Validation("sync envelope sid is not valid UTF-8".into()))?
        .to_string();

    match kdf_mode {
        KDF_MODE_RAW_KEY => {
            if kdf_iters != 0 || salt != [0u8; SALT_LEN] {
                return Err(CatError::Validation(
                    "kdf_mode=0x01 envelope must have zero kdf_iters and zero salt".into(),
                ));
            }
        }
        KDF_MODE_PBKDF2_SHA256 => {
            if !(MIN_PBKDF2_ITERS..=MAX_PBKDF2_ITERS).contains(&kdf_iters) {
                return Err(CatError::Validation(format!(
                    "PBKDF2 iteration count {kdf_iters} out of allowed range {MIN_PBKDF2_ITERS}..={MAX_PBKDF2_ITERS}"
                )));
            }
        }
        other => {
            return Err(CatError::Validation(format!(
                "unsupported sync envelope kdf_mode 0x{other:02x}"
            )));
        }
    }

    Ok(EnvelopeHeader {
        kdf_mode,
        kdf_iters,
        salt,
        sid,
        header_len,
    })
}

fn validate_sid(sid: &str) -> CatResult<()> {
    if sid.len() > MAX_SID_LEN {
        return Err(CatError::Validation(format!(
            "sync sid length {} exceeds max {MAX_SID_LEN}",
            sid.len()
        )));
    }
    Ok(())
}

fn seal_inner(
    plaintext: &[u8],
    key32: &[u8; KEY_LEN],
    kdf_mode: u8,
    kdf_iters: u32,
    salt: &[u8; SALT_LEN],
    sid: &str,
    nonce_bytes: &[u8; NONCE_LEN],
) -> CatResult<Vec<u8>> {
    validate_sid(sid)?;
    let sid_bytes = sid.as_bytes();
    let header_len = HEADER_FIXED_LEN + sid_bytes.len();
    let total_len = header_len + NONCE_LEN + plaintext.len() + TAG_LEN;
    if total_len > MAX_SYNC_ENVELOPE_BYTES {
        return Err(CatError::Validation(format!(
            "sync envelope size {total_len} exceeds {} byte limit",
            MAX_SYNC_ENVELOPE_BYTES
        )));
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.push(kdf_mode);
    out.extend_from_slice(&kdf_iters.to_be_bytes());
    out.extend_from_slice(salt);
    out.push(sid_bytes.len() as u8);
    out.extend_from_slice(sid_bytes);
    debug_assert_eq!(out.len(), header_len);

    let aad_bytes = out.clone();
    out.extend_from_slice(nonce_bytes);

    let mut in_out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    in_out.extend_from_slice(plaintext);

    let unbound = UnboundKey::new(&AES_256_GCM, key32)
        .map_err(|_| CatError::Security("failed to initialize AES-256-GCM key".into()))?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);
    less_safe
        .seal_in_place_append_tag(nonce, Aad::from(&aad_bytes), &mut in_out)
        .map_err(|_| CatError::Security("AES-256-GCM encryption failed".into()))?;

    out.extend_from_slice(&in_out);
    Ok(out)
}

fn open_inner(envelope: &[u8], header: &EnvelopeHeader, key32: &[u8; KEY_LEN]) -> CatResult<Vec<u8>> {
    let aad = &envelope[0..header.header_len];
    let nonce_start = header.header_len;
    let nonce_end = nonce_start + NONCE_LEN;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&envelope[nonce_start..nonce_end]);

    let mut in_out = envelope[nonce_end..].to_vec();
    let unbound = UnboundKey::new(&AES_256_GCM, key32)
        .map_err(|_| CatError::Security("failed to initialize AES-256-GCM key".into()))?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plaintext = less_safe
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .map_err(|_| {
            CatError::Security("sync envelope decryption/authentication failed".into())
        })?;
    Ok(plaintext.to_vec())
}

/// Encrypt payload into a `CCSYNC01` envelope using a direct 256-bit key (`kdf_mode = 0x01`)
/// with a fresh CSPRNG 96-bit nonce.
pub fn seal_with_key(plaintext: &[u8], key32: &[u8; KEY_LEN], sid: &str) -> CatResult<Vec<u8>> {
    let nonce = generate_random_bytes::<NONCE_LEN>()?;
    seal_with_key_and_nonce(plaintext, key32, sid, &nonce)
}

/// Deterministic `kdf_mode = 0x01` encryption with explicit 96-bit nonce (for golden test vectors).
pub fn seal_with_key_and_nonce(
    plaintext: &[u8],
    key32: &[u8; KEY_LEN],
    sid: &str,
    nonce: &[u8; NONCE_LEN],
) -> CatResult<Vec<u8>> {
    seal_inner(
        plaintext,
        key32,
        KDF_MODE_RAW_KEY,
        0,
        &[0u8; SALT_LEN],
        sid,
        nonce,
    )
}

/// Decrypt a `kdf_mode = 0x01` `CCSYNC01` envelope using a direct 256-bit key.
pub fn open_with_key(envelope: &[u8], key32: &[u8; KEY_LEN]) -> CatResult<Vec<u8>> {
    let header = inspect_envelope_header(envelope)?;
    if header.kdf_mode != KDF_MODE_RAW_KEY {
        return Err(CatError::Validation(format!(
            "expected kdf_mode=0x01 envelope, got 0x{:02x}",
            header.kdf_mode
        )));
    }
    open_inner(envelope, &header, key32)
}

/// Decrypt a `kdf_mode = 0x01` envelope and assert its authenticated `sid` matches `expected_sid`.
pub fn open_with_key_expect_sid(
    envelope: &[u8],
    key32: &[u8; KEY_LEN],
    expected_sid: &str,
) -> CatResult<Vec<u8>> {
    let header = inspect_envelope_header(envelope)?;
    if header.kdf_mode != KDF_MODE_RAW_KEY {
        return Err(CatError::Validation(format!(
            "expected kdf_mode=0x01 envelope, got 0x{:02x}",
            header.kdf_mode
        )));
    }
    if header.sid != expected_sid {
        return Err(CatError::Security(
            "sync envelope session ID mismatch".into(),
        ));
    }
    open_inner(envelope, &header, key32)
}

fn derive_pbkdf2_key(password: &str, salt: &[u8; SALT_LEN], iters: u32) -> CatResult<[u8; KEY_LEN]> {
    if password.is_empty() {
        return Err(CatError::Validation(
            "sync password must not be empty".into(),
        ));
    }
    if !(MIN_PBKDF2_ITERS..=MAX_PBKDF2_ITERS).contains(&iters) {
        return Err(CatError::Validation(format!(
            "PBKDF2 iteration count {iters} out of allowed range {MIN_PBKDF2_ITERS}..={MAX_PBKDF2_ITERS}"
        )));
    }
    let nz = NonZeroU32::new(iters)
        .ok_or_else(|| CatError::Validation("PBKDF2 iteration count must be non-zero".into()))?;
    let mut derived = [0u8; KEY_LEN];
    pbkdf2::derive(PBKDF2_HMAC_SHA256, nz, salt, password.as_bytes(), &mut derived);
    Ok(derived)
}

/// Encrypt payload into a `CCSYNC01` envelope using `PBKDF2-HMAC-SHA256` (`kdf_mode = 0x02`).
/// Passing `iters == 0` uses `DEFAULT_PBKDF2_ITERS` (`100_000`).
pub fn seal_with_password(
    plaintext: &[u8],
    password: &str,
    sid: &str,
    iters: u32,
) -> CatResult<Vec<u8>> {
    let resolved_iters = if iters == 0 {
        DEFAULT_PBKDF2_ITERS
    } else {
        iters
    };
    let salt = generate_random_bytes::<SALT_LEN>()?;
    let nonce = generate_random_bytes::<NONCE_LEN>()?;
    seal_with_password_deterministic(plaintext, password, sid, resolved_iters, &salt, &nonce)
}

/// Deterministic `kdf_mode = 0x02` encryption with explicit salt and nonce (for golden test vectors).
pub fn seal_with_password_deterministic(
    plaintext: &[u8],
    password: &str,
    sid: &str,
    iters: u32,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> CatResult<Vec<u8>> {
    let key32 = derive_pbkdf2_key(password, salt, iters)?;
    seal_inner(
        plaintext,
        &key32,
        KDF_MODE_PBKDF2_SHA256,
        iters,
        salt,
        sid,
        nonce,
    )
}

/// Decrypt a `kdf_mode = 0x02` `CCSYNC01` envelope using a UTF-8 password.
pub fn open_with_password(envelope: &[u8], password: &str) -> CatResult<Vec<u8>> {
    let header = inspect_envelope_header(envelope)?;
    if header.kdf_mode != KDF_MODE_PBKDF2_SHA256 {
        return Err(CatError::Validation(format!(
            "expected kdf_mode=0x02 envelope, got 0x{:02x}",
            header.kdf_mode
        )));
    }
    let key32 = derive_pbkdf2_key(password, &header.salt, header.kdf_iters)?;
    open_inner(envelope, &header, &key32)
}

/// Convenience dispatcher matching Plan 6.1 `seal_sync_envelope`.
pub fn seal_sync_envelope(
    zip_bytes: &[u8],
    secret: SyncSecret<'_>,
    sid: &str,
) -> CatResult<Vec<u8>> {
    match secret {
        SyncSecret::RawKey(key) => seal_with_key(zip_bytes, key, sid),
        SyncSecret::Password(pass) => seal_with_password(zip_bytes, pass, sid, DEFAULT_PBKDF2_ITERS),
    }
}

/// Convenience dispatcher matching Plan 6.1 `open_sync_envelope`.
/// If `expected_sid` is `Some(s)`, verifies the authenticated envelope header `sid` equals `s`.
pub fn open_sync_envelope(
    envelope: &[u8],
    secret: SyncSecret<'_>,
    expected_sid: Option<&str>,
) -> CatResult<Vec<u8>> {
    let header = inspect_envelope_header(envelope)?;
    if let Some(expected) = expected_sid
        && header.sid != expected
    {
        return Err(CatError::Security(
            "sync envelope session ID mismatch".into(),
        ));
    }
    match secret {
        SyncSecret::RawKey(key) => {
            if header.kdf_mode != KDF_MODE_RAW_KEY {
                return Err(CatError::Validation(format!(
                    "expected kdf_mode=0x01 envelope, got 0x{:02x}",
                    header.kdf_mode
                )));
            }
            open_inner(envelope, &header, key)
        }
        SyncSecret::Password(pass) => {
            if header.kdf_mode != KDF_MODE_PBKDF2_SHA256 {
                return Err(CatError::Validation(format!(
                    "expected kdf_mode=0x02 envelope, got 0x{:02x}",
                    header.kdf_mode
                )));
            }
            let key32 = derive_pbkdf2_key(pass, &header.salt, header.kdf_iters)?;
            open_inner(envelope, &header, &key32)
        }
    }
}

/// Compute 64-char lowercase hex `HMAC-SHA256(key32, "{sid}:{method}:{path}")`.
pub fn compute_auth_mac(key32: &[u8; KEY_LEN], sid: &str, method: &str, path: &str) -> String {
    let key = hmac::Key::new(HMAC_SHA256, key32);
    let message = format!("{sid}:{method}:{path}");
    let tag = hmac::sign(&key, message.as_bytes());
    hex::encode(tag.as_ref())
}

/// Constant-time verification of `X-CatCloud-Auth` HMAC header.
pub fn verify_auth_mac(
    key32: &[u8; KEY_LEN],
    sid: &str,
    method: &str,
    path: &str,
    candidate_hex: &str,
) -> bool {
    let trimmed = candidate_hex.trim();
    if trimmed.len() != 64 {
        return false;
    }
    let Ok(candidate_bytes) = hex::decode(trimmed) else {
        return false;
    };
    let key = hmac::Key::new(HMAC_SHA256, key32);
    let message = format!("{sid}:{method}:{path}");
    hmac::verify(&key, message.as_bytes(), &candidate_bytes).is_ok()
}

/// Compute 64-char lowercase hex PIN proof:
/// `HMAC-SHA256(pin.as_bytes(), "{sid}:{challenge_b64}:{server_pub_b64}:{client_pub_b64}")`.
pub fn compute_pin_proof(
    pin: &str,
    sid: &str,
    challenge_b64: &str,
    server_pub_b64: &str,
    client_pub_b64: &str,
) -> String {
    let key = hmac::Key::new(HMAC_SHA256, pin.as_bytes());
    let message = format!("{sid}:{challenge_b64}:{server_pub_b64}:{client_pub_b64}");
    let tag = hmac::sign(&key, message.as_bytes());
    hex::encode(tag.as_ref())
}

/// Constant-time verification of a client's PIN handshake proof.
pub fn verify_pin_proof(
    pin: &str,
    sid: &str,
    challenge_b64: &str,
    server_pub_b64: &str,
    client_pub_b64: &str,
    candidate_hex: &str,
) -> bool {
    let trimmed = candidate_hex.trim();
    if trimmed.len() != 64 {
        return false;
    }
    let Ok(candidate_bytes) = hex::decode(trimmed) else {
        return false;
    };
    let key = hmac::Key::new(HMAC_SHA256, pin.as_bytes());
    let message = format!("{sid}:{challenge_b64}:{server_pub_b64}:{client_pub_b64}");
    hmac::verify(&key, message.as_bytes(), &candidate_bytes).is_ok()
}

/// Derive a 32-byte session key from an ephemeral P-256 ECDH exchange:
/// `HKDF-SHA256(salt = challenge_bytes, ikm = shared_secret, info = b"catcloud-lan-pin-v1:" || sid)`.
pub fn derive_ecdh_session_key(
    my_priv: EphemeralP256KeyPair,
    peer_pub_65b: &[u8],
    challenge_bytes: &[u8],
    sid: &str,
) -> CatResult<[u8; KEY_LEN]> {
    if peer_pub_65b.len() != P256_UNCOMPRESSED_PUB_LEN || peer_pub_65b[0] != 0x04 {
        return Err(CatError::Validation(
            "peer P-256 public key must be 65-byte uncompressed SEC1 (0x04||X||Y)".into(),
        ));
    }
    if challenge_bytes.is_empty() {
        return Err(CatError::Validation(
            "ECDH HKDF challenge salt must not be empty".into(),
        ));
    }
    validate_sid(sid)?;

    let peer_pub = UnparsedPublicKey::new(&ECDH_P256, peer_pub_65b);
    agreement::agree_ephemeral(my_priv.private_key, &peer_pub, |shared_secret| {
        let salt = hkdf::Salt::new(HKDF_SHA256, challenge_bytes);
        let prk = salt.extract(shared_secret);
        let info = [PIN_HKDF_INFO_PREFIX, sid.as_bytes()];
        let okm = prk
            .expand(&info, HkdfKeyLen32)
            .map_err(|_| CatError::Security("HKDF-SHA256 expand failed".into()))?;
        let mut session_key = [0u8; KEY_LEN];
        okm.fill(&mut session_key)
            .map_err(|_| CatError::Security("HKDF-SHA256 output fill failed".into()))?;
        Ok(session_key)
    })
    .map_err(|_| CatError::Security("ECDH P-256 key agreement failed".into()))?
}

/// Compute 16-char lowercase hex plaintext fingerprint `hex(SHA-256(zip_bytes))[0..16]`.
pub fn plaintext_fingerprint(zip_bytes: &[u8]) -> String {
    let digest = Sha256::digest(zip_bytes);
    let full = hex::encode(digest);
    full[..16].to_string()
}

/// Returns `true` if `ip` must be blocked for public `relay_url` fetches (SSRF defense).
pub fn is_forbidden_relay_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_relay_ipv4(v4),
        IpAddr::V6(v6) => is_forbidden_relay_ipv6(v6),
    }
}

fn is_forbidden_relay_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_multicast()
        || v4.is_unspecified()
        || o[0] == 0 // 0.0.0.0/8 ("this network")
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT / Tailscale
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // RFC 6890 IETF protocol assignments (/24)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking / Fake-IP TUN
        || o[0] >= 240 // 240.0.0.0/4 reserved
}

fn is_forbidden_relay_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_forbidden_relay_ipv4(mapped);
    }
    let segs = v6.segments();
    // IPv4-compatible ::w.x.y.z (deprecated)
    if segs[0..6] == [0, 0, 0, 0, 0, 0] {
        return true;
    }
    // NAT64 well-known prefix 64:ff9b::/96
    if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6] == [0, 0, 0, 0] {
        let embedded = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xff) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xff) as u8,
        );
        return is_forbidden_relay_ipv4(embedded);
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (segs[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local
        || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-Local
        || (segs[0] & 0xffc0) == 0xfec0 // fec0::/10 deprecated site-local
        || (segs[0] == 0x2001 && segs[1] == 0x0db8) // 2001:db8::/32 documentation
}

/// Validate a `relay_url` target strictly enforcing `https://` and blocking SSRF targets.
pub fn validate_relay_url(raw_url: &str) -> CatResult<Url> {
    let trimmed = raw_url.trim();
    let parsed = Url::parse(trimmed)
        .map_err(|err| CatError::Validation(format!("invalid relay_url '{trimmed}': {err}")))?;
    if parsed.scheme() != "https" {
        return Err(CatError::Security(
            "relay_url must use https:// scheme".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CatError::Security(
            "relay_url must not contain embedded userinfo credentials".into(),
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| CatError::Validation("relay_url is missing host".into()))?;
    match host {
        Host::Ipv4(v4) => {
            if is_forbidden_relay_ipv4(v4) {
                return Err(CatError::Security(format!(
                    "relay_url target IP {v4} is blocked by SSRF policy"
                )));
            }
        }
        Host::Ipv6(v6) => {
            if is_forbidden_relay_ipv6(v6) {
                return Err(CatError::Security(format!(
                    "relay_url target IPv6 {v6} is blocked by SSRF policy"
                )));
            }
        }
        Host::Domain(domain) => {
            let lower = domain.trim_end_matches('.').to_ascii_lowercase();
            if lower.is_empty()
                || lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || lower.ends_with(".lan")
                || lower.ends_with(".home.arpa")
                || lower == "metadata.google.internal"
                || lower.chars().all(|c| c.is_ascii_digit())
                || lower.starts_with("0x")
            {
                return Err(CatError::Security(format!(
                    "relay_url host '{domain}' is blocked by SSRF policy"
                )));
            }
            if let Ok(ip) = lower.parse::<IpAddr>()
                && is_forbidden_relay_ip(ip)
            {
                return Err(CatError::Security(format!(
                    "relay_url IP '{domain}' is blocked by SSRF policy"
                )));
            }
        }
    }
    Ok(parsed)
}

fn is_cleartext_allowed_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64) // 100.64.0.0/10 CGNAT / Tailscale
}

fn is_cleartext_allowed_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_cleartext_allowed_ipv4(mapped);
    }
    let segs = v6.segments();
    v6.is_loopback()
        || (segs[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local (ULA)
        || (segs[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-Local
}

fn is_cleartext_allowed_endpoint_host(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(v4) => is_cleartext_allowed_ipv4(*v4),
        Host::Ipv6(v6) => is_cleartext_allowed_ipv6(*v6),
        Host::Domain(domain) => {
            let lower = domain.trim_end_matches('.').to_ascii_lowercase();
            lower == "localhost"
                || lower.ends_with(".localhost")
                || lower.ends_with(".local")
                || lower.ends_with(".lan")
        }
    }
}

fn validate_endpoint_url(raw_url: &str) -> CatResult<Url> {
    let trimmed = raw_url.trim();
    let parsed = Url::parse(trimmed)
        .map_err(|err| CatError::Validation(format!("invalid sync endpoint '{trimmed}': {err}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CatError::Security(
            "sync endpoint must not contain embedded userinfo credentials".into(),
        ));
    }
    let host = parsed
        .host()
        .ok_or_else(|| CatError::Validation("sync endpoint is missing host".into()))?;
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" => {
            if !is_cleartext_allowed_endpoint_host(&host) {
                return Err(CatError::Security(format!(
                    "public sync endpoint '{host}' must use https:// (cleartext http:// is restricted to loopback/LAN/link-local/CGNAT hosts)"
                )));
            }
            Ok(parsed)
        }
        other => Err(CatError::Validation(format!(
            "sync endpoint scheme '{other}' must be http or https"
        ))),
    }
}

fn validate_host_token(host: &str) -> CatResult<String> {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(CatError::Validation("invalid sync host entry".into()));
    }
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '@' | ',' | '\\'))
    {
        return Err(CatError::Validation(format!(
            "sync host '{trimmed}' contains illegal characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn normalize_fingerprint(fp: &str) -> CatResult<String> {
    let trimmed = fp.trim();
    if trimmed.len() != 16 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CatError::Validation(
            "sync fingerprint 'fp' must be 16 hex characters".into(),
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Format a `SyncUri` into `catcloud://sync/v1?<non-secret>#k=<b64url-nopad-32B>`.
/// The master key `k` is strictly placed in `#fragment` and never in `?query`.
pub fn format_sync_uri(uri: &SyncUri) -> CatResult<String> {
    let mut query_parts: Vec<String> = Vec::new();
    query_parts.push(format!("role={}", uri.role.as_str()));

    match uri.role {
        SyncRole::Pull | SyncRole::Push => {
            let sid = uri
                .sid
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    CatError::Validation("pull/push sync URI requires non-empty 'sid'".into())
                })?;
            validate_sid(sid)?;

            if let Some(ep) = uri.endpoint.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                let validated = validate_endpoint_url(ep)?;
                query_parts.push(format!(
                    "ep={}",
                    percent_encode_query_value(validated.as_str())
                ));
            }

            let mut clean_hosts = Vec::with_capacity(uri.hosts.len());
            for h in &uri.hosts {
                clean_hosts.push(validate_host_token(h)?);
            }
            if !clean_hosts.is_empty() {
                if uri.port.is_none() {
                    return Err(CatError::Validation(
                        "sync URI with 'hosts' requires 'port'".into(),
                    ));
                }
                query_parts.push(format!("hosts={}", clean_hosts.join(",")));
            }
            if let Some(port) = uri.port {
                if port == 0 {
                    return Err(CatError::Validation(
                        "sync URI 'port' must be between 1 and 65535".into(),
                    ));
                }
                query_parts.push(format!("port={port}"));
            }
            if clean_hosts.is_empty() && uri.endpoint.as_deref().map(str::trim).unwrap_or("").is_empty() {
                return Err(CatError::Validation(
                    "pull/push sync URI requires at least one host+port or an endpoint 'ep'".into(),
                ));
            }
            query_parts.push(format!("sid={}", percent_encode_query_value(sid)));
        }
        SyncRole::RelayUrl => {
            let target = uri
                .url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    CatError::Validation("relay_url sync URI requires 'url'".into())
                })?;
            let validated = validate_relay_url(target)?;
            query_parts.push(format!(
                "url={}",
                percent_encode_query_value(validated.as_str())
            ));
        }
        SyncRole::FileKey => {}
    }

    if let Some(fp) = uri.fingerprint.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let norm = normalize_fingerprint(fp)?;
        query_parts.push(format!("fp={norm}"));
    }

    let k_b64 = URL_SAFE_NO_PAD.encode(uri.key);
    Ok(format!(
        "catcloud://sync/v1?{}#k={k_b64}",
        query_parts.join("&")
    ))
}

fn percent_encode_query_value(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Parse `catcloud://sync/v1?...#k=...` (also accepts `catcloud-sync://` alias).
/// Strictly rejects `k` in `?query` and applies SSRF policy on `role=relay_url`.
pub fn parse_sync_uri(raw: &str) -> CatResult<SyncUri> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed)
        .map_err(|err| CatError::Validation(format!("invalid sync URI: {err}")))?;

    let valid_route = match parsed.scheme() {
        "catcloud" => parsed.host_str() == Some("sync") && parsed.path() == "/v1",
        "catcloud-sync" => {
            (parsed.host_str() == Some("v1") && matches!(parsed.path(), "" | "/"))
                || (parsed.host_str() == Some("sync") && parsed.path() == "/v1")
        }
        other => {
            return Err(CatError::Validation(format!(
                "unsupported sync URI scheme '{other}'"
            )));
        }
    };
    if !valid_route {
        return Err(CatError::Validation(
            "unsupported sync URI path (expected catcloud://sync/v1)".into(),
        ));
    }

    let mut role: Option<SyncRole> = None;
    let mut endpoint: Option<String> = None;
    let mut hosts: Vec<String> = Vec::new();
    let mut port: Option<u16> = None;
    let mut sid: Option<String> = None;
    let mut url_param: Option<String> = None;
    let mut fingerprint: Option<String> = None;

    for (k, v) in parsed.query_pairs() {
        let key_lower = k.to_ascii_lowercase();
        if key_lower == "k" {
            return Err(CatError::Security(
                "sync key 'k' must be placed in #fragment and is forbidden in ?query".into(),
            ));
        }
        match key_lower.as_str() {
            "role" => role = Some(SyncRole::parse_str(v.trim())?),
            "ep" => {
                if !v.trim().is_empty() {
                    let validated = validate_endpoint_url(&v)?;
                    endpoint = Some(validated.to_string());
                }
            }
            "hosts" => {
                for item in v.split(',') {
                    let item = item.trim();
                    if !item.is_empty() {
                        hosts.push(validate_host_token(item)?);
                    }
                }
            }
            "port" => {
                let parsed_port: u16 = v
                    .trim()
                    .parse()
                    .map_err(|_| CatError::Validation("invalid sync URI 'port'".into()))?;
                if parsed_port == 0 {
                    return Err(CatError::Validation(
                        "sync URI 'port' must be between 1 and 65535".into(),
                    ));
                }
                port = Some(parsed_port);
            }
            "sid" => {
                let s = v.trim();
                if !s.is_empty() {
                    validate_sid(s)?;
                    sid = Some(s.to_string());
                }
            }
            "url" => {
                if !v.trim().is_empty() {
                    url_param = Some(v.trim().to_string());
                }
            }
            "fp" => {
                if !v.trim().is_empty() {
                    fingerprint = Some(normalize_fingerprint(&v)?);
                }
            }
            _ => {}
        }
    }

    let role = role.ok_or_else(|| CatError::Validation("sync URI missing 'role'".into()))?;

    let fragment = parsed
        .fragment()
        .ok_or_else(|| CatError::Validation("sync URI missing '#k=' fragment".into()))?;
    let mut key_b64: Option<&str> = None;
    for pair in fragment.split('&') {
        if let Some((fk, fv)) = pair.split_once('=')
            && fk.eq_ignore_ascii_case("k")
        {
            key_b64 = Some(fv.trim());
            break;
        }
    }
    let key_b64 = key_b64
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CatError::Validation("sync URI fragment missing 'k=<b64url-32B>'".into()))?;
    let key_vec = URL_SAFE_NO_PAD
        .decode(key_b64)
        .map_err(|err| CatError::Validation(format!("invalid base64url key 'k': {err}")))?;
    if key_vec.len() != KEY_LEN {
        return Err(CatError::Validation(format!(
            "sync key 'k' must decode to exactly {KEY_LEN} bytes, got {}",
            key_vec.len()
        )));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&key_vec);

    match role {
        SyncRole::Pull | SyncRole::Push => {
            if sid.is_none() {
                return Err(CatError::Validation(
                    "pull/push sync URI requires 'sid'".into(),
                ));
            }
            if !hosts.is_empty() && port.is_none() {
                return Err(CatError::Validation(
                    "pull/push sync URI with 'hosts' requires 'port'".into(),
                ));
            }
            if hosts.is_empty() && endpoint.is_none() {
                return Err(CatError::Validation(
                    "pull/push sync URI requires 'hosts'+'port' or 'ep'".into(),
                ));
            }
        }
        SyncRole::RelayUrl => {
            let target = url_param
                .as_deref()
                .ok_or_else(|| CatError::Validation("relay_url sync URI requires 'url'".into()))?;
            let validated = validate_relay_url(target)?;
            url_param = Some(validated.to_string());
        }
        SyncRole::FileKey => {}
    }

    Ok(SyncUri {
        role,
        endpoint,
        hosts,
        port,
        sid,
        url: url_param,
        fingerprint,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_vectors_ccsync01_and_tamper_rejection() {
        let mut key = [0u8; KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut nonce = [0u8; NONCE_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = 0xa0u8 + (i as u8);
        }
        let plaintext = b"catcloud-sync-golden-v1";

        // Vector 1: mode=0x01, sid=""
        let v1 = seal_with_key_and_nonce(plaintext, &key, "", &nonce).unwrap();
        assert_eq!(&v1[0..8], b"CCSYNC01");
        assert_eq!(v1[8], 0x01);
        assert_eq!(&v1[9..13], &[0, 0, 0, 0]);
        assert_eq!(&v1[13..29], &[0u8; 16]);
        assert_eq!(v1[29], 0);
        assert_eq!(&v1[30..42], &nonce);
        assert_eq!(v1.len(), 30 + 12 + plaintext.len() + 16);
        assert_eq!(open_with_key(&v1, &key).unwrap(), plaintext);

        // Vector 2: mode=0x01, sid="0123456789abcdef"
        let sid_demo = "0123456789abcdef";
        let v2 = seal_with_key_and_nonce(plaintext, &key, sid_demo, &nonce).unwrap();
        assert_eq!(v2[29] as usize, sid_demo.len());
        assert_eq!(&v2[30..46], sid_demo.as_bytes());
        assert_eq!(&v2[46..58], &nonce);
        assert_eq!(
            open_with_key_expect_sid(&v2, &key, sid_demo).unwrap(),
            plaintext
        );
        assert!(open_with_key_expect_sid(&v2, &key, "fedcba9876543210").is_err());

        // Vector 3: mode=0x02, iters=1000, salt=[0x11; 16], pin="123456", sid=""
        let salt = [0x11u8; SALT_LEN];
        let v3 = seal_with_password_deterministic(plaintext, "123456", "", 1000, &salt, &nonce)
            .unwrap();
        assert_eq!(v3[8], 0x02);
        assert_eq!(u32::from_be_bytes([v3[9], v3[10], v3[11], v3[12]]), 1000);
        assert_eq!(&v3[13..29], &salt);
        assert_eq!(open_with_password(&v3, "123456").unwrap(), plaintext);
        assert!(open_with_password(&v3, "123457").is_err());

        println!("GOLDEN_V1_MODE1_EMPTY_SID={}", hex::encode(&v1));
        println!("GOLDEN_V2_MODE1_DEMO_SID={}", hex::encode(&v2));
        println!("GOLDEN_V3_MODE2_PBKDF2={}", hex::encode(&v3));

        // 1-bit tamper test across header (AAD), nonce, ciphertext, and tag
        for &target_idx in &[0usize, 8, 29, 30, 42, v1.len() - 1] {
            let mut tampered = v1.clone();
            tampered[target_idx] ^= 0x01;
            assert!(
                open_with_key(&tampered, &key).is_err(),
                "tampered byte at idx {target_idx} must be rejected"
            );
        }
        // Flipping a bit inside sid (AAD) on v2 must fail authentication
        let mut tampered_sid = v2.clone();
        tampered_sid[35] ^= 0x01;
        assert!(open_with_key(&tampered_sid, &key).is_err());
    }

    #[test]
    fn ecdh_p256_and_hmac_handshake_match_both_sides() {
        let server_kp = EphemeralP256KeyPair::generate().unwrap();
        let client_kp = EphemeralP256KeyPair::generate().unwrap();
        let server_pub = *server_kp.public_key_bytes();
        let client_pub = *client_kp.public_key_bytes();
        let server_pub_b64 = server_kp.public_key_b64();
        let client_pub_b64 = client_kp.public_key_b64();

        let challenge = generate_random_bytes::<16>().unwrap();
        let challenge_b64 = STANDARD.encode(challenge);
        let sid = "0123456789abcdef";
        let pin = "482913";

        let proof = compute_pin_proof(pin, sid, &challenge_b64, &server_pub_b64, &client_pub_b64);
        assert_eq!(proof.len(), 64);
        assert!(verify_pin_proof(
            pin,
            sid,
            &challenge_b64,
            &server_pub_b64,
            &client_pub_b64,
            &proof
        ));
        assert!(!verify_pin_proof(
            "482914",
            sid,
            &challenge_b64,
            &server_pub_b64,
            &client_pub_b64,
            &proof
        ));

        let k_server = derive_ecdh_session_key(server_kp, &client_pub, &challenge, sid).unwrap();
        let k_client = derive_ecdh_session_key(client_kp, &server_pub, &challenge, sid).unwrap();
        assert_eq!(k_server, k_client);

        let mac = compute_auth_mac(&k_client, sid, "POST", "/sync/v1/bundle");
        assert!(verify_auth_mac(&k_server, sid, "POST", "/sync/v1/bundle", &mac));
        assert!(!verify_auth_mac(&k_server, sid, "GET", "/sync/v1/bundle", &mac));
    }

    #[test]
    fn sync_uri_roundtrip_and_security_guards() {
        let key = [0x42u8; KEY_LEN];
        let fp = plaintext_fingerprint(b"demo-zip-payload");
        assert_eq!(fp.len(), 16);

        let uri = SyncUri {
            role: SyncRole::Pull,
            endpoint: Some("https://sync.example.com:8443".into()),
            hosts: vec!["192.168.1.25".into(), "10.0.0.8".into()],
            port: Some(43210),
            sid: Some("0123456789abcdef".into()),
            url: None,
            fingerprint: Some(fp.clone()),
            key,
        };
        let encoded = format_sync_uri(&uri).unwrap();
        assert!(encoded.starts_with("catcloud://sync/v1?"));
        assert!(encoded.contains("#k="));
        assert!(!encoded.split('#').next().unwrap().contains("k="));

        let parsed = parse_sync_uri(&encoded).unwrap();
        assert_eq!(parsed.role, SyncRole::Pull);
        assert_eq!(parsed.hosts, vec!["192.168.1.25", "10.0.0.8"]);
        assert_eq!(parsed.port, Some(43210));
        assert_eq!(parsed.sid.as_deref(), Some("0123456789abcdef"));
        assert_eq!(parsed.fingerprint.as_deref(), Some(fp.as_str()));
        assert_eq!(parsed.key, key);

        // Alias scheme compatibility
        let alias = encoded.replacen("catcloud://sync/v1", "catcloud-sync://v1", 1);
        assert_eq!(parse_sync_uri(&alias).unwrap().key, key);

        // Reject 'k' in query string
        let k_b64 = URL_SAFE_NO_PAD.encode(key);
        let leaky = format!("catcloud://sync/v1?role=file_key&k={k_b64}#k={k_b64}");
        assert!(parse_sync_uri(&leaky).is_err());

        // RelayUrl HTTPS & SSRF guards
        let valid_relay = SyncUri {
            role: SyncRole::RelayUrl,
            endpoint: None,
            hosts: vec![],
            port: None,
            sid: None,
            url: Some("https://relay.example.org/bundles/demo.ccsync".into()),
            fingerprint: Some(fp.clone()),
            key,
        };
        let relay_str = format_sync_uri(&valid_relay).unwrap();
        assert_eq!(parse_sync_uri(&relay_str).unwrap().role, SyncRole::RelayUrl);

        for bad_url in [
            "http://relay.example.org/demo.ccsync",
            "https://127.0.0.1/demo.ccsync",
            "https://localhost/demo.ccsync",
            "https://192.168.1.1/demo.ccsync",
            "https://10.0.0.1/demo.ccsync",
            "https://172.16.0.5/demo.ccsync",
            "https://169.254.169.254/latest/meta-data/",
            "https://198.18.0.1/demo.ccsync",
            "https://[::1]/demo.ccsync",
            "https://[::ffff:127.0.0.1]/demo.ccsync",
            "https://[fc00::1]/demo.ccsync",
            "https://[fe80::1]/demo.ccsync",
            "https://user:pass@relay.example.org/demo.ccsync",
        ] {
            let bad_uri = SyncUri {
                role: SyncRole::RelayUrl,
                endpoint: None,
                hosts: vec![],
                port: None,
                sid: None,
                url: Some(bad_url.into()),
                fingerprint: None,
                key,
            };
            assert!(
                format_sync_uri(&bad_uri).is_err(),
                "expected SSRF/scheme rejection for {bad_url}"
            );
        }
    }

    #[test]
    fn endpoint_url_rejects_public_cleartext_http_and_allows_lan_cgnat() {
        let key = [0x33u8; KEY_LEN];

        for allowed_ep in [
            "https://sync.example.com:8443",
            "https://203.0.113.10:8443",
            "http://127.0.0.1:43210",
            "http://localhost:43210",
            "http://mybox.local:43210",
            "http://nas.lan:43210",
            "http://192.168.1.25:43210",
            "http://10.0.0.8:43210",
            "http://172.16.0.5:43210",
            "http://169.254.1.2:43210",
            "http://100.64.0.1:43210",
            "http://100.100.10.2:43210",
            "http://100.127.255.254:43210",
            "http://[::1]:43210",
            "http://[fd00::1]:43210",
            "http://[fe80::1]:43210",
            "http://[::ffff:192.168.1.10]:43210",
        ] {
            let uri = SyncUri {
                role: SyncRole::Pull,
                endpoint: Some(allowed_ep.into()),
                hosts: vec![],
                port: None,
                sid: Some("0123456789abcdef".into()),
                url: None,
                fingerprint: None,
                key,
            };
            let encoded = format_sync_uri(&uri)
                .unwrap_or_else(|e| panic!("expected allowed endpoint {allowed_ep}, got err: {e}"));
            let parsed = parse_sync_uri(&encoded)
                .unwrap_or_else(|e| panic!("expected parse success for {allowed_ep}, got err: {e}"));
            assert!(parsed.endpoint.is_some());
        }

        let outside_cgnat_ep = format!("http://{}.{}.{}.{}:43210", 100, 128, 0, 1);
        let mapped_public_v6 = format!("http://[::ffff:{}.{}.{}.{}]:8080", 203, 0, 113, 10);
        for rejected_ep in [
            "http://sync.example.com:8080",
            "http://sync.example.org/relay",
            "http://203.0.113.10:8080",
            "http://198.51.100.20:43210",
            outside_cgnat_ep.as_str(),
            "http://[2001:db8::1]:8080",
            mapped_public_v6.as_str(),
        ] {
            let uri = SyncUri {
                role: SyncRole::Pull,
                endpoint: Some(rejected_ep.into()),
                hosts: vec![],
                port: None,
                sid: Some("0123456789abcdef".into()),
                url: None,
                fingerprint: None,
                key,
            };
            assert!(
                format_sync_uri(&uri).is_err(),
                "expected public cleartext endpoint rejection for {rejected_ep}"
            );
            let k_b64 = URL_SAFE_NO_PAD.encode(key);
            let raw = format!(
                "catcloud://sync/v1?role=pull&ep={}&sid=0123456789abcdef#k={k_b64}",
                percent_encode_query_value(rejected_ep)
            );
            assert!(
                parse_sync_uri(&raw).is_err(),
                "expected parse rejection for public cleartext endpoint {rejected_ep}"
            );
        }
    }
}
