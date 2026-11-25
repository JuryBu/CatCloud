pub mod crypto;
pub mod lan_http;
pub mod qr;

pub use crypto::{
    DEFAULT_PBKDF2_ITERS, ENVELOPE_MAGIC, EphemeralP256KeyPair, EnvelopeHeader, KEY_LEN,
    KDF_MODE_PBKDF2_SHA256, KDF_MODE_RAW_KEY, MAX_SYNC_ENVELOPE_BYTES, NONCE_LEN,
    P256_UNCOMPRESSED_PUB_LEN, SALT_LEN, SyncRole, SyncSecret, SyncUri, TAG_LEN,
    compute_auth_mac, compute_pin_proof, decode_base64_flex, derive_ecdh_session_key,
    format_sync_uri, generate_pin_6, generate_random_bytes, generate_random_key,
    generate_session_id, inspect_envelope_header, is_forbidden_relay_ip, open_sync_envelope,
    open_with_key, open_with_key_expect_sid, open_with_password, parse_sync_uri,
    plaintext_fingerprint, seal_sync_envelope, seal_with_key, seal_with_key_and_nonce,
    seal_with_password, seal_with_password_deterministic, validate_relay_url, verify_auth_mac,
    verify_pin_proof,
};
pub use lan_http::{
    DEFAULT_SYNC_TTL_SECS, LanSyncReceiveInfo, LanSyncReceiveServer, LanSyncSendInfo,
    LanSyncSendServer, LanSyncServerOptions, MAX_AUTH_FAILURES, MAX_HTTP_BODY_BYTES,
    ReceivedSyncBundle, fetch_relay_url_bundle, fetch_sync_bundle_via_pin,
    fetch_sync_bundle_via_uri, is_lan_or_loopback_ip, list_lan_ipv4_candidates,
    push_sync_bundle_via_pin, push_sync_bundle_via_uri,
};
pub use qr::{
    EccLevel, QrMatrix, encode_qr_matrix, encode_qr_matrix_with_ecc, render_qr_svg,
    render_qr_svg_with_ecc, render_qr_terminal, render_qr_terminal_with_ecc,
};
