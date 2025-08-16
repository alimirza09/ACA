use base64::{Engine as _, engine::general_purpose};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::{Nonce, PublicKey, SecretKey};
use std::fs;
use std::path::Path;

pub fn init_crypto() {
    sodiumoxide::init().unwrap();
}

pub fn generate_and_store_keypair(path: &Path) -> (PublicKey, SecretKey) {
    let (pk, sk) = box_::gen_keypair();
    fs::write(
        path.join("public.key"),
        general_purpose::STANDARD.encode(pk.0),
    )
    .unwrap();
    fs::write(
        path.join("secret.key"),
        general_purpose::STANDARD.encode(sk.0),
    )
    .unwrap();
    (pk, sk)
}

pub fn load_keypair(path: &Path) -> (PublicKey, SecretKey) {
    let pk_path = path.join("public.key");
    let sk_path = path.join("secret.key");
    if !(sk_path.exists() || pk_path.exists()) {
        let _ = generate_and_store_keypair(path);
    }
    let pk = {
        let b64 = fs::read_to_string(pk_path).unwrap();
        PublicKey(
            general_purpose::STANDARD
                .decode(b64.trim())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };
    let sk = {
        let b64 = fs::read_to_string(sk_path).unwrap();
        SecretKey(
            general_purpose::STANDARD
                .decode(b64.trim())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    };

    return (pk, sk);
}

pub fn parse_public_key(b64: &str) -> Option<PublicKey> {
    let decoded = general_purpose::STANDARD.decode(b64.trim()).ok()?;
    Some(PublicKey(decoded.try_into().ok()?))
}

pub fn encode_public_key(pk: &PublicKey) -> String {
    general_purpose::STANDARD.encode(pk.0)
}

pub fn encrypt_message(msg: &[u8], their_pk: &PublicKey, my_sk: &SecretKey) -> Vec<u8> {
    let nonce = box_::gen_nonce();
    let mut encrypted = box_::seal(msg, &nonce, their_pk, my_sk);
    let mut out = nonce.0.to_vec();
    out.append(&mut encrypted);
    out
}

pub fn decrypt_message(
    ciphertext: &[u8],
    their_pk: &PublicKey,
    my_sk: &SecretKey,
) -> Option<Vec<u8>> {
    if ciphertext.len() < box_::NONCEBYTES {
        return None;
    }
    let nonce = Nonce::from_slice(&ciphertext[..box_::NONCEBYTES]).unwrap();
    let ct = &ciphertext[box_::NONCEBYTES..];
    box_::open(ct, &nonce, their_pk, my_sk).ok()
}
