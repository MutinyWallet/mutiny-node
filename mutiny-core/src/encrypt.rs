use crate::error::MutinyError;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes256;
use aes_gcm::Aes256Gcm;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead},
    KeyInit,
};
use argon2::Argon2;
use base64;
use bitcoin::secp256k1;
use bitcoin::secp256k1::SecretKey;
use cbc::{Decryptor, Encryptor};
use getrandom::getrandom;
use std::sync::Arc;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Clone)]
pub struct Cipher {
    key: Arc<Aes256Gcm>,
    salt: [u8; 16],
}

pub fn encryption_key_from_pass(password: &str) -> Result<Cipher, MutinyError> {
    let mut salt = [0u8; 16];
    getrandom(&mut salt).unwrap();

    let key = get_encryption_key(password, &salt)?;

    // convert key to proper format for aes_gcm
    let key = GenericArray::clone_from_slice(&key);
    Ok(Cipher {
        key: Arc::new(Aes256Gcm::new(&key)),
        salt,
    })
}

pub fn encrypt(content: &str, c: &Cipher) -> Result<String, MutinyError> {
    // convert key and nonce to proper format for aes_gcm
    let mut nonce = [0u8; 12];
    getrandom(&mut nonce).unwrap();

    // convert nonce to proper format for aes_gcm
    let nonce = GenericArray::from_slice(&nonce);

    let encrypted_data = c.key.encrypt(nonce, content.as_bytes().to_vec().as_ref())?;

    let mut result: Vec<u8> = Vec::new();
    result.extend(&c.salt);
    result.extend(nonce);
    result.extend(encrypted_data);

    Ok(base64::encode(&result))
}

pub fn decrypt_with_password(encrypted: &str, password: &str) -> Result<String, MutinyError> {
    let encrypted = base64::decode(encrypted)?;
    if encrypted.len() < 12 + 16 {
        return Err(MutinyError::IncorrectPassword);
    }

    let (rest, encrypted_bytes) = encrypted.split_at(16 + 12);
    let (salt, nonce_bytes) = rest.split_at(16);

    let key = get_encryption_key(password, salt)?;

    // convert key and nonce to proper format for aes_gcm
    let key = GenericArray::clone_from_slice(&key);
    let nonce = GenericArray::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(&key);

    let decrypted_data = cipher.decrypt(nonce, encrypted_bytes)?;

    let decrypted_string =
        String::from_utf8(decrypted_data).map_err(|_| MutinyError::IncorrectPassword)?;

    Ok(decrypted_string)
}

pub fn get_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32], MutinyError> {
    let mut key = [0u8; 32];
    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| MutinyError::IncorrectPassword)?;
    Ok(key)
}

fn argon2() -> Argon2<'static> {
    let mut binding = argon2::ParamsBuilder::new();
    let params = binding.m_cost(7 * 1024).t_cost(1).p_cost(1);
    Argon2::from(params.build().expect("valid params"))
}

pub fn encrypt_with_key(encryption_key: &SecretKey, bytes: &[u8]) -> Vec<u8> {
    let iv: [u8; 16] = secp256k1::rand::random();

    let cipher = Aes256CbcEnc::new(&encryption_key.secret_bytes().into(), &iv.into());
    let mut encrypted: Vec<u8> = cipher.encrypt_padded_vec_mut::<Pkcs7>(bytes);
    encrypted.extend(iv);

    encrypted
}

pub fn decrypt_with_key(
    encryption_key: &SecretKey,
    bytes: Vec<u8>,
) -> Result<Vec<u8>, MutinyError> {
    if bytes.len() < 16 {
        return Err(MutinyError::IncorrectPassword);
    }
    // split last 16 bytes off as iv
    let iv = &bytes[bytes.len() - 16..];
    let bytes = &bytes[..bytes.len() - 16];

    let cipher = Aes256CbcDec::new(&encryption_key.secret_bytes().into(), iv.into());
    let decrypted: Vec<u8> = cipher.decrypt_padded_vec_mut::<Pkcs7>(bytes)?;

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use crate::encrypt::{
        decrypt_with_key, decrypt_with_password, encrypt, encrypt_with_key,
        encryption_key_from_pass,
    };
    use bitcoin::secp256k1::SecretKey;

    #[test]
    fn test_encryption() {
        let password = "password";
        let content = "hello world";
        let cipher = encryption_key_from_pass(password).unwrap();

        let encrypted = encrypt(content, cipher).unwrap();
        println!("{encrypted}");

        let decrypted = decrypt_with_password(&encrypted, password).unwrap();
        println!("{decrypted}");
        assert_eq!(content, decrypted);
    }

    #[test]
    fn test_encryption_with_key() {
        let key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let content = [6u8; 32].to_vec();

        let encrypted = encrypt_with_key(&key, &content);

        let decrypted = decrypt_with_key(&key, encrypted).unwrap();
        assert_eq!(content, decrypted);
    }
}
