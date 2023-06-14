use crate::error::MutinyError;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use pbkdf2::password_hash::Output;
use pbkdf2::password_hash::{PasswordHasher, Salt, SaltString};
use pbkdf2::{Params, Pbkdf2};

pub fn encrypt(content: &str, password: &str) -> Result<String, MutinyError> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).unwrap();
    let derive_key = derive_key(password, &salt);
    let key = derive_key.as_bytes();

    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).unwrap();

    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce = Nonce::from_slice(&iv);
    let mut bytes = cipher.encrypt(nonce, content.as_bytes())?;

    let mut combined = vec![];
    combined.append(&mut salt.to_vec());
    combined.append(&mut iv.to_vec());
    combined.append(&mut bytes);
    Ok(base64::encode(combined.as_slice()))
}

pub fn decrypt(encrypted: &str, password: &str) -> Result<String, MutinyError> {
    let buffer = base64::decode(encrypted).map_err(|_| MutinyError::IncorrectPassword)?;
    let buffer_slice = buffer.as_slice();
    let salt = &buffer_slice[0..16];
    let iv = &buffer_slice[16..28];
    let data = &buffer_slice[28..];

    let derive_key = derive_key(password, salt);
    let key = derive_key.as_bytes();

    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce = Nonce::from_slice(iv);
    let decrypted = cipher.decrypt(nonce, data)?;
    Ok(String::from_utf8(decrypted).unwrap())
}

fn derive_key(password: &str, salt: &[u8]) -> Output {
    let params = Params {
        rounds: 2048,
        output_length: 32,
    };

    let salt_string = SaltString::b64_encode(salt).unwrap();
    let salt = Salt::from(&salt_string);
    let password = password.as_bytes();
    let key = Pbkdf2
        .hash_password_customized(password, None, None, params, salt)
        .unwrap();
    key.hash.unwrap()
}

#[cfg(test)]
mod tests {
    use crate::encrypt::{decrypt, encrypt};

    #[test]
    fn test_encryption() {
        let password = "password";
        let content = "hello world";
        let encrypted = encrypt(content, password).unwrap();
        println!("{encrypted}");

        let decrypted = decrypt(&encrypted, password).unwrap();
        println!("{decrypted}");
        assert_eq!(content, decrypted);
    }
}
