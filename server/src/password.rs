use argon2::{
    Argon2, PasswordVerifier,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};

/// Hash a plaintext password using Argon2 with a random salt.
pub fn hash_password(password: &str) -> Result<String, ()> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    let password_hash = argon2.hash_password(password.as_bytes(), &salt);

    if password_hash.is_err() {
        return Err(());
    }

    Ok(password_hash.unwrap().to_string())
}

/// Verify a plaintext password against a stored Argon2 hash.
pub fn verify_password(password: &Vec<u8>, stored_hash: &str) -> bool {
    let password = std::str::from_utf8(password);

    if password.is_err() {
        return false;
    }

    let password = password.unwrap();

    let stored_hash = argon2::PasswordHash::new(stored_hash);

    if stored_hash.is_err() {
        return false;
    }

    let stored_hash = stored_hash.unwrap();

    let argon2 = Argon2::default();
    argon2
        .verify_password(password.as_bytes(), &stored_hash)
        .is_ok()
}
