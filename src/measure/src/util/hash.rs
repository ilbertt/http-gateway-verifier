use sha2::{Digest, Sha256, Sha384};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha384(data: &[u8]) -> Vec<u8> {
    Sha384::digest(data).to_vec()
}
