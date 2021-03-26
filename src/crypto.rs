// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rand::Rng;

pub fn encrypt(password: &str, data: Vec<u8>) -> Vec<u8> {
    let hash = sm3_hash(password.as_bytes());
    let key = hash[0..16].to_owned();
    let iv = hash[16..32].to_owned();

    let cipher = libsm::sm4::Cipher::new(&key, libsm::sm4::Mode::Cfb);

    cipher.encrypt(&data, &iv)
}

pub fn decrypt(password: &str, data: Vec<u8>) -> Vec<u8> {
    let hash = sm3_hash(password.as_bytes());
    let key = hash[0..16].to_owned();
    let iv = hash[16..32].to_owned();

    let cipher = libsm::sm4::Cipher::new(&key, libsm::sm4::Mode::Cfb);

    cipher.decrypt(&data, &iv)
}

pub const HASH_BYTES_LEN: usize = 32;

fn sm3_hash(input: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let mut result = [0u8; HASH_BYTES_LEN];
    result.copy_from_slice(libsm::sm3::hash::Sm3Hash::new(input).get_hash().as_ref());
    result
}

const SM2_PUBKEY_BYTES_LEN: usize = 64;
const SM2_PRIVKEY_BYTES_LEN: usize = 32;
pub const SM2_SIGNATURE_BYTES_LEN: usize = 128;

fn sm2_gen_keypair() -> ([u8; SM2_PUBKEY_BYTES_LEN], [u8; SM2_PRIVKEY_BYTES_LEN]) {
    let mut private_key = [0; SM2_PRIVKEY_BYTES_LEN];
    let mut public_key = [0u8; SM2_PUBKEY_BYTES_LEN];

    rand::thread_rng().fill_bytes(&mut private_key);
    let key_pair = efficient_sm2::KeyPair::new(&private_key).unwrap();
    let pubkey = key_pair.public_key();
    public_key.copy_from_slice(&pubkey.bytes_less_safe()[1..]);

    (public_key, private_key)
}

fn sm2_sign(pubkey: &[u8], privkey: &[u8], msg: &[u8]) -> [u8; SM2_SIGNATURE_BYTES_LEN] {
    let key_pair = efficient_sm2::KeyPair::new(privkey).unwrap();
    let sig = key_pair.sign(msg).unwrap();

    let mut sig_bytes = [0u8; SM2_SIGNATURE_BYTES_LEN];
    sig_bytes[..32].copy_from_slice(&sig.r());
    sig_bytes[32..64].copy_from_slice(&sig.s());
    sig_bytes[64..].copy_from_slice(pubkey);
    sig_bytes
}

fn sm2_recover(signature: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let r = &signature[0..32];
    let s = &signature[32..64];
    let pk = &signature[64..];

    let signature = efficient_sm2::Signature::new(r, s).unwrap();
    let public_key = efficient_sm2::PublicKey::new(&pk[..32], &pk[32..]);

    if signature.verify(&public_key, message).is_ok() {
        Some(pk.to_vec())
    } else {
        None
    }
}

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = sm2_gen_keypair();
    (pk.to_vec(), sk.to_vec())
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    sm3_hash(data).to_vec()
}

pub fn verify_data_hash(data: Vec<u8>, hash: Vec<u8>) -> bool {
    if hash.len() != HASH_BYTES_LEN {
        false
    } else {
        hash == hash_data(&data)
    }
}

pub const ADDR_BYTES_LEN: usize = 20;

pub fn pk2address(pk: &[u8]) -> Vec<u8> {
    hash_data(pk)[HASH_BYTES_LEN - ADDR_BYTES_LEN..].to_vec()
}

pub fn sign_message(pubkey: Vec<u8>, privkey: Vec<u8>, msg: Vec<u8>) -> Option<Vec<u8>> {
    if msg.len() != HASH_BYTES_LEN {
        None
    } else {
        Some(sm2_sign(&pubkey, &privkey, &msg).to_vec())
    }
}

pub fn recover_signature(msg: Vec<u8>, signature: Vec<u8>) -> Option<Vec<u8>> {
    if signature.len() != SM2_SIGNATURE_BYTES_LEN {
        None
    } else {
        sm2_recover(&signature, &msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm3_test() {
        let hash_empty: [u8; HASH_BYTES_LEN] = [
            0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8,
            0x1a, 0x8f, 0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb,
            0x50, 0x82, 0xaa, 0x2b,
        ];
        assert_eq!(sm3_hash(&[]), hash_empty);
    }

    #[test]
    fn test_data_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];
        let hash = hash_data(&data);
        assert!(verify_data_hash(data.clone(), hash));
    }

    #[test]
    fn test_signature() {
        // message must be 32 bytes
        let data: [u8; HASH_BYTES_LEN] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];

        let (pubkey, privkey) = generate_keypair();
        let signature = sign_message(pubkey.clone(), privkey, data.to_vec()).unwrap();
        assert_eq!(recover_signature(data.to_vec(), signature), Some(pubkey));
    }
}
