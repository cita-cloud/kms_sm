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
    let ctx = libsm::sm2::signature::SigCtx::new();
    let (pk, sk) = ctx.new_keypair();

    let mut pubkey = [0u8; SM2_PUBKEY_BYTES_LEN];
    pubkey.copy_from_slice(&ctx.serialize_pubkey(&pk, false)[1..]);

    let mut privkey = [0u8; SM2_PRIVKEY_BYTES_LEN];
    privkey.copy_from_slice(&ctx.serialize_seckey(&sk)[..]);

    (pubkey, privkey)
}

fn sm2_sign(pubkey: &[u8], privkey: &[u8], msg: &[u8]) -> [u8; SM2_SIGNATURE_BYTES_LEN] {
    let ctx = libsm::sm2::signature::SigCtx::new();

    let sk = ctx.load_seckey(privkey).unwrap();

    let signature = ctx.sign_raw(&msg, &sk);

    let mut sig_bytes = [0u8; SM2_SIGNATURE_BYTES_LEN];
    let r_bytes = signature.get_r().to_bytes_be();
    let s_bytes = signature.get_s().to_bytes_be();

    sig_bytes[32 - r_bytes.len()..32].copy_from_slice(&r_bytes[..]);
    sig_bytes[64 - s_bytes.len()..64].copy_from_slice(&s_bytes[..]);
    sig_bytes[64..].copy_from_slice(pubkey);
    sig_bytes
}

fn sm2_recover(signature: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    let ctx = libsm::sm2::signature::SigCtx::new();
    let r = &signature[0..32];
    let s = &signature[32..64];
    let pk = &signature[64..];

    let sig = libsm::sm2::signature::Signature::new(r, s);

    let mut pk_full = [0u8; SM2_PUBKEY_BYTES_LEN + 1];
    pk_full[0] = 4;
    pk_full[1..].copy_from_slice(pk);
    let ppk = ctx.load_pubkey(&pk_full[..]).unwrap();

    if ctx.verify_raw(&message, &ppk, &sig) {
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

const ADDR_BYTES_LEN: usize = 20;

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
    use crate::kms::REVERSE_KEYS;

    #[test]
    fn aes_test() {
        let password = "password";
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];

        let cipher_message = aes(password, data.clone());
        let decrypted_message = aes(password, cipher_message);
        assert_eq!(data, decrypted_message);
    }

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
    fn keccak_test() {
        let hash_empty: [u8; HASH_BYTES_LEN] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(keccak_hash(&[]), hash_empty);
    }

    #[test]
    fn test_data_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];
        for i in 1..REVERSE_KEYS {
            let crypt_type = i as u32;
            let hash = hash_data(crypt_type, &data);
            assert!(verify_data_hash(crypt_type, data.clone(), hash));
        }
    }

    #[test]
    fn test_signature() {
        // message must be 32 bytes
        let data: [u8; HASH_BYTES_LEN] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];

        for i in 1..REVERSE_KEYS {
            let crypt_type = i as u32;
            let (pubkey, privkey) = generate_keypair(crypt_type);
            let signature = sign_message(crypt_type, pubkey.clone(), privkey, data.to_vec());
            assert_eq!(
                recover_signature(crypt_type, data.to_vec(), signature),
                Some(pubkey)
            );
        }
    }
}
