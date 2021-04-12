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

use crate::crypto::{
    decrypt, encrypt, generate_keypair, hash_data, pk2address, recover_signature, sign_message,
    verify_data_hash,
};
use log::info;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::{Error, Result};
use std::vec::Vec;

const PASSWORD_SALT: &str = "Matthew 5-13";
pub const CONFIG_TYPE: &str = "sm";

pub struct KMS {
    pool: Pool<SqliteConnectionManager>,
    password: String,
}

fn get_config(pool: Pool<SqliteConnectionManager>) -> Result<(Vec<u8>, String)> {
    let conn = pool.get().unwrap();
    let mut stmt = conn.prepare("SELECT password, config_type  FROM config WHERE id = ?")?;
    let mut rows = stmt.query([1])?;

    if let Some(row) = rows.next()? {
        let password = row.get(0)?;
        let config_type = row.get(1)?;
        info!("get old config: {:?} {}", password, config_type);
        Ok((password, config_type))
    } else {
        info!("get config failed, create new config");
        Err(Error::QueryReturnedNoRows)
    }
}

impl KMS {
    pub fn new(db_path: &str, key_file: &Option<String>) -> Self {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::new(manager).unwrap();

        let conn = pool.get().unwrap();

        // table of config to store main password and default crypt_type
        conn.execute(
            "create table if not exists config (
             id integer primary key,
             password BLOB,
             config_type TEXT
         )",
            [],
        )
        .unwrap();

        // table of account
        conn.execute(
            "create table if not exists account (
             id INTEGER PRIMARY KEY,
             pubkey BLOB,
             privkey BLOB,
             description TEXT
         )",
            [],
        )
        .unwrap();

        // user input main password or use key file
        let mut password = match key_file {
            Some(key_file) => std::fs::read_to_string(key_file)
                .unwrap_or_else(|err| panic!("Error while loading key file: [{}]", err))
                .trim_end()
                .to_string(),
            None => rpassword::read_password_from_tty(Some("Password: ")).unwrap(),
        };

        let kms = KMS {
            pool: pool.clone(),
            password: password.clone(),
        };

        if let Ok((pwd_hash, config_type)) = get_config(pool) {
            info!("verify config");
            // password add salt
            password.push_str(PASSWORD_SALT);
            if !verify_data_hash(password.as_bytes().to_vec(), pwd_hash) {
                panic!("password mismatch!");
            }
            if config_type != CONFIG_TYPE {
                panic!("config_type is not match!");
            }
            println!("config check ok!");
        } else {
            info!("store new config");
            // password add salt
            password.push_str(PASSWORD_SALT);
            let pwd_hash = hash_data(password.as_bytes());
            let _ = conn
                .execute(
                    "INSERT INTO config (id, password, config_type) values (?1, ?2, ?3)",
                    &[&1, &pwd_hash as &dyn ToSql, &CONFIG_TYPE],
                )
                .unwrap();
        }

        kms
    }

    fn insert_account(
        &self,
        pubkey: Vec<u8>,
        privkey: Vec<u8>,
        description: String,
    ) -> Result<u64, String> {
        let conn = self.pool.get().unwrap();

        let ret = conn.execute(
            "INSERT INTO account (pubkey, privkey, description) values (?1, ?2, ?3)",
            &[
                &pubkey as &dyn ToSql,
                &privkey as &dyn ToSql,
                &description as &dyn ToSql,
            ],
        );

        if let Err(e) = ret {
            let err_str = format!("insert key failed: {:?}", e);
            Err(err_str)
        } else {
            let latest_id = conn.last_insert_rowid();
            Ok(latest_id as u64)
        }
    }

    pub fn generate_key_pair(&self, description: String) -> Result<(u64, Vec<u8>), String> {
        let (pk, sk) = generate_keypair();
        let encrypted_sk = encrypt(&self.password, sk);
        self.insert_account(pk.clone(), encrypted_sk, description)
            .map_or_else(Err, |key_id| {
                let address = pk2address(&pk);
                Ok((key_id, address))
            })
    }

    pub fn hash_date(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let hash = hash_data(data);
        Ok(hash)
    }

    pub fn verify_data_hash(&self, data: Vec<u8>, hash: Vec<u8>) -> Result<bool, String> {
        Ok(verify_data_hash(data, hash))
    }

    fn get_account(&self, key_id: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let conn = self.pool.get().unwrap();
        let mut stmt = conn.prepare("SELECT pubkey, privkey FROM account WHERE id = ?")?;
        let mut rows = stmt.query([key_id])?;

        if let Some(row) = rows.next()? {
            let pubkey = row.get(0)?;
            let encrypted_sk = row.get(1)?;

            let privkey = decrypt(&self.password, encrypted_sk);
            Ok((pubkey, privkey))
        } else {
            Err(Error::QueryReturnedNoRows)
        }
    }

    pub fn sign_message(&self, key_id: u64, msg: Vec<u8>) -> Result<Vec<u8>, String> {
        if let Ok((pubkey, privkey)) = self.get_account(key_id) {
            if let Some(signature) = sign_message(pubkey, privkey, msg) {
                Ok(signature)
            } else {
                Err("Sign msg failed".to_owned())
            }
        } else {
            Err("Can't find key id!".to_owned())
        }
    }

    pub fn recover_signature(&self, msg: Vec<u8>, signature: Vec<u8>) -> Result<Vec<u8>, String> {
        if let Some(pubkey) = recover_signature(msg, signature) {
            let address = pk2address(&pubkey);
            Ok(address)
        } else {
            Err("Recover signature failed".to_owned())
        }
    }
}
