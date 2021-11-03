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
use log::{info, warn};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::types::ToSql;
use rusqlite::{Error, Result};
use status_code::StatusCode;

const PASSWORD_SALT: &str = "Matthew 5-13";
pub const CONFIG_TYPE: &str = "sm";

pub struct Kms {
    pool: Pool<SqliteConnectionManager>,
    password: Vec<u8>,
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

impl Kms {
    pub fn new(db_path: String, mut password: String) -> Self {
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

        if let Ok((pwd_hash, config_type)) = get_config(pool.clone()) {
            info!("verify config");
            // password add salt
            password.push_str(PASSWORD_SALT);
            if verify_data_hash(password.as_bytes(), &pwd_hash).is_err() {
                panic!("password mismatch!");
            }
            if config_type != CONFIG_TYPE {
                panic!("config_type is not match!");
            }
            info!("config check ok!");
            Kms {
                pool,
                password: pwd_hash,
            }
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
            Kms {
                pool,
                password: pwd_hash,
            }
        }
    }

    fn insert_account(
        &self,
        pubkey: Vec<u8>,
        privkey: Vec<u8>,
        description: String,
    ) -> Result<u64, StatusCode> {
        let conn = self.pool.get().unwrap();

        match conn.execute(
            "INSERT INTO account (pubkey, privkey, description) values (?1, ?2, ?3)",
            &[
                &pubkey as &dyn ToSql,
                &privkey as &dyn ToSql,
                &description as &dyn ToSql,
            ],
        ) {
            Err(e) => {
                warn!("insert_account failed: {:?}", e);
                Err(StatusCode::InsertAccountError)
            }
            Ok(_) => Ok(conn.last_insert_rowid() as u64),
        }
    }

    pub fn generate_key_pair(&self, description: String) -> Result<(u64, Vec<u8>), StatusCode> {
        let (pk, sk) = generate_keypair()?;
        let encrypted_sk = encrypt(&self.password, sk);
        self.insert_account(pk.clone(), encrypted_sk, description)
            .map(|key_id| {
                let address = pk2address(&pk);
                (key_id, address)
            })
    }

    pub fn hash_date(&self, data: &[u8]) -> Vec<u8> {
        hash_data(data)
    }

    pub fn verify_data_hash(&self, data: &[u8], hash: &[u8]) -> StatusCode {
        verify_data_hash(data, hash).map_or_else(|e| e, |_| StatusCode::Success)
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

    pub fn sign_message(&self, key_id: u64, msg: &[u8]) -> Result<Vec<u8>, StatusCode> {
        match self.get_account(key_id) {
            Ok((pubkey, privkey)) => sign_message(&pubkey, &privkey, msg),
            Err(err) => {
                warn!("sign_message get account(id: {}) failed: {:?}", key_id, err);
                Err(StatusCode::NotFoundAccount)
            }
        }
    }

    pub fn recover_signature(&self, msg: &[u8], signature: &[u8]) -> Result<Vec<u8>, StatusCode> {
        let pub_key = recover_signature(msg, signature)?;
        Ok(pk2address(&pub_key))
    }
}
