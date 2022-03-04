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

use cloud_util::common::read_toml;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct KmsConfig {
    pub kms_port: u16,

    pub db_path: String,

    pub db_key: String,
}

impl Default for KmsConfig {
    fn default() -> Self {
        Self {
            kms_port: 50005,
            db_path: "kms.db".to_string(),
            db_key: "123456".to_string(),
        }
    }
}

impl KmsConfig {
    pub fn new(config_str: &str) -> Self {
        read_toml(config_str, "kms_sm")
    }
}

#[cfg(test)]
mod tests {
    use super::KmsConfig;

    #[test]
    fn basic_test() {
        let config = KmsConfig::new("example/config.toml");

        assert_eq!(config.kms_port, 60005);
        assert_eq!(config.db_path, "kms.db".to_string());
    }
}
