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

mod config;
mod crypto;
mod kms;

use clap::Clap;
use git_version::git_version;
use log::{debug, info};

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/kms_sm";

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Clap)]
#[clap(version = "0.1.0", author = "Rivtower Technologies.")]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// print information from git
    #[clap(name = "git")]
    GitInfo,
    /// run this service
    #[clap(name = "run")]
    Run(RunOpts),
    /// create key in command line
    #[clap(name = "create")]
    Create(CreateOpts),
}

/// A subcommand for run
#[derive(Clap)]
struct RunOpts {
    /// Sets grpc port of this service.
    #[clap(short = 'p', long = "port", default_value = "50005")]
    grpc_port: String,
    /// Sets path of db file.
    #[clap(short = 'd', long = "db")]
    db_path: Option<String>,
    /// Sets path of key_file.
    #[clap(short = 'k', long = "key")]
    key_file: Option<String>,
    /// Chain config path
    #[clap(short = 'c', long = "config", default_value = "config.toml")]
    config_path: String,
}

/// A subcommand for create
#[derive(Clap)]
struct CreateOpts {
    /// Sets path of db file.
    #[clap(short = 'd', long = "db")]
    db_path: Option<String>,
    /// Sets path of key_file.
    #[clap(short = 'k', long = "key")]
    key_file: Option<String>,
    /// Chain config path
    #[clap(short = 'c', long = "config", default_value = "config.toml")]
    config_path: String,
}

fn main() {
    ::std::env::set_var("RUST_BACKTRACE", "full");

    let opts: Opts = Opts::parse();

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match opts.subcmd {
        SubCommand::GitInfo => {
            println!("git version: {}", GIT_VERSION);
            println!("homepage: {}", GIT_HOMEPAGE);
        }
        SubCommand::Run(opts) => {
            let _ = run(opts);
        }
        SubCommand::Create(opts) => {
            let _ = create(opts);
        }
    }
}

use cita_cloud_proto::common::{Empty, Hash, HashRespond};
use cita_cloud_proto::kms::{
    kms_service_server::KmsService, kms_service_server::KmsServiceServer, GenerateKeyPairRequest,
    GenerateKeyPairResponse, GetCryptoInfoResponse, HashDataRequest, RecoverSignatureRequest,
    RecoverSignatureResponse, SignMessageRequest, SignMessageResponse, VerifyDataHashRequest,
};
use tonic::{transport::Server, Request, Response, Status};

use crate::config::KmsConfig;
use crate::crypto::{check_transactions, ADDR_BYTES_LEN, SM2_SIGNATURE_BYTES_LEN};
use cita_cloud_proto::blockchain::RawTransactions;
use kms::Kms;
use status_code::StatusCode;
use std::sync::Arc;
use tokio::sync::RwLock;

// grpc server of RPC
pub struct KmsServer {
    kms: Arc<RwLock<Kms>>,
}

impl KmsServer {
    fn new(kms: Arc<RwLock<Kms>>) -> Self {
        KmsServer { kms }
    }
}

#[tonic::async_trait]
impl KmsService for KmsServer {
    async fn get_crypto_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<GetCryptoInfoResponse>, Status> {
        debug!("get_crypto_info");
        Ok(Response::new(GetCryptoInfoResponse {
            status: Some(StatusCode::Success.into()),
            name: kms::CONFIG_TYPE.to_string(),
            hash_len: crypto::HASH_BYTES_LEN as u32,
            signature_len: crypto::SM2_SIGNATURE_BYTES_LEN as u32,
            address_len: crypto::ADDR_BYTES_LEN as u32,
        }))
    }

    // Err code maybe return: aborted
    async fn generate_key_pair(
        &self,
        request: Request<GenerateKeyPairRequest>,
    ) -> Result<Response<GenerateKeyPairResponse>, Status> {
        debug!("generate_key_pair request: {:?}", request);

        let req = request.into_inner();
        let description = req.description;

        let kms = self.kms.read().await;
        kms.generate_key_pair(description).map_or_else(
            |e| Err(Status::invalid_argument(e.to_string())),
            |(key_id, address)| Ok(Response::new(GenerateKeyPairResponse { key_id, address })),
        )
    }

    async fn hash_data(
        &self,
        request: Request<HashDataRequest>,
    ) -> Result<Response<HashRespond>, Status> {
        debug!("hash_date request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;

        let kms = self.kms.read().await;
        Ok(Response::new(HashRespond {
            status: Some(StatusCode::Success.into()),
            hash: Some(Hash {
                hash: kms.hash_date(&data),
            }),
        }))
    }

    async fn verify_data_hash(
        &self,
        request: Request<VerifyDataHashRequest>,
    ) -> Result<Response<cita_cloud_proto::common::StatusCode>, Status> {
        debug!("verify_data_hash request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;
        let hash = req.hash;

        let kms = self.kms.read().await;
        Ok(Response::new(kms.verify_data_hash(&data, &hash).into()))
    }

    // Err code maybe return: aborted/invalid_argument
    async fn sign_message(
        &self,
        request: Request<SignMessageRequest>,
    ) -> Result<Response<SignMessageResponse>, Status> {
        debug!("sign_message request: {:?}", request);

        let req = request.into_inner();
        let key_id = req.key_id;
        let msg = req.msg;

        let kms = self.kms.read().await;
        kms.sign_message(key_id, &msg).map_or_else(
            |status| {
                Ok(Response::new(SignMessageResponse {
                    status: Some(status.into()),
                    signature: [0; SM2_SIGNATURE_BYTES_LEN].to_vec(),
                }))
            },
            |signature| {
                Ok(Response::new(SignMessageResponse {
                    status: Some(StatusCode::Success.into()),
                    signature,
                }))
            },
        )
    }

    // Err code maybe return: invalid_argument
    async fn recover_signature(
        &self,
        request: Request<RecoverSignatureRequest>,
    ) -> Result<Response<RecoverSignatureResponse>, Status> {
        debug!("recover_signature request: {:?}", request);

        let req = request.into_inner();
        let msg = req.msg;
        let signature = req.signature;

        let kms = self.kms.read().await;
        kms.recover_signature(&msg, &signature).map_or_else(
            |status| {
                Ok(Response::new(RecoverSignatureResponse {
                    status: Some(status.into()),
                    address: [0; ADDR_BYTES_LEN].to_vec(),
                }))
            },
            |address| {
                Ok(Response::new(RecoverSignatureResponse {
                    status: Some(StatusCode::Success.into()),
                    address,
                }))
            },
        )
    }

    async fn check_transactions(
        &self,
        request: Request<RawTransactions>,
    ) -> Result<Response<cita_cloud_proto::common::StatusCode>, Status> {
        debug!("check_transactions request: {:?}", request);
        let req = request.into_inner();
        Ok(Response::new(check_transactions(&req).into()))
    }
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<(), Box<dyn std::error::Error>> {
    let config = KmsConfig::new(&opts.config_path);
    // init log4rs
    log4rs::init_file(&config.log_file, Default::default()).unwrap();

    let grpc_port = {
        if "50005" != opts.grpc_port {
            opts.grpc_port.clone()
        } else if config.kms_port != 50005 {
            config.kms_port.to_string()
        } else {
            "50005".to_string()
        }
    };
    info!("grpc port of this service: {}", grpc_port);

    let db_path = match opts.db_path {
        Some(path) => path,
        None => config.db_path,
    };
    info!("db path of this service: {}", &db_path);

    let key_file = match opts.key_file {
        Some(key) => key,
        None => config.db_key,
    };
    info!("key_file is {:?}", &key_file);

    let kms = Kms::new(db_path, key_file);

    let addr_str = format!("0.0.0.0:{}", grpc_port);
    let addr = addr_str.parse()?;

    info!("start grpc server!");
    Server::builder()
        .add_service(KmsServiceServer::new(KmsServer::new(Arc::new(
            RwLock::new(kms),
        ))))
        .serve(addr)
        .await?;

    Ok(())
}

fn create(opts: CreateOpts) {
    let config = KmsConfig::new(&opts.config_path);

    let db_path = match opts.db_path {
        Some(path) => path,
        None => config.db_path,
    };
    info!("db path of this service: {}", &db_path);

    let key_file = match opts.key_file {
        Some(key) => key,
        None => config.db_key,
    };
    info!("key_file is {:?}", &key_file);

    let kms = Kms::new(db_path, key_file);
    let (key_id, address) = kms
        .generate_key_pair("create by cmd".to_owned())
        .expect("generate_key_pair failed");
    let mut address_hex = String::from("0x");
    for v in address {
        let v_str = format!("{:02x}", v);
        address_hex.push_str(&v_str);
    }
    println!("key_id:{},address:{}", key_id, address_hex);
}
