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

use clap::Parser;
use git_version::git_version;
use log::{debug, info, warn};

const GIT_VERSION: &str = git_version!(
    args = ["--tags", "--always", "--dirty=-modified"],
    fallback = "unknown"
);
const GIT_HOMEPAGE: &str = "https://github.com/cita-cloud/kms_sm";

/// This doc string acts as a help message when the user runs '--help'
/// as do all doc strings on fields
#[derive(Parser)]
#[clap(version, author)]
struct Opts {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// print information from git
    #[clap(name = "git")]
    GitInfo,
    /// run this service
    #[clap(name = "run")]
    Run(RunOpts),
}

/// A subcommand for run
#[derive(Parser)]
struct RunOpts {
    /// Chain config path
    #[clap(short = 'c', long = "config", default_value = "config.toml")]
    config_path: String,
    /// log config path
    #[clap(short = 'l', long = "log", default_value = "kms-log4rs.yaml")]
    log_file: String,
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
            let fin = run(opts);
            warn!("Should not reach here {:?}", fin);
        }
    }
}

use cita_cloud_proto::common::{Empty, Hash, HashResponse};
use cita_cloud_proto::kms::{
    kms_service_server::KmsService, kms_service_server::KmsServiceServer, GenerateKeyPairRequest,
    GenerateKeyPairResponse, GetCryptoInfoResponse, HashDataRequest, RecoverSignatureRequest,
    RecoverSignatureResponse, SignMessageRequest, SignMessageResponse, VerifyDataHashRequest,
};
use tonic::{transport::Server, Request, Response, Status};

use crate::config::KmsConfig;
use crate::crypto::{check_transactions, ADDR_BYTES_LEN, SM2_SIGNATURE_BYTES_LEN};
use crate::kms::Kms;
use cita_cloud_proto::blockchain::RawTransactions;
use status_code::StatusCode;
use std::net::AddrParseError;
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
    ) -> Result<Response<HashResponse>, Status> {
        debug!("hash_date request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;

        let kms = self.kms.read().await;
        Ok(Response::new(HashResponse {
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
async fn run(opts: RunOpts) -> Result<(), StatusCode> {
    let config = KmsConfig::new(&opts.config_path);
    // init log4rs
    log4rs::init_file(&opts.log_file, Default::default())
        .map_err(|e| println!("log init err: {}", e))
        .unwrap();

    info!("grpc port of this service: {}", &config.kms_port);

    info!("db path of this service: {}", &config.db_path);

    let kms = Kms::new(config.db_path, config.db_key);

    let addr_str = format!("0.0.0.0:{}", config.kms_port);
    let addr = addr_str.parse().map_err(|e: AddrParseError| {
        warn!("grpc listen addr parse failed: {} ", e);
        StatusCode::FatalError
    })?;

    info!("start grpc server!");
    Server::builder()
        .add_service(KmsServiceServer::new(KmsServer::new(Arc::new(
            RwLock::new(kms),
        ))))
        .serve(addr)
        .await
        .map_err(|e| {
            warn!("start kms grpc server failed: {} ", e);
            StatusCode::FatalError
        })?;

    Ok(())
}
