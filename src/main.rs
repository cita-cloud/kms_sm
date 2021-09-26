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
    #[clap(short = 'd', long = "db", default_value = "kms.db")]
    db_path: String,
    /// Sets path of key_file.
    #[clap(short = 'k', long = "key")]
    key_file: Option<String>,
}

/// A subcommand for create
#[derive(Clap)]
struct CreateOpts {
    /// Sets path of db file.
    #[clap(short = 'd', long = "db", default_value = "kms.db")]
    db_path: String,
    /// Sets path of key_file.
    #[clap(short = 'k', long = "key")]
    key_file: Option<String>,
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
            // init log4rs
            log4rs::init_file("kms-log4rs.yaml", Default::default()).unwrap();
            info!("grpc port of this service: {}", opts.grpc_port);
            info!("db path of this service: {}", opts.db_path);
            match &opts.key_file {
                Some(key_file) => info!("key_file is {}", key_file),
                None => info!("interact mod"),
            }
            let _ = run(opts);
        }
        SubCommand::Create(opts) => {
            let _ = create(opts);
        }
    }
}

use cita_cloud_proto::common::{Empty, SimpleResponse, HashRespond, Hash};
use cita_cloud_proto::kms::{
    kms_service_server::KmsService, kms_service_server::KmsServiceServer, GenerateKeyPairRequest,
    GenerateKeyPairResponse, GetCryptoInfoResponse, HashDataRequest, HashDataResponse,
    RecoverSignatureRequest, RecoverSignatureResponse, SignMessageRequest, SignMessageResponse,
    VerifyDataHashRequest,
};
use tonic::{transport::Server, Request, Response, Status};

use kms::KMS;
use std::sync::Arc;
use tokio::sync::RwLock;
use status_code::StatusCode;
use cita_cloud_proto::blockchain::RawTransactions;

// grpc server of RPC
pub struct KmsServer {
    kms: Arc<RwLock<KMS>>,
}

impl KmsServer {
    fn new(kms: Arc<RwLock<KMS>>) -> Self {
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
        let reply = GetCryptoInfoResponse {
            status: Some(StatusCode::Success.into()),
            name: kms::CONFIG_TYPE.to_string(),
            hash_len: crypto::HASH_BYTES_LEN as u32,
            signature_len: crypto::SM2_SIGNATURE_BYTES_LEN as u32,
            address_len: crypto::ADDR_BYTES_LEN as u32,
        };
        Ok(Response::new(reply))
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
        kms.generate_key_pair(description).map(|(key_id, address)| {
            let reply = GenerateKeyPairResponse { key_id, address };
            Response::new(reply)
        })
    }

    async fn hash_data(
        &self,
        request: Request<HashDataRequest>,
    ) -> Result<Response<HashRespond>, Status> {
        debug!("hash_date request: {:?}", request);

        let req = request.into_inner();
        let data = req.data;

        let kms = self.kms.read().await;
        let reply = HashRespond {
            status: Some(StatusCode::Success.into()),
            hash: Some(Hash{
                hash: kms.hash_date(&data)
            }),
        };
        Ok(Response::new(reply))
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
        Ok(kms.verify_data_hash(data, hash).into())
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
        kms.sign_message(key_id, msg).map(|signature| {
            let reply = SignMessageResponse { signature };
            Response::new(reply)
        })
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
        kms.recover_signature(msg, signature).map(|address| {
            let reply = RecoverSignatureResponse { address };
            Response::new(reply)
        })
    }

    async fn check_transactions(&self, request: Request<RawTransactions>) -> Result<Response<cita_cloud_proto::common::StatusCode>, Status> {
        todo!()
    }
}

#[tokio::main]
async fn run(opts: RunOpts) -> Result<(), Box<dyn std::error::Error>> {
    let kms = KMS::new(&opts.db_path, &opts.key_file);

    let addr_str = format!("0.0.0.0:{}", opts.grpc_port);
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
    let kms = KMS::new(&opts.db_path, &opts.key_file);
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
