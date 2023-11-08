use crate::utils::get_cached_entry_by_name;
use crate::cmd::verify::VerificationProvider;
use super::{VerifyArgs, VerifyCheckArgs, etherscan::EtherscanVerificationProvider};

use foundry_common::zksolc_manager::DEFAULT_ZKSOLC_VERSION;

use foundry_cli::utils::LoadConfig;
// use crate::cmd::zkforge::verify::provider::VerificationProvider;
// use crate::cmd::forge::verify::EtherscanVerificationProvider;
use foundry_common::fs;
use foundry_utils::Retry;
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};
use tracing::warn;

use ethers::{
    // abi::Function,
    etherscan::{
        // utils::lookup_compiler_version,
        verify::CodeFormat,
        // Client,
    },
    // prelude::errors::EtherscanError,
    // solc::{artifacts::CompactContract, cache::CacheEntry, Project, Solc},
};

use reqwest;
// use eyre::Result;

use async_trait::async_trait;
// use ethers_core::types::Address;

use ethers::solc::ConfigurableContractArtifact;
use ethers::types::Address;

// pub static ZKSYNC_URL: &str = "https://zksync2-mainnet-explorer.zksync.io/contract_verification";
pub static ZKSYNC_URL: &str = "https://zksync2-testnet-explorer.zksync.dev/contract_verification";


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZksyncVerifyRequest {
    #[serde(rename = "contractAddress")]
    pub address: Address,
    #[serde(rename = "sourceCode")]
    pub source: String,
    #[serde(rename = "codeFormat")]
    pub code_format: CodeFormat,
    /// if codeformat=solidity-standard-json-input, then expected as
    /// `erc20.sol:erc20`
    #[serde(rename = "contractName")]
    pub contract_name: String,
    #[serde(rename = "compilerSolcVersion")]
    pub compiler_solc_version: String,
    #[serde(rename = "compilerZksolcVersion")]
    pub compiler_zksolc_version: String,
    /// applicable when codeformat=solidity-single-file
    #[serde(rename = "optimizationUsed", skip_serializing_if = "Option::is_none")]
    pub optimization_used: Option<String>,
    /// The constructor arguments for the contract, if any.
    ///
    /// NOTE: This is renamed as the misspelled `ethers-etherscan/src/verify.rs`. The reason for
    /// this is that Etherscan has had this misspelling on their API for quite a long time, and
    /// changing it would break verification with arguments.
    ///
    /// For instances (e.g. blockscout) that might support the proper spelling, the field
    /// `blockscout_constructor_arguments` is populated with the exact arguments passed to this
    /// field as well.
    #[serde(rename = "constructorArguements", skip_serializing_if = "Option::is_none")]
    pub constructor_arguments: Option<String>,
}


impl ZksyncVerifyRequest {
    pub fn new(
        address: Address,
        contract_name: String,
        source: String,
        compiler_solc_version: String,
        compiler_zksolc_version: String,
    ) -> Self {
        Self {
            address,
            contract_name,
            source,
            code_format: CodeFormat::StandardJsonInput,
            compiler_solc_version,
            compiler_zksolc_version,
            optimization_used: None,
            constructor_arguments: None,
        }
    }

    #[must_use]
    pub fn optimization(self, optimization: bool) -> Self {
        if optimization {
            self.optimized()
        } else {
            self.not_optimized()
        }
    }

    #[must_use]
    pub fn optimized(mut self) -> Self {
        self.optimization_used = Some("1".to_string());
        self
    }

    #[must_use]
    pub fn not_optimized(mut self) -> Self {
        self.optimization_used = Some("0".to_string());
        self
    }

    #[must_use]
    pub fn code_format(mut self, code_format: CodeFormat) -> Self {
        self.code_format = code_format;
        self
    }

    #[must_use]
    pub fn constructor_arguments(
        mut self,
        constructor_arguments: Option<impl Into<String>>,
    ) -> Self {
        let constructor_args = constructor_arguments.map(|s| {
            s.into()
                .trim()
                // TODO is this correct?
                .trim_start_matches("0x")
                .to_string()
        });
        self.constructor_arguments = constructor_args.clone();
        self
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ZkSyncVerificationProvider;

#[async_trait]
impl VerificationProvider for ZkSyncVerificationProvider {
    async fn preflight_check(&mut self, args: VerifyArgs) -> eyre::Result<()> {
        let _ = self.prepare_request(&args).await?;
        Ok(())
    }

    async fn verify(&mut self, args: VerifyArgs) -> eyre::Result<()>{
        let verify_args = self.prepare_request(&args).await?;

        // trace!("submitting verification request {:?}", body);
        // println!("submitting verification request {:?}", body);

        println!("forge::verify {:?}", verify_args);

        // println!("verifying contract with etherscan {:?}", etherscan);

        let client = reqwest::Client::new();

        let retry: Retry = args.retry.into();
        let resp = retry
            .run_async(|| {
                async {
                    println!(
                        "\nSubmitting verification for [{}] {:?}.",
                        args.contract.name,
                        // SimpleCast::to_checksum_address(&args.address)
                        args.address
                    );
                    let response = client
                        .post(args.verifier.verifier_url.as_deref().unwrap_or(ZKSYNC_URL))
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&verify_args)?)
                        .send()
                        .await?;

                    let status = response.status();

                    println!("zksync verification request for address ({}) submitted with status code {}", format_args!("{:?}", args.address), status);

                    if !status.is_success() {
                        let error: serde_json::Value = response.json().await?;
                        eprintln!(
                            "zkSync verification request for address ({}) failed with status code {}\nDetails: {:#}",
                            format_args!("{:?}", args.address),
                            status,
                            error
                        );
                        warn!("Failed verify submission: {:?}", error);
                        std::process::exit(1);
                    }

                    let text = response.text().await?;

                    println!("Response: {}", text);

                    Ok(Some(serde_json::from_str::<ZkSyncVerificationResponse>(&text)?))
                }
                .boxed()
            })
            .await?;

        self.process_zksync_response(resp.map(|r| r.result));
        Ok(())
    }

    async fn check(&self, args: VerifyCheckArgs) -> eyre::Result<()> {
        let retry: Retry = args.retry.into();
        
        Ok(())
    }
}

impl ZkSyncVerificationProvider {

    // Etherscan API request
    /// Configures the API request to the etherscan API using the given [`VerifyArgs`].
    async fn prepare_request(&self, args: &VerifyArgs) -> eyre::Result<ZksyncVerifyRequest> {
        let mut provider = EtherscanVerificationProvider::default();

        let config = args.try_load_config_emit_warnings()?;
        // let etherscan = provider.client(
        //     args.etherscan.chain.unwrap_or_default(),
        //     args.verifier.verifier_url.as_deref(),
        //     args.etherscan.key.as_deref(),
        //     &config,
        // )?;
        let verify_args = provider.create_verify_request(args, Some(config)).await?;

        let zksync_args = ZksyncVerifyRequest::new(
            verify_args.address,
            verify_args.contract_name,
            verify_args.source,
            verify_args.compiler_version,
            DEFAULT_ZKSOLC_VERSION.to_owned(),
        ).constructor_arguments(verify_args.constructor_arguments);
        // .code_format(verify_args.code_format);


            // let mut verify_args =
            // VerifyContract::new(args.address, contract_name, source, compiler_version)
            //     .constructor_arguments(constructor_args)
            //     .code_format(code_format);

        // if code_format == CodeFormat::SingleFile {
        //     verify_args = if let Some(optimizations) = args.num_of_optimizations {
        //         verify_args.optimized().runs(optimizations as u32)
        //     } else if config.optimizer {
        //         verify_args.optimized().runs(config.optimizer_runs.try_into()?)
        //     } else {
        //         verify_args.not_optimized()
        //     };
        // }

        // Ok(verify_args)
        Ok(zksync_args)
    }

    async fn prepare_request__(&self, args: &VerifyArgs) -> eyre::Result<()> {
        // let provider = EtherscanVerificationProvider::default();

        // let config = args.try_load_config_emit_warnings()?;
        // let etherscan = provider.client(
        //     args.etherscan.chain.unwrap_or_default(),
        //     args.verifier.verifier_url.as_deref(),
        //     args.etherscan.key.as_deref(),
        //     &config,
        // )?;
        // let verify_args = provider.create_verify_request(args, Some(config)).await?;

        // Ok((etherscan, verify_args));

        // export interface ZkSyncBlockExplorerVerifyRequest {
        //     contractAddress: string;
        //     contractName: string;
        //     sourceCode: string | CompilerInput;
        //     codeFormat: string;
        //     compilerSolcVersion: string;
        //     compilerZksolcVersion: string;
        //     optimizationUsed: boolean;
        //     constructorArguments: string;
        // }

        let mut config = args.try_load_config_emit_warnings()?;
        config.libraries.extend(args.libraries.clone());

        let project = config.project()?;

        if !config.cache {
            eyre::bail!("Cache is required for zkSync verification.")
        }

        let cache = project.read_cache_file()?;
        let (path, entry) = get_cached_entry_by_name(&cache, &args.contract.name)?;

        if entry.solc_config.settings.metadata.is_none() {
            eyre::bail!(
                r#"Contract {} was compiled without the solc `metadata` setting.
zkSync requires contract metadata for verification.
metadata output can be enabled via `extra_output = ["metadata"]` in `foundry.toml`"#,
                args.contract.name
            )
        }

        let mut files = HashMap::with_capacity(2 + entry.imports.len());

        let artifact_path = entry
            .find_artifact_path(&args.contract.name)
            .ok_or_else(|| eyre::eyre!("No artifact found for contract {}", args.contract.name))?;

        let artifact: ConfigurableContractArtifact = fs::read_json_file(artifact_path)?;
        if let Some(metadata) = artifact.metadata {
            let metadata = serde_json::to_string_pretty(&metadata)?;
            files.insert("metadata.json".to_string(), metadata);
        } else {
            eyre::bail!(
                r#"No metadata found in artifact `{}` for contract {}.
zkSync requires contract metadata for verification.
metadata output can be enabled via `extra_output = ["metadata"]` in `foundry.toml`"#,
                artifact_path.display(),
                args.contract.name
            )
        }

        let contract_path = args.contract.path.clone().map_or(path, PathBuf::from);
        let filename = contract_path.file_name().unwrap().to_string_lossy().to_string();
        files.insert(filename, fs::read_to_string(&contract_path)?);

        for import in entry.imports {
            let import_entry = format!("{}", import.display());
            files.insert(import_entry, fs::read_to_string(&import)?);
        }

        // let req = ZkSyncVerifyRequest {
        //     address: format!("{:?}", args.address),
        //     chain: args.etherscan.chain.unwrap_or_default().id().to_string(),
        //     files,
        //     chosen_contract: None,
        // };

        // Ok(req)

        Ok(())
    }

    fn process_zksync_response(&self, response: Option<Vec<ZkSyncResponseElement>>) {
        let response = response.unwrap().remove(0);
        if response.status == "successful" {
            if let Some(ts) = response.storage_timestamp {
                println!("Contract source code already verified. Storage Timestamp: {ts}");
            } else {
                println!("Contract successfully verified")
            }
        } else if response.status == "failed" {
            println!("Contract source code is not verified")
        } else if response.status == "queued" {
            println!("Contract source code is being verified")
        } else if response.status == "in_progress" {
            println!("Contract source code is being verified")
        } else if response.status == "partial" {
            println!("?? The recompiled contract partially matches the deployed version")
        } else if response.status == "false" {
            println!("Contract source code is not verified")
        } else {
            eprintln!("Unknown status from zkSync. Status: {}", response.status);
            std::process::exit(1);
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ZkSyncVerificationResponse {
    result: Vec<ZkSyncResponseElement>,
}

#[derive(Deserialize, Debug)]
pub struct ZkSyncResponseElement {
    status: String,
    #[serde(rename = "storageTimestamp")]
    storage_timestamp: Option<String>,
}
