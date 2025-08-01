#![allow(dead_code)]
mod consensus;
mod core;
mod address;
mod wallet;
mod wallets;
mod oracle_api;
mod mempool;
mod cli;
mod job_pool;

use crate::cli::{Cli, Commands};
use crate::core::blockchain::Blockchain;
use crate::consensus::pow::{ProofOfWork, PowError};
use crate::core::block::Block;
use crate::core::transaction::{Transaction, TXInput, TXOutput};
use crate::wallets::Wallets;
use crate::address::Network;
use crate::mempool::Mempool;
use crate::job_pool::JobPool;
use crate::oracle_api::WorkUnit;
use anyhow::{Result, anyhow, Context};
use bs58;
use clap::Parser;
use env_logger::Env;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Mine { wallet, rpc_bind } => run_miner(wallet, rpc_bind).await,
        Commands::CreateWallet { output } => create_wallet(output),
        Commands::Status { rpc_connect } => show_blockchain_status(rpc_connect).await,
        Commands::GetBalance { address, rpc_connect } => get_balance(address, rpc_connect).await,
        Commands::SubmitJob { scene_file } => {
            let rpc_connect = "127.0.0.1:9001".to_string();
            submit_job(scene_file, rpc_connect).await
        },
        Commands::AssembleJob { job_id, output } => assemble_job(job_id, output).await,
        Commands::Send { from, to, amount, wallet, rpc_connect } => send_transaction(from, to, amount, wallet, rpc_connect).await,
    }
}

async fn run_miner(wallet_address: String, rpc_bind: String) -> Result<()> {
    log::info!("Starting RenderChain node...");
    let wallets = Wallets::load_from_file("wallets.json")?;
    let miner_wallet = wallets.get_wallet(&wallet_address).ok_or_else(|| anyhow!("Wallet not found"))?;
    let blockchain = Arc::new(Mutex::new(Blockchain::new()?));
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let job_pool = Arc::new(Mutex::new(JobPool::new()));

    let listener = TcpListener::bind(&rpc_bind).await?;
    log::info!("RPC server listening on {}", rpc_bind);
    
    let bc_for_rpc = blockchain.clone();
    let mempool_for_rpc = mempool.clone();
    let job_pool_for_rpc = job_pool.clone();
    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let bc_clone = bc_for_rpc.clone();
                let mempool_clone = mempool_for_rpc.clone();
                let job_pool_clone = job_pool_for_rpc.clone();
                tokio::spawn(async move {
                    let mut buffer = [0; 8192]; 
                    if let Ok(n) = stream.read(&mut buffer).await {
                        let request_str = String::from_utf8_lossy(&buffer[..n]);
                        let response = handle_rpc_request(&request_str, bc_clone, mempool_clone, job_pool_clone).await;
                        if let Err(e) = stream.write_all(response.as_bytes()).await {
                            log::error!("Failed to write RPC response: {}", e);
                        }
                    }
                });
            }
        }
    });
    
    {
        let bc = blockchain.lock().unwrap();
        log::info!("Blockchain initialized with height: {}", bc.height);
        log::info!("Tip: {}", hex::encode(&bc.tip));
        log::info!("Miner address: {}", miner_wallet.get_address(Network::Mainnet));
    }
    log::info!("Starting mining loop... Waiting for jobs to be submitted.");
    
    loop {
        let has_jobs = {
            let job_pool_guard = job_pool.lock().unwrap();
            !job_pool_guard.is_empty()
        };

        if !has_jobs {
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        log::info!("Jobs available. Starting new mining round...");
        
        let miner_address_str = miner_wallet.get_address(Network::Mainnet);
        let decoded_address = bs58::decode(&miner_address_str).into_vec()?;
        let miner_pub_key_hash = decoded_address[1..decoded_address.len() - 4].to_vec();
        
        let new_block_candidate = {
            let bc = blockchain.lock().unwrap();
            let coinbase_tx = Transaction::new_coinbase_tx(&miner_pub_key_hash, format!("Block #{} reward", bc.height + 1));
            let mut transactions = vec![coinbase_tx];
            let mut mempool_guard = mempool.lock().unwrap();
            let pending = mempool_guard.drain_pending_transactions(10);
            
            if !pending.is_empty() { log::info!("Including {} transactions from mempool.", pending.len()); }
            transactions.extend(pending);
            Block::new(1, transactions.clone(), bc.tip.clone())?
        };
        
        let mut pow = ProofOfWork::new(new_block_candidate);
        
        match pow.run(job_pool.clone()) {
            Ok((certificates, winning_nonce)) => {
                let mut finalized_block = pow.into_block();
                finalized_block.finalize(certificates.clone(), winning_nonce)?;
                
                let mut bc_lock = blockchain.lock().unwrap();
                if let Err(e) = bc_lock.add_block(finalized_block.clone()) {
                    log::error!("Failed to add block: {}", e);
                } else {
                    log::info!("✅ Mined block #{} with {} proof(s). New tip: {}", 
                        bc_lock.height, 
                        finalized_block.proofs.len(), 
                        hex::encode(&bc_lock.tip)
                    );

                    // =================== NEW IPFS LOGIC STARTS HERE ===================
                    // Check if the mined tile was the last one for a job.
                    if let Some(cert) = certificates.first() {
                        let result = &cert.simulation_result;
                        
                        // The job is complete if the tile index is one less than the total.
                        if result.tile_index == result.total_tiles - 1 {
                            log::info!("🎉 Final tile for job '{}' mined. Beginning assembly and upload.", cert.task_id);
                            
                            // Spawn a new async task for assembly so it doesn't block the main mining loop.
                            let job_id_clone = cert.task_id.clone();
                            tokio::spawn(async move {
                                if let Err(e) = assemble_and_publish_result(&job_id_clone).await {
                                    log::error!("[Assembler] Failed to publish result for job {}: {}", job_id_clone, e);
                                }
                            });
                        }
                    }
                    // =================== NEW IPFS LOGIC ENDS HERE ===================
                }
            }
            Err(PowError::AbortedForNewJob) => {
                log::info!("Mining round aborted, job likely completed or pool is empty. Checking again...");
            }
            Err(e) => {
                log::error!("❌ Mining failed: {}", e);
            },
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn create_unsigned_transaction(from: &str, to: &str, amount: u64, bc: &Blockchain) -> Result<Transaction> {
    let from_pub_key_hash = bs58::decode(from).into_vec()?[1..21].to_vec();
    let to_pub_key_hash = bs58::decode(to).into_vec()?[1..21].to_vec();
    let (accumulated, spendable_outputs) = bc.find_spendable_outputs(&from_pub_key_hash, amount)?;
    let mut inputs = vec![];
    for (txid, outs) in spendable_outputs {
        for out_idx in outs {
            inputs.push(TXInput { txid: txid.clone(), vout: out_idx, signature: vec![], pub_key: vec![] });
        }
    }
    let mut outputs = vec![TXOutput { value: amount, pub_key_hash: to_pub_key_hash }];
    if accumulated > amount {
        outputs.push(TXOutput { value: accumulated - amount, pub_key_hash: from_pub_key_hash });
    }
    let mut tx = Transaction { id: vec![], vin: inputs, vout: outputs };
    tx.id = tx.hash()?;
    Ok(tx)
}

async fn handle_rpc_request(request: &str, bc_arc: Arc<Mutex<Blockchain>>, mempool_arc: Arc<Mutex<Mempool>>, job_pool_arc: Arc<Mutex<JobPool>>) -> String {
    let parts: Vec<&str> = request.trim().splitn(2, ' ').collect();
    
    match parts.as_slice() {
        ["get_balance", args] => {
            let addr = args.trim();
            if let Ok(decoded) = bs58::decode(addr).into_vec() {
                if decoded.len() > 4 {
                    let pkh = &decoded[1..decoded.len() - 4];
                    format!("OK balance {}", bc_arc.lock().unwrap().get_balance(pkh))
                } else {
                    format!("ERR InvalidAddressLength: Address '{}' is too short.", addr)
                }
            } else {
                format!("ERR InvalidAddressFormat: Could not decode address '{}'.", addr)
            }
        }
        ["get_status"] => {
            let bc = bc_arc.lock().unwrap();
            format!("OK status height={} tip={}", bc.height, hex::encode(&bc.tip))
        }
        ["create_unsigned_tx", args] => {
            let sub_parts: Vec<&str> = args.split_whitespace().collect();
            if let [from, to, amount_str] = sub_parts.as_slice() {
                match amount_str.parse::<u64>() {
                    Ok(amount) => {
                        let bc = bc_arc.lock().unwrap();
                        match create_unsigned_transaction(from, to, amount, &bc) {
                            Ok(tx) => format!("OK unsigned_tx {}", hex::encode(bincode::serialize(&tx).unwrap())),
                            Err(e) => format!("ERR CreateTxFailed: {}", e),
                        }
                    }
                    Err(_) => format!("ERR InvalidAmount: Could not parse '{}' as a number.", amount_str),
                }
            } else {
                format!("ERR InvalidArgs: Expected 'from to amount', got '{}'", args)
            }
        }
        ["submit_tx", tx_hex] => {
            match hex::decode(tx_hex.trim()) {
                Ok(tx_bytes) => {
                    match bincode::deserialize::<Transaction>(&tx_bytes) {
                        Ok(tx) => {
                            let txid = tx.id.clone();
                            mempool_arc.lock().unwrap().add_transaction(tx);
                            format!("OK tx_submitted {}", hex::encode(&txid))
                        },
                        Err(e) => format!("ERR InvalidTransactionData: Could not deserialize. Bincode error: {}", e)
                    }
                },
                Err(_) => format!("ERR InvalidHex: Could not decode hex string.")
            }
        }
        ["submit_job", scene_file] => {
            match std::fs::canonicalize(scene_file.trim()) {
                Ok(path) => {
                    let absolute_scene_file = path.to_string_lossy();
                    let job_id = format!("job_{}", chrono::Utc::now().timestamp_micros());
                    log::info!("New render job received: {}. Queuing tiles for {}...", &job_id, &absolute_scene_file);

                    let work_units = WorkUnit::generate_tile_work_units(&job_id, &absolute_scene_file);
                    let total_tiles = work_units.len();
                    
                    let mut job_pool_guard = job_pool_arc.lock().unwrap();
                    job_pool_guard.add_jobs(work_units);
                    
                    log::info!("All {} tiles for job {} have been queued.", total_tiles, &job_id);
                    format!("OK job_submitted {}", job_id)
                },
                Err(e) => {
                    format!("ERR SceneFileNotFound: Could not find '{}'. OS error: {}", scene_file.trim(), e)
                }
            }
        }
        _ => format!("ERR InvalidCommand: Received '{}'", request.trim()),
    }
}

// =================== NEW IPFS HELPER FUNCTION ===================
async fn assemble_and_publish_result(job_id: &str) -> Result<()> {
    // 1. Assemble the final image
    log::info!("[Assembler] Assembling final image for job '{}'...", job_id);
    let output_path_str = format!("./render_output/{}_final.png", job_id);
    let output_path = PathBuf::from(&output_path_str);
    
    consensus::pow::RenderEngine::assemble_final_image(job_id, &output_path)
        .context("Failed to assemble final image")?;
    log::info!("[Assembler] Image assembled at '{}'", output_path.display());

    // 2. Add the final image to IPFS using the command line
    log::info!("[Assembler] Adding final image to IPFS...");
    let ipfs_output = tokio::process::Command::new("ipfs")
        .arg("add")
        .arg("--quieter")
        .arg(&output_path)
        .output()
        .await
        .context("Failed to execute IPFS command. Is the IPFS daemon running?")?;

    if !ipfs_output.status.success() {
        return Err(anyhow!("IPFS command failed: {}", String::from_utf8_lossy(&ipfs_output.stderr)));
    }

    let ipfs_cid = String::from_utf8(ipfs_output.stdout)?.trim().to_string();
    log::info!("🎉🎉🎉 Job '{}' is complete and available on IPFS! 🎉🎉🎉", job_id);
    log::info!("IPFS Content ID (CID): {}", ipfs_cid);
    log::info!("Public Gateway URL: https://ipfs.io/ipfs/{}", ipfs_cid);
    log::info!("(Note: Public gateways can be slow. Use `ipfs get {}` for a faster download if you have IPFS installed.)", ipfs_cid);

    Ok(())
}

fn create_wallet(output: String) -> Result<()> {
    let mut wallets = Wallets::load_from_file(&output)?;
    let new_address = wallets.add_wallet();
    wallets.save_to_file(&output)?;
    println!("Updated wallet file: {}", output);
    println!("Added new address: {}", new_address);
    Ok(())
}

async fn show_blockchain_status(rpc_connect: String) -> Result<()> {
    let mut stream = TcpStream::connect(rpc_connect).await?;
    stream.write_all(b"get_status").await?;
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    if !response.starts_with("OK") {
        log::error!("Failed to get status from node: {}", response);
    } else {
        println!("Blockchain Status:\n{}", response);
    }
    Ok(())
}

async fn get_balance(address: String, rpc_connect: String) -> Result<()> {
    let command = format!("get_balance {}", address);
    let mut stream = TcpStream::connect(rpc_connect).await?;
    stream.write_all(command.as_bytes()).await?;
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    if response.starts_with("OK") {
        let parts: Vec<&str> = response.split_whitespace().collect();
        println!("Balance for address {}: {} FOLD", address, parts[2]);
    } else {
        log::error!("Failed to get balance from node: {}", response);
    }
    Ok(())
}

async fn submit_job(scene_file: String, rpc_connect: String) -> Result<()> {
    log::info!("Submitting render job for scene: {}", scene_file);
    let command = format!("submit_job {}", scene_file);
    let mut stream = TcpStream::connect(&rpc_connect).await?;
    stream.write_all(command.as_bytes()).await?;
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    if response.starts_with("OK") {
        let parts: Vec<&str> = response.split_whitespace().collect();
        println!("Success! Job submitted to the node.");
        println!("JOB_ID: {}", parts[2]);
    } else {
        log::error!("Failed to submit job: {}", response);
    }
    Ok(())
}

async fn send_transaction(from: String, to: String, amount: u64, wallet_file: String, rpc_connect: String) -> Result<()> {
    log::info!("Requesting unsigned transaction from the node...");
    let command = format!("create_unsigned_tx {} {} {}", from, to, amount);
    let mut stream = TcpStream::connect(&rpc_connect).await?;
    stream.write_all(command.as_bytes()).await?;
    let mut buffer = [0; 8192];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    let parts: Vec<&str> = response.split_whitespace().collect();
    let unsigned_tx_hex = match parts.as_slice() {
        ["OK", "unsigned_tx", hex_str] => *hex_str,
        ["ERR", ..] => return Err(anyhow!("Node returned an error: {}", response)),
        _ => return Err(anyhow!("Invalid response from node: {}", response)),
    };
    let tx_bytes = hex::decode(unsigned_tx_hex)?;
    let mut unsigned_tx: Transaction = bincode::deserialize(&tx_bytes)?;
    log::info!("Received unsigned transaction with TXID: {}", hex::encode(&unsigned_tx.id));
    let wallets = Wallets::load_from_file(&wallet_file)?;
    let sender_wallet = wallets.get_wallet(&from).ok_or_else(|| anyhow!("Sender wallet not found in {}", wallet_file))?;
    let bc_readonly = Blockchain::new_readonly()?;
    let mut prev_txs = HashMap::new();
    for vin in &unsigned_tx.vin {
        let prev_tx = bc_readonly.find_transaction(&vin.txid)?.ok_or_else(|| anyhow!("A referenced transaction was not found"))?;
        prev_txs.insert(vin.txid.clone(), prev_tx);
    }
    sender_wallet.sign_transaction(&mut unsigned_tx, prev_txs).map_err(|e| anyhow!(e))?;
    log::info!("Transaction signed locally.");
    let signed_tx_hex = hex::encode(bincode::serialize(&unsigned_tx)?);
    let submit_command = format!("submit_tx {}", signed_tx_hex);
    let mut stream = TcpStream::connect(&rpc_connect).await?;
    stream.write_all(submit_command.as_bytes()).await?;
    let n = stream.read(&mut buffer).await?;
    let final_response = String::from_utf8_lossy(&buffer[..n]);
    let final_parts: Vec<&str> = final_response.trim().split_whitespace().collect();
    if let ["OK", "tx_submitted", txid] = final_parts.as_slice() {
        println!("Success! Transaction submitted to the node.");
        println!("TXID: {}", txid);
        println!("Wait for the next block to be mined for confirmation.");
    } else { log::error!("Failed to submit transaction: {}", final_response); }
    Ok(())
}

async fn assemble_job(job_id: String, output_path: String) -> Result<()> {
    log::info!("Starting assembly for job ID: {}", job_id);
    let bc = Blockchain::new_readonly()?;
    let output_dir = std::env::current_dir()?.join("render_output");
    
    log::info!("Scanning blockchain for completed tiles for job '{}'...", &job_id);
    let mut current_hash = bc.tip.clone();
    let mut verified_tiles = HashSet::new();
    loop {
        let block_data = match bc.db.get(&current_hash)? {
            Some(data) => data,
            None => {
                log::warn!("Block not found in DB for hash: {}. Reached end of scannable chain.", hex::encode(current_hash));
                break;
            }
        };
        let block: Block = bincode::deserialize(&block_data)?;

        for cert in &block.proofs {
            if cert.task_id == job_id {
                let result = &cert.simulation_result;
                
                if verified_tiles.contains(&result.tile_index) { continue; }
                
                log::info!("Found proof for tile #{}. Verifying with nonce {}...", result.tile_index, result.nonce);

                let miner_filename = format!("tile_{}_{}_miner.png", result.tile_index, result.nonce);
                let miner_filepath = output_dir.join(&miner_filename);

                if !miner_filepath.exists() {
                    log::warn!("Cannot verify tile #{}: miner's output file not found at {}", result.tile_index, miner_filepath.display());
                    continue;
                }

                let file_bytes = fs::read(&miner_filepath).with_context(|| format!("Failed to read miner file: {}", miner_filepath.display()))?;
                let mut hasher = Sha256::new();
                hasher.update(&file_bytes);
                let calculated_hash = hex::encode(hasher.finalize());

                if calculated_hash == result.output_hash {
                    log::info!("✅ Hash verified for tile #{}.", result.tile_index);
                    verified_tiles.insert(result.tile_index);
                } else {
                    log::warn!("HASH MISMATCH for tile #{}. On-chain: {}, Calculated: {}. Skipping.", 
                               result.tile_index, &result.output_hash[..10], &calculated_hash[..10]);
                }
            }
        }
        
        if block.prev_hash.is_empty() || block.prev_hash == vec![0; 32] { break; }
        current_hash = block.prev_hash;
    }

    if verified_tiles.is_empty() {
        return Err(anyhow!("Could not find any completed tiles for job '{}' on the blockchain.", job_id));
    }

    consensus::pow::RenderEngine::assemble_final_image(&job_id, &PathBuf::from(output_path))
        .context("Failed to assemble final image")?;
    
    Ok(())
}