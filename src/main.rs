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
use crate::consensus::pow::ProofOfWork;
use crate::core::block::Block;
use crate::core::transaction::{Transaction, TXInput, TXOutput};
use crate::wallets::Wallets;
use crate::address::Network;
use crate::mempool::Mempool;
use crate::job_pool::JobPool;
use crate::oracle_api::WorkUnit;
use anyhow::{Result, anyhow};
use bs58;
use clap::Parser;
use env_logger::Env;
use image::{ImageBuffer, RgbaImage};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
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
        Commands::SubmitJob { scene_file, rpc_connect } => submit_job(scene_file, rpc_connect).await,
        Commands::AssembleJob { scene_file, output } => assemble_job(scene_file, output).await,
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
    log::info!("Starting mining loop...");
    
    loop {
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
                finalized_block.finalize(certificates, winning_nonce)?;
                
                let mut bc_lock = blockchain.lock().unwrap();
                if let Err(e) = bc_lock.add_block(finalized_block.clone()) {
                    log::error!("Failed to add block: {}", e);
                } else {
                    log::info!("✅ Mined block #{} with {} transaction(s). New tip: {}", bc_lock.height, finalized_block.transactions.len(), hex::encode(&bc_lock.tip));
                }
            }
            Err(e) => {
                match e {
                    crate::consensus::pow::PowError::AbortedForNewJob => {
                        // This is expected when the job pool is empty. Wait before checking again.
                    }
                    _ => {
                        log::error!("❌ Mining failed: {}", e);
                    }
                }
            },
        }
        thread::sleep(Duration::from_secs(1));
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
    let mut outputs = vec![];
    outputs.push(TXOutput { value: amount, pub_key_hash: to_pub_key_hash });
    if accumulated > amount {
        outputs.push(TXOutput { value: accumulated - amount, pub_key_hash: from_pub_key_hash });
    }
    let mut tx = Transaction { id: vec![], vin: inputs, vout: outputs };
    tx.id = tx.hash()?;
    Ok(tx)
}

async fn handle_rpc_request(request: &str, bc_arc: Arc<Mutex<Blockchain>>, mempool_arc: Arc<Mutex<Mempool>>, job_pool_arc: Arc<Mutex<JobPool>>) -> String {
    let parts: Vec<&str> = request.trim().split_whitespace().collect();
    match parts.as_slice() {
        ["get_balance", addr] => {
            if let Ok(decoded) = bs58::decode(addr).into_vec() {
                if decoded.len() > 4 {
                    let pkh = &decoded[1..decoded.len() - 4];
                    let balance = bc_arc.lock().unwrap().get_balance(pkh);
                    format!("OK balance {}", balance)
                } else { "ERR InvalidAddressLength".to_string() }
            } else { "ERR InvalidAddressFormat".to_string() }
        }
        ["get_status"] => {
            let bc = bc_arc.lock().unwrap();
            format!("OK status height={} tip={}", bc.height, hex::encode(&bc.tip))
        }
        ["create_unsigned_tx", from, to, amount_str] => {
            match amount_str.parse::<u64>() {
                Ok(amount) => {
                    let bc = bc_arc.lock().unwrap();
                    match create_unsigned_transaction(from, to, amount, &bc) {
                        Ok(tx) => format!("OK unsigned_tx {}", hex::encode(bincode::serialize(&tx).unwrap())),
                        Err(e) => format!("ERR {}", e.to_string()),
                    }
                }
                Err(_) => "ERR InvalidAmount".to_string(),
            }
        }
        ["submit_tx", tx_hex] => {
            if let Ok(tx_bytes) = hex::decode(tx_hex) {
                if let Ok(tx) = bincode::deserialize::<Transaction>(&tx_bytes) {
                    let txid = tx.id.clone();
                    mempool_arc.lock().unwrap().add_transaction(tx);
                    format!("OK tx_submitted {}", hex::encode(&txid))
                } else { "ERR InvalidTransactionData".to_string() }
            } else { "ERR InvalidHex".to_string() }
        }
        ["submit_job", scene_file] => {
            // PATH NORMALIZATION: Remove Windows verbatim prefix
            let absolute_scene_file = match std::fs::canonicalize(scene_file) {
                Ok(path) => {
                    let p = path.to_string_lossy().into_owned();
                    if p.starts_with(r"\\?\") {
                        p[4..].to_string()  // Remove verbatim prefix
                    } else {
                        p
                    }
                }
                Err(e) => return format!("ERR Cannot find scene file: {}", e),
            };

            const TOTAL_TILES: u32 = 16; 
            let job_id = format!("job_{}", chrono::Utc::now().timestamp_micros());
            log::info!("New render job received: {}. Queuing {} tiles for {}...", &job_id, TOTAL_TILES, &absolute_scene_file);
            let mut job_pool_guard = job_pool_arc.lock().unwrap();
            for i in 0..TOTAL_TILES {
                let job = WorkUnit {
                    task_id: job_id.clone(),
                    tile_index: i,
                    scene_file: absolute_scene_file.clone(), // Store normalized path
                    render_settings: "{}".to_string(),
                };
                job_pool_guard.add_job(job);
            }
            log::info!("All {} tiles for job {} have been queued.", TOTAL_TILES, &job_id);
            format!("OK job_submitted {}", job_id)
        }
        _ => "ERR InvalidCommand".to_string(),
    }
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
    let parts: Vec<&str> = response.trim().split_whitespace().collect();
    if let ["OK", "status", height_part, tip_part] = parts.as_slice() {
        println!("Blockchain Status:");
        println!("  {}", height_part);
        println!("  {}", tip_part);
    } else { log::error!("Failed to get status from node: {}", response); }
    Ok(())
}

async fn get_balance(address: String, rpc_connect: String) -> Result<()> {
    let command = format!("get_balance {}", address);
    let mut stream = TcpStream::connect(rpc_connect).await?;
    stream.write_all(command.as_bytes()).await?;
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    let parts: Vec<&str> = response.trim().split_whitespace().collect();
    if let ["OK", "balance", balance_str] = parts.as_slice() {
        println!("Balance for address {}: {} FOLD", address, balance_str);
    } else { log::error!("Failed to get balance from node: {}", response); }
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
    let parts: Vec<&str> = response.trim().split_whitespace().collect();
    if let ["OK", "job_submitted", job_id] = parts.as_slice() {
        println!("Success! Job submitted to the node.");
        println!("JOB_ID: {}", job_id);
    } else { log::error!("Failed to submit job: {}", response); }
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
    let parts: Vec<&str> = response.trim().split_whitespace().collect();
    let unsigned_tx_hex = match parts.as_slice() {
        ["OK", "unsigned_tx", hex_str] => *hex_str,
        ["ERR", err_msg] => return Err(anyhow!("Node returned an error: {}", err_msg)),
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

async fn assemble_job(scene_file: String, output_path: String) -> Result<()> {
    log::info!("Starting assembly for job: {}", scene_file);
    let bc = Blockchain::new_readonly()?;
    let mut completed_tiles = HashMap::<u32, Vec<u8>>::new();

    log::info!("Scanning blockchain for completed tiles...");
    let mut current_hash = bc.tip.clone();
    loop {
        let block_data = bc.db.get(current_hash.clone())?.ok_or_else(|| anyhow!("Block not found"))?;
        let block: Block = bincode::deserialize(&block_data)?;

        for cert in block.proofs {
            let result = cert.simulation_result.clone();
            
            // Compare by file name only, not full path
            if Path::new(&result.scene_file).file_name() == Path::new(&scene_file).file_name() {
                if !completed_tiles.contains_key(&result.tile_index) {
                    log::info!("Found proof for tile #{}. Verifying with nonce {}...", result.tile_index, result.nonce);
                    log::debug!("On-chain scene path: {}", result.scene_file);
                    log::debug!("User-provided scene path: {}", scene_file);
                    
                    // Use the USER'S scene file path, not the blockchain's absolute path
                    let work_unit_for_regen = WorkUnit {
                        task_id: "assembly_regen".to_string(),
                        tile_index: result.tile_index,
                        scene_file: scene_file.clone(), // Critical fix
                        render_settings: "{}".to_string(),
                    };
                    
                    let image_bytes = consensus::pow::RenderEngine::run(&work_unit_for_regen, result.nonce,"regen")?;
                    
                    let mut hasher = Sha256::new();
                    hasher.update(&image_bytes);
                    let calculated_hash = hex::encode(hasher.finalize());
                    
                    if calculated_hash == result.output_hash {
                        log::info!("Verification successful for tile #{}.", result.tile_index);
                        completed_tiles.insert(result.tile_index, image_bytes);
                    } else {
                        log::warn!("HASH MISMATCH for tile #{}. On-chain: {}, Calculated: {}. Skipping.", 
                                   result.tile_index, &result.output_hash[..10], &calculated_hash[..10]);
                    }
                }
            }
        }
        
        if block.prev_hash == vec![0; 32] { break; }
        current_hash = block.prev_hash;
    }

    if completed_tiles.is_empty() {
        log::warn!("No valid & completed tiles found for this job on the blockchain.");
        return Ok(());
    }
    
    let (img_width, img_height) = (1024, 768);
    let (tile_count_x, tile_count_y) = (4, 4);
    let tile_width = img_width / tile_count_x;
    let tile_height = img_height / tile_count_y;

    log::info!("Stitching {} completed tiles into final image...", completed_tiles.len());
    let mut final_image: RgbaImage = ImageBuffer::new(img_width, img_height);

    for (tile_index, image_bytes) in completed_tiles {
        let tile_img = image::load_from_memory(&image_bytes)?.to_rgba8();
        let tile_x_coord = (tile_index % tile_count_x) * tile_width;
        let tile_y_coord = (tile_index / tile_count_x) * tile_height;
        image::imageops::overlay(&mut final_image, &tile_img, tile_x_coord as i64, tile_y_coord as i64);
    }

    final_image.save(&output_path)?;
    log::info!("Assembly complete! Final image saved to: {}", output_path);
    Ok(())
}