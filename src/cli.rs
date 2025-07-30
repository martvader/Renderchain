use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "renderchain")]
#[command(version = "1.0")]
#[command(about = "RenderChain CLI - A Decentralized Rendering Network")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the mining node and RPC server
    Mine {
        /// Address from your wallet file to receive rewards
        #[arg(short, long)]
        wallet: String,
        /// Bind address for the RPC server
        #[arg(long, default_value = "127.0.0.1:9001")]
        rpc_bind: String,
    },

    /// Create a new wallet and add it to the collection
    CreateWallet {
        /// The wallet collection file
        #[arg(short, long, default_value = "wallets.json")]
        output: String,
    },

    /// Check blockchain status via RPC
    Status {
        /// Address of the RPC server to connect to
        #[arg(long, default_value = "127.0.0.1:9001")]
        rpc_connect: String,
    },

    /// Get the balance of an address via RPC
    GetBalance {
        /// The address to get the balance for
        #[arg(long)]
        address: String,
        /// Address of the RPC server to connect to
        #[arg(long, default_value = "127.0.0.1:9001")]
        rpc_connect: String,
    },
    
    /// Submit a new render job to the network
    SubmitJob {
        /// Path to the .blend scene file to be rendered
        #[arg(long)]
        scene_file: String,
    },

    /// Assemble the final image for a completed render job
    AssembleJob {
        /// The job ID of the job you want to assemble
        #[arg(long)]
        job_id: String,
        /// The output path for the final, stitched image
        #[arg(long, default_value = "final_render.png")]
        output: String,
    },

    /// Send a transaction by submitting it to the node via RPC
    Send {
        /// Sender address (must be in your wallet file)
        #[arg(long)]
        from: String,
        /// Recipient address
        #[arg(long)]
        to: String,
        /// Amount to send
        #[arg(long)]
        amount: u64,
        /// The wallet collection file to use
        #[arg(long, default_value = "wallets.json")]
        wallet: String,
        /// Address of the RPC server to connect to
        #[arg(long, default_value = "127.0.0.1:9001")]
        rpc_connect: String,
    },
}