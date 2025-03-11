use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use edge_frontend::{
  noir::NoirProgram,
  program::{self, Configuration, Switchboard, RAM, Z0_SECONDARY},
  setup::Setup,
  CompressedSNARK, Scalar,
};
use tracing::{debug, info, trace, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Creates a Noir program that is the even case of the function in the Collatz conjecture.
pub fn collatz_even() -> NoirProgram {
  let path = std::path::PathBuf::from("target/collatz_even.json");

  // Get the current working directory
  let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
  let absolute_path = current_dir.join(&path);

  match std::fs::read(&path) {
    Ok(bytecode) => NoirProgram::new(&bytecode),
    Err(e) => {
      panic!(
        "Failed to read Noir program file.\nRelative path: '{}'\nAbsolute path: '{}'\nError: {}",
        path.display(),
        absolute_path.display(),
        e
      );
    },
  }
}

/// Creates a Noir program that is the odd case of the function in the Collatz conjecture.
pub fn collatz_odd() -> NoirProgram {
  let path = std::path::PathBuf::from("target/collatz_odd.json");

  // Get the current working directory
  let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
  let absolute_path = current_dir.join(&path);

  match std::fs::read(&path) {
    Ok(bytecode) => NoirProgram::new(&bytecode),
    Err(e) => {
      panic!(
        "Failed to read Noir program file.\nRelative path: '{}'\nAbsolute path: '{}'\nError: {}",
        path.display(),
        absolute_path.display(),
        e
      );
    },
  }
}

#[derive(Parser)]
#[command(author, version, about = "Demo application for edge-frontend", long_about = None)]
struct Cli {
  /// Verbosity level (-v = info, -vv = debug, -vvv = trace)
  #[arg( short,long, action = clap::ArgAction::Count, global = true)]
  verbose: u8,

  #[command(subcommand)]
  command: Commands,
}

#[derive(Subcommand)]
enum Commands {
  /// Run the offline setup phase
  Setup {
    /// Path to save the setup file
    #[arg(short, long, default_value = "setup.bytes")]
    output: PathBuf,
  },
  /// Generate and compress a proof
  Prove {
    /// Input value for the Collatz program
    #[arg(short, long)]
    input: u64,

    /// Path to the setup file
    #[arg(short, long, default_value = "setup.bytes")]
    setup: PathBuf,

    /// Path to save the proof file
    #[arg(short, long, default_value = "proof.bytes")]
    output: PathBuf,
  },
  /// Verify a compressed proof
  Verify {
    /// Input value for the Collatz program
    #[arg(short, long)]
    input: u64,

    /// Path to the setup file
    #[arg(short, long, default_value = "setup.bytes")]
    setup: PathBuf,

    /// Path to the proof file
    #[arg(short, long, default_value = "proof.bytes")]
    proof: PathBuf,
  },
}

fn setup_logging(verbosity: u8) {
  let level = match verbosity {
    0 => Level::WARN,
    1 => Level::INFO,
    2 => Level::DEBUG,
    _ => Level::TRACE,
  };

  // Create a custom filter
  let filter = EnvFilter::from_default_env()
    .add_directive(format!("edge_frontend={}", level).parse().unwrap())
    .add_directive(format!("edge_prover={}", level).parse().unwrap())
    .add_directive(format!("demo={}", level).parse().unwrap());

  // Set up the subscriber
  tracing_subscriber::registry().with(fmt::layer().with_target(true)).with(filter).init();

  debug!("Logging initialized at level: {:?}", level);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let cli = Cli::parse();

  // Set up logging based on verbosity
  setup_logging(cli.verbose);

  match cli.command {
    Commands::Setup { output } => {
      info!("🔧 Running offline setup phase...");

      // Step 1: Create demo programs
      let collatz_even = collatz_even();
      let collatz_odd = collatz_odd();
      info!("✅ Created demo programs");
      debug!("Program details - even: {:?}, odd: {:?}", collatz_even, collatz_odd);

      // Step 2: Create switchboard
      let switchboard = Switchboard::<Configuration>::new(vec![collatz_even, collatz_odd]);
      info!("✅ Created switchboard");
      trace!("Switchboard details: {:?}", switchboard);

      // Step 3: Initialize the setup
      let setup = Setup::new(switchboard)?;
      info!("✅ Initialized setup");
      trace!("Setup details: {:?}", setup);

      // Step 4: Save the setup to a file
      setup.store_file(&output)?;
      info!("✅ Saved setup to file: {}", output.display());

      Ok(())
    },
    Commands::Prove { input, setup, output } => {
      info!("🔍 Running proving phase...");
      debug!("Input value: {}", input);

      // Step 1: Read the setup from the file
      let psetup = Setup::load_file(&setup)?;
      info!("✅ Loaded setup from file: {}", setup.display());
      trace!("Setup details: {:?}", psetup);

      // Step 2: Create demo programs
      let collatz_even = collatz_even();
      let collatz_odd = collatz_odd();
      info!("✅ Created demo programs");
      debug!("Program details - even: {:?}, odd: {:?}", collatz_even, collatz_odd);

      // Step 3: Create and prepare the switchboard for proving
      let program_index = (input % 2) as usize;
      debug!(
        "Using program index: {} ({})",
        program_index,
        if program_index == 0 { "even" } else { "odd" }
      );

      let switchboard = Switchboard::<RAM>::new(
        vec![collatz_even, collatz_odd],
        vec![Scalar::from(input)],
        program_index,
      );
      trace!("Switchboard details: {:?}", switchboard);

      let psetup = psetup.into_ready(switchboard);
      info!("✅ Prepared setup for proving");
      trace!("Ready setup details: {:?}", psetup);

      // Step 4: Generate the proof
      info!("Generating recursive SNARK (this may take a while)...");
      let recursive_snark = program::run(&psetup)?;
      info!("✅ Generated recursive SNARK");
      trace!("Recursive SNARK details: {:?}", recursive_snark);

      // Step 5: Compress the proof
      info!("Compressing proof (this may take a while)...");
      let compressed_proof = program::compress(&psetup, &recursive_snark)?;
      info!("✅ Compressed the proof");
      trace!("Compressed proof details: {:?}", compressed_proof);

      // Step 6: Serialize and store the proof
      let serialized_proof = bincode::serialize(&compressed_proof)?;
      fs::write(&output, &serialized_proof)?;
      info!("✅ Saved proof to file: {}", output.display());
      debug!("Proof size: {} bytes", serialized_proof.len());

      Ok(())
    },
    Commands::Verify { input, setup, proof } => {
      info!("🔐 Running verification phase...");
      debug!("Input value: {}", input);

      // Step 1: Read the setup from the file
      let vsetup = Setup::load_file(&setup)?;
      info!("✅ Loaded setup from file: {}", setup.display());
      trace!("Setup details: {:?}", vsetup);

      // Step 2: Read and deserialize the proof
      let proof_bytes = fs::read(&proof)?;
      debug!("Proof size: {} bytes", proof_bytes.len());

      let compressed_proof: CompressedSNARK = bincode::deserialize(&proof_bytes)?;
      info!("✅ Loaded proof from file: {}", proof.display());
      trace!("Compressed proof details: {:?}", compressed_proof);

      // Step 3: Create demo programs (needed for switchboard)
      let collatz_even = collatz_even();
      let collatz_odd = collatz_odd();
      debug!("Program details - even: {:?}, odd: {:?}", collatz_even, collatz_odd);

      // Step 4: Create and prepare the switchboard for verification
      let vswitchboard = Switchboard::<Configuration>::new(vec![collatz_even, collatz_odd]);
      trace!("Switchboard details: {:?}", vswitchboard);

      let vsetup = vsetup.into_ready(vswitchboard);
      trace!("Ready setup details: {:?}", vsetup);

      // Step 5: Get the verifier key
      let vk = vsetup.verifier_key()?;
      info!("✅ Prepared verification key");
      trace!("Verifier key details: {:?}", vk);

      // Step 6: Verify the proof
      let z0_primary = [Scalar::from(input)];

      info!("Verifying proof...");
      match compressed_proof.verify(&vsetup.params, &vk, &z0_primary, Z0_SECONDARY) {
        Ok(_) => {
          info!("✅ Proof verification successful!");
          Ok(())
        },
        Err(e) => {
          info!("❌ Proof verification failed: {e}");
          debug!("Verification error details: {:?}", e);
          Err(e.into())
        },
      }
    },
  }
}
