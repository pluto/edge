use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use edge_frontend::{
  noir::NoirProgram,
  program::{self, Configuration, Switchboard, RAM, Z0_SECONDARY},
  setup::Setup,
  CompressedSNARK, Scalar,
};

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let cli = Cli::parse();

  match cli.command {
    Commands::Setup { output } => {
      println!("🔧 Running offline setup phase...");

      // Step 1: Create demo programs
      let collatz_even = collatz_even();
      let collatz_odd = collatz_odd();
      println!("✅ Created demo programs");

      // Step 2: Create switchboard
      let switchboard = Switchboard::<Configuration>::new(vec![collatz_even, collatz_odd]);
      println!("✅ Created switchboard");

      // Step 3: Initialize the setup
      let setup = Setup::new(switchboard)?;
      println!("✅ Initialized setup");

      // Step 4: Save the setup to a file
      setup.store_file(&output)?;
      println!("✅ Saved setup to file: {}", output.display());

      Ok(())
    },
    Commands::Prove { input, setup, output } => {
      println!("🔍 Running proving phase...");

      // Step 1: Read the setup from the file
      let psetup = Setup::load_file(&setup)?;
      println!("✅ Loaded setup from file: {}", setup.display());

      // Step 2: Create demo programs
      let collatz_even = collatz_even();
      let collatz_odd = collatz_odd();
      println!("✅ Created demo programs");

      // Step 3: Create and prepare the switchboard for proving
      let switchboard = Switchboard::<RAM>::new(
        vec![collatz_even, collatz_odd],
        vec![Scalar::from(input)],
        (input % 2) as usize,
      );
      let psetup = psetup.into_ready(switchboard);
      println!("✅ Prepared setup for proving");

      // Step 4: Generate the proof
      let recursive_snark = program::run(&psetup)?;
      println!("✅ Generated recursive SNARK");

      // Step 5: Compress the proof
      let compressed_proof = program::compress(&psetup, &recursive_snark)?;
      println!("✅ Compressed the proof");

      // Step 6: Serialize and store the proof
      let serialized_proof = bincode::serialize(&compressed_proof)?;
      fs::write(&output, &serialized_proof)?;
      println!("✅ Saved proof to file: {}", output.display());

      Ok(())
    },
    Commands::Verify { input, setup, proof } => {
      println!("🔐 Running verification phase...");

      // Step 1: Read the setup from the file
      let vsetup = Setup::load_file(&setup)?;
      println!("✅ Loaded setup from file: {}", setup.display());

      // Step 2: Read and deserialize the proof
      let proof_bytes = fs::read(&proof)?;
      let compressed_proof: CompressedSNARK = bincode::deserialize(&proof_bytes)?;
      println!("✅ Loaded proof from file: {}", proof.display());

      // Step 3: Create demo programs (needed for switchboard)
      let collatz_even = collatz_even();
      let collatz_odd = collatz_odd();

      // Step 4: Create and prepare the switchboard for verification
      let vswitchboard = Switchboard::<Configuration>::new(vec![collatz_even, collatz_odd]);
      let vsetup = vsetup.into_ready(vswitchboard);

      // Step 5: Get the verifier key
      let vk = vsetup.verifier_key()?;
      println!("✅ Prepared verification key");

      // Step 6: Verify the proof
      let z0_primary = [Scalar::from(input)];

      match compressed_proof.verify(&vsetup.params, &vk, &z0_primary, Z0_SECONDARY) {
        Ok(_) => {
          println!("✅ Proof verification successful!");
          Ok(())
        },
        Err(e) => {
          println!("❌ Proof verification failed: {e}");
          Err(e.into())
        },
      }
    },
  }
}
