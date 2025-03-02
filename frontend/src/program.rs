use client_side_prover::{
  supernova::{NonUniformCircuit, RecursiveSNARK},
  traits::snark::{default_ck_hint, BatchedRelaxedR1CSSNARKTrait},
};
use halo2curves::grumpkin;
use noirc_abi::InputMap;
use proof::FoldingProof;
use tracing::trace;

use super::*;
use crate::{noir::NoirProgram, setup::Setup};

// TODO: Consider moving contents of mod.rs files to a separate files. mod.rs
// files should  only be used to adjust the visibility of exported items.

/// Compressed proof type
pub type CompressedProof = FoldingProof<CompressedSNARK<E1, S1, S2>, Scalar>;

// NOTE: These are `pub(crate)` to avoid exposing the `index` field to the
// outside world.
#[derive(Debug, Clone)]
pub struct Switchboard {
  pub(crate) circuits:              Vec<NoirProgram>,
  pub(crate) public_input:          Vec<Scalar>,
  pub(crate) initial_circuit_index: usize,
  pub(crate) switchboard_inputs:    Vec<InputMap>,
}

impl Switchboard {
  pub fn new(
    mut circuits: Vec<NoirProgram>,
    switchboard_inputs: Vec<InputMap>,
    public_input: Vec<Scalar>,
    initial_circuit_index: usize,
  ) -> Self {
    // Set the index of each circuit given the order they are passed in since this is skipped in
    // serde
    circuits.iter_mut().enumerate().for_each(|(i, c)| c.index = i);
    Self { circuits, public_input, initial_circuit_index, switchboard_inputs }
  }
}

impl NonUniformCircuit<E1> for Switchboard {
  type C1 = NoirProgram;
  type C2 = TrivialCircuit<grumpkin::Fr>;

  fn num_circuits(&self) -> usize { self.circuits.len() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  fn secondary_circuit(&self) -> Self::C2 { TrivialCircuit::default() }

  fn initial_circuit_index(&self) -> usize { self.initial_circuit_index }
}

pub fn run(setup: Setup, switchboard: &Switchboard) -> Result<RecursiveSNARK<E1>, ProofError> {
  info!("Starting SuperNova program...");
  let public_params = setup.into_public_params(&switchboard.circuits);

  let z0_primary = &switchboard.public_input;
  let z0_secondary = &[grumpkin::Fr::ZERO];

  let time = std::time::Instant::now();

  // Initialize recursive SNARK as None
  let mut recursive_snark: Option<RecursiveSNARK<E1>> = None;

  for (idx, switchboard_witness) in switchboard.switchboard_inputs.iter().enumerate() {
    info!("Step {} of {} witnesses", idx + 1, switchboard.switchboard_inputs.len());

    // Determine program counter based on current state
    let program_counter = match &recursive_snark {
      None => switchboard.initial_circuit_index(),
      Some(snark) => {
        // TODO: I honestly am surprised that the prover chose to use a usize instead of a field
        // element for the PC, it would be cleaner to do otherwise
        let pc_bytes = snark.program_counter().to_bytes();

        // Check if higher bytes are non-zero (which would be truncated in usize conversion)
        let usize_size = std::mem::size_of::<usize>();
        if pc_bytes[usize_size..].iter().any(|&b| b != 0) {
          return Err(ProofError::Other("Program counter value too large for usize".into()));
        }

        // Convert the relevant bytes to usize (using little-endian order)
        let mut pc_value = 0usize;
        for (i, &b) in pc_bytes.iter().take(usize_size).enumerate() {
          pc_value |= (b as usize) << (i * 8);
        }

        pc_value
      },
    };

    debug!("Program counter = {:?}", program_counter);

    // Prepare circuits for this step
    let mut circuit_primary = switchboard.primary_circuit(program_counter);
    circuit_primary.witness = Some(switchboard_witness.clone());
    let circuit_secondary = switchboard.secondary_circuit();

    // Initialize or update the recursive SNARK
    if recursive_snark.is_none() {
      // Initialize a new recursive SNARK for the first step
      recursive_snark = Some(RecursiveSNARK::new(
        &public_params,
        switchboard,
        &circuit_primary,
        &circuit_secondary,
        z0_primary,
        z0_secondary,
      )?);
    }

    // Prove the next step
    info!("Proving single step...");
    let snark = recursive_snark.as_mut().unwrap();
    snark.prove_step(&public_params, &circuit_primary, &circuit_secondary)?;
    info!("Done proving single step...");

    // TODO: Feature gate this or just remove it
    // info!("Verifying single step...");
    // snark.verify(&public_params, snark.z0_primary(), z0_secondary)?;
    // info!("Single step verification done");
  }

  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  // Return the completed recursive SNARK
  Ok(recursive_snark.unwrap())
}

// TODO: We need to make this not take in the programs
pub fn compress(
  setup: Setup,
  recursive_snark: &RecursiveSNARK<E1>,
  programs: &[NoirProgram],
) -> Result<CompressedProof, ProofError> {
  let pk = ProverKey {
    pk_primary:   S1::initialize_pk(setup.aux_params.ck_primary.clone(), setup.vk_digest_primary)?,
    pk_secondary: S2::initialize_pk(
      setup.aux_params.ck_secondary.clone(),
      setup.vk_digest_secondary,
    )?,
  };
  // let pk:  = CompressedSNARK::<E1, S1, S2>::initialize_pk(
  //   public_params,
  //   vk_digest_primary,
  //   vk_digest_secondary,
  // )
  // .unwrap();
  debug!(
    "initialized pk pk_primary.digest={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest, pk.pk_secondary.vk_digest
  );
  let public_params = setup.into_public_params(programs);

  debug!("`CompressedSNARK::prove STARTING PROVING!");
  let proof = FoldingProof {
    proof:           CompressedSNARK::<E1, S1, S2>::prove(&public_params, &pk, recursive_snark)?,
    verifier_digest: pk.pk_primary.vk_digest,
  };
  debug!("`CompressedSNARK::prove completed!");

  Ok(proof)
}


