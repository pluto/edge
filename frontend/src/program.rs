use client_side_prover::supernova::{NonUniformCircuit, RecursiveSNARK};
use halo2curves::grumpkin;
use noirc_abi::InputMap;
use proof::FoldingProof;
use tracing::trace;

use super::*;
use crate::{
  noir::NoirProgram,
  setup::{Ready, Setup},
};

// TODO: Consider moving contents of mod.rs files to a separate files. mod.rs
// files should  only be used to adjust the visibility of exported items.

/// Compressed proof type
pub type CompressedProof = FoldingProof<CompressedSNARK<E1, S1, S2>, Scalar>;

pub trait Memory: private::Sealed {
  type Data;
}

mod private {
  use super::{RAM, ROM};
  pub trait Sealed {}
  impl Sealed for ROM {}
  impl Sealed for RAM {}
}

#[derive(Debug, Clone)]
pub struct ROM {}
impl Memory for ROM {
  type Data = Vec<InputMap>;
}

#[derive(Debug, Clone)]
pub struct RAM {}
impl Memory for RAM {
  type Data = ();
}

// NOTE: These are `pub(crate)` to avoid exposing the `index` field to the
// outside world.
#[derive(Debug, Clone)]
pub struct Switchboard<M: Memory> {
  pub(crate) circuits:              Vec<NoirProgram>,
  pub(crate) public_input:          Vec<Scalar>,
  pub(crate) initial_circuit_index: usize,
  pub(crate) switchboard_inputs:    M::Data,
}

impl Switchboard<ROM> {
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

impl Switchboard<RAM> {
  pub fn new(
    mut circuits: Vec<NoirProgram>,
    public_input: Vec<Scalar>,
    initial_circuit_index: usize,
  ) -> Self {
    // Set the index of each circuit given the order they are passed in since this is skipped in
    // serde
    circuits.iter_mut().enumerate().for_each(|(i, c)| c.index = i);
    Self { circuits, public_input, initial_circuit_index, switchboard_inputs: () }
  }
}

impl<M: Memory> NonUniformCircuit<E1> for Switchboard<M> {
  type C1 = NoirProgram;
  type C2 = TrivialCircuit<grumpkin::Fr>;

  fn num_circuits(&self) -> usize { self.circuits.len() }

  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  fn secondary_circuit(&self) -> Self::C2 { TrivialCircuit::default() }

  fn initial_circuit_index(&self) -> usize { self.initial_circuit_index }
}

pub fn run<M: Memory>(setup: &Setup<Ready<M>>) -> Result<RecursiveSNARK<E1>, FrontendError> {
  if std::any::type_name::<M>() == std::any::type_name::<ROM>() {
    // Safety: We've verified the type matches ROM
    let setup = unsafe {
      &*std::ptr::from_ref::<setup::Setup<setup::Ready<M>>>(setup)
        .cast::<setup::Setup<setup::Ready<program::ROM>>>()
    };
    run_rom(setup)
  } else if std::any::type_name::<M>() == std::any::type_name::<RAM>() {
    // Safety: We've verified the type matches RAM
    let setup = unsafe {
      &*std::ptr::from_ref::<setup::Setup<setup::Ready<M>>>(setup)
        .cast::<setup::Setup<setup::Ready<program::RAM>>>()
    };
    run_ram(setup)
  } else {
    unreachable!("The trait `Memory` is sealed, so you cannot reach this point")
  }
}

pub fn run_rom(setup: &Setup<Ready<ROM>>) -> Result<RecursiveSNARK<E1>, FrontendError> {
  info!("Starting SuperNova program...");

  let z0_primary = &setup.switchboard.public_input;
  let z0_secondary = &[grumpkin::Fr::ZERO];

  let time = std::time::Instant::now();

  // Initialize recursive SNARK as None
  let mut recursive_snark: Option<RecursiveSNARK<E1>> = None;

  for (idx, switchboard_witness) in setup.switchboard.switchboard_inputs.iter().enumerate() {
    info!("Step {} of {} witnesses", idx + 1, setup.switchboard.switchboard_inputs.len());

    // Determine program counter based on current state
    let program_counter = match &recursive_snark {
      None => setup.switchboard.initial_circuit_index(),
      Some(snark) => {
        // TODO: I honestly am surprised that the prover chose to use a usize instead of a field
        // element for the PC, it would be cleaner to do otherwise
        let pc_bytes = snark.program_counter().to_bytes();

        // Check if higher bytes are non-zero (which would be truncated in usize conversion)
        let usize_size = std::mem::size_of::<usize>();
        if pc_bytes[usize_size..].iter().any(|&b| b != 0) {
          return Err(FrontendError::Other("Program counter value too large for usize".into()));
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
    let mut circuit_primary = setup.switchboard.primary_circuit(program_counter);
    circuit_primary.witness = Some(switchboard_witness.clone());
    let circuit_secondary = setup.switchboard.secondary_circuit();

    // Initialize or update the recursive SNARK
    if recursive_snark.is_none() {
      // Initialize a new recursive SNARK for the first step
      recursive_snark = Some(RecursiveSNARK::new(
        &setup.params,
        &setup.switchboard,
        &circuit_primary,
        &circuit_secondary,
        z0_primary,
        z0_secondary,
      )?);
    }

    // Prove the next step
    info!("Proving single step...");
    let snark = recursive_snark.as_mut().unwrap();
    snark.prove_step(&setup.params, &circuit_primary, &circuit_secondary)?;
    info!("Done proving single step...");
  }

  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  // Return the completed recursive SNARK
  Ok(recursive_snark.unwrap())
}

pub fn run_ram(setup: &Setup<Ready<RAM>>) -> Result<RecursiveSNARK<E1>, FrontendError> {
  info!("Starting SuperNova program...");

  let z0_primary = &setup.switchboard.public_input;
  let z0_secondary = &[grumpkin::Fr::ZERO];

  let time = std::time::Instant::now();

  // Initialize recursive SNARK as None
  let mut recursive_snark: Option<RecursiveSNARK<E1>> = None;
  let termination_pc = Scalar::ZERO - Scalar::ONE;

  loop {
    // Determine program counter based on current state
    let program_counter = match &recursive_snark {
      None => setup.switchboard.initial_circuit_index(),
      Some(snark) => {
        dbg!(&snark.program_counter());
        let current_pc = snark.program_counter();
        if current_pc == termination_pc {
          break;
        }

        // Convert Scalar to usize for circuit indexing
        let pc_bytes = current_pc.to_bytes();

        // Check if higher bytes are non-zero (which would be truncated in usize conversion)
        let usize_size = std::mem::size_of::<usize>();
        if pc_bytes[usize_size..].iter().any(|&b| b != 0) {
          return Err(FrontendError::Other("Program counter value too large for usize".into()));
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
    dbg!(&program_counter);
    let mut circuit_primary = setup.switchboard.primary_circuit(program_counter);
    // TODO: This is a hack to get the witness to be non-empty so ACVM is spawned
    circuit_primary.witness = Some(InputMap::new());
    let circuit_secondary = setup.switchboard.secondary_circuit();

    // Initialize or update the recursive SNARK
    if recursive_snark.is_none() {
      // Initialize a new recursive SNARK for the first step
      recursive_snark = Some(RecursiveSNARK::new(
        &setup.params,
        &setup.switchboard,
        &circuit_primary,
        &circuit_secondary,
        z0_primary,
        z0_secondary,
      )?);
    }

    // Prove the next step
    info!("Proving single step...");
    let snark = recursive_snark.as_mut().unwrap();
    snark.prove_step(&setup.params, &circuit_primary, &circuit_secondary)?;
    info!("Done proving single step...");
    dbg!(snark.program_counter());
  }

  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  // Return the completed recursive SNARK
  Ok(recursive_snark.unwrap())
}

pub fn compress<M: Memory>(
  setup: &Setup<Ready<M>>,
  recursive_snark: &RecursiveSNARK<E1>,
) -> Result<CompressedProof, FrontendError> {
  let pk = CompressedSNARK::<E1, S1, S2>::initialize_pk(
    &setup.params,
    setup.vk_digest_primary,
    setup.vk_digest_secondary,
  )
  .unwrap();
  debug!(
    "initialized pk pk_primary.digest={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest, pk.pk_secondary.vk_digest
  );

  debug!("`CompressedSNARK::prove STARTING PROVING!");
  let proof = FoldingProof {
    proof:           CompressedSNARK::<E1, S1, S2>::prove(&setup.params, &pk, recursive_snark)?,
    verifier_digest: pk.pk_primary.vk_digest,
  };
  debug!("`CompressedSNARK::prove completed!");

  Ok(proof)
}
