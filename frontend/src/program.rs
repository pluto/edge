//! # Program Execution
//!
//! This module provides the core execution functionality for NIVC (Non-uniform Incrementally
//! Verifiable Computation) with Noir circuits. It defines the memory models, switchboard logic for
//! circuit coordination, and functions for running programs and compressing proofs.
//!
//! ## Memory Models
//!
//! Two memory models are supported:
//! - **ROM (Read-Only Memory)**: Programs with all inputs known in advance
//! - **RAM (Random-Access Memory)**: Programs that compute inputs dynamically during execution
//!
//! ## Switchboard
//!
//! The [`Switchboard`] struct manages a collection of Noir circuits and controls the execution flow
//! between them. It maintains:
//! - A list of circuits
//! - The current program counter (circuit index)
//! - Input data appropriate for the memory model
//!
//! ## Execution Functions
//!
//! - [`run`]: Executes a program with the appropriate memory model
//! - [`compress`]: Compresses a recursive SNARK into a more compact form for verification

use client_side_prover::supernova::{NonUniformCircuit, RecursiveSNARK};
use halo2curves::{ff::PrimeField, grumpkin};
use noirc_abi::InputMap;
use tracing::trace;

use super::*;
use crate::{
  noir::NoirProgram,
  setup::{Ready, Setup},
};

/// Trait for memory models used in the NIVC system
///
/// This trait is sealed, meaning it can only be implemented by the types in this crate
/// (specifically, `ROM` and `RAM`).
pub trait Memory: private::Sealed {
  /// The data type associated with this memory model
  type Data;
}

/// Private module containing implementation details for sealing the Memory trait
mod private {
  use super::{Configuration, RAM, ROM};
  /// Seals the [`Memory`] trait
  pub trait Sealed {}
  impl Sealed for ROM {}
  impl Sealed for RAM {}
  impl Sealed for Configuration {}
}

/// Read-Only Memory model
///
/// In ROM mode, all inputs for the computation are known in advance and provided
/// as a sequence of witness values.
#[derive(Debug, Clone)]
pub struct ROM {}
impl Memory for ROM {
  /// ROM uses a vector of `InputMaps` as its data
  type Data = Vec<InputMap>;
}

/// Random-Access Memory model
///
/// In RAM mode, inputs are computed dynamically during execution. Each circuit
/// can influence the execution path by setting the program counter for the next step.
#[derive(Debug, Clone)]
pub struct RAM {}
impl Memory for RAM {
  /// RAM doesn't require any additional input data
  type Data = ();
}

/// A memory model that doesn't require any additional input data.
///
/// This is just a placeholder to allow the setup to be easily created then serialized and
/// deserialized.
#[derive(Debug, Clone)]
pub struct Configuration {}
impl Memory for Configuration {
  type Data = ();
}

/// Manages a collection of circuits and controls execution flow
///
/// The switchboard holds all the circuits that can be executed in a NIVC computation,
/// and maintains the program counter (current circuit index). It is parameterized by
/// a memory model that determines how inputs are handled.
#[derive(Debug, Clone)]
pub struct Switchboard<M: Memory> {
  /// The collection of Noir circuits that can be executed
  pub(crate) circuits: Vec<NoirProgram>,

  /// Public input values (initial registers for the computation)
  pub(crate) public_input: Vec<Scalar>,

  /// The initial circuit index to start execution from
  pub(crate) initial_circuit_index: usize,

  /// Input data specific to the memory model
  pub(crate) switchboard_inputs: M::Data,
}

impl Switchboard<Configuration> {
  /// Creates a new switchboard with Blank memory model
  ///
  /// # Arguments
  ///
  /// * `circuits` - Collection of Noir circuits that can be executed
  ///
  /// # Returns
  pub fn new(mut circuits: Vec<NoirProgram>) -> Self {
    // Set the index of each circuit given the order they are passed in since this is skipped in
    // serde
    circuits.iter_mut().enumerate().for_each(|(i, c)| c.index = i);
    Self { circuits, public_input: vec![], initial_circuit_index: 0, switchboard_inputs: () }
  }

  pub fn into_rom(
    self,
    initial_circuit_index: usize,
    switchboard_inputs: Vec<InputMap>,
    public_input: Vec<Scalar>,
  ) -> Switchboard<ROM> {
    Switchboard { circuits: self.circuits, public_input, initial_circuit_index, switchboard_inputs }
  }

  pub fn into_ram(
    self,
    initial_circuit_index: usize,
    public_input: Vec<Scalar>,
  ) -> Switchboard<RAM> {
    Switchboard {
      circuits: self.circuits,
      public_input,
      initial_circuit_index,
      switchboard_inputs: self.switchboard_inputs,
    }
  }
}

impl Switchboard<ROM> {
  /// Creates a new switchboard with Read-Only Memory model
  ///
  /// # Arguments
  ///
  /// * `circuits` - Collection of Noir circuits that can be executed
  /// * `switchboard_inputs` - Sequence of inputs for each execution step
  /// * `public_input` - Initial register values
  /// * `initial_circuit_index` - The starting circuit index
  ///
  /// # Returns
  ///
  /// A new `Switchboard` instance configured for ROM execution
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
  /// Creates a new switchboard with Random-Access Memory model
  ///
  /// # Arguments
  ///
  /// * `circuits` - Collection of Noir circuits that can be executed
  /// * `public_input` - Initial register values
  /// * `initial_circuit_index` - The starting circuit index
  ///
  /// # Returns
  ///
  /// A new [`Switchboard`] instance configured for RAM execution
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

  /// Returns the number of circuits in the switchboard
  fn num_circuits(&self) -> usize { self.circuits.len() }

  /// Returns the primary circuit at the given index
  fn primary_circuit(&self, circuit_index: usize) -> Self::C1 {
    self.circuits[circuit_index].clone()
  }

  /// Returns the secondary circuit (always trivial for NIVC with Noir)
  fn secondary_circuit(&self) -> Self::C2 { TrivialCircuit::default() }

  /// Returns the initial circuit index to start execution from
  fn initial_circuit_index(&self) -> usize { self.initial_circuit_index }
}

/// Executes a program with the appropriate memory model
///
/// This function dispatches to either [`run_rom`] or [`run_ram`] based on the memory model.
///
/// # Arguments
///
/// * `setup` - The setup parameters for the program
///
/// # Returns
///
/// A [`RecursiveSNARK`] representing the execution trace
///
/// # Errors
///
/// Returns a [`FrontendError`] if execution fails
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

/// Executes a program using the ROM memory model
///
/// In ROM mode, all inputs are known in advance and provided as a sequence.
/// The program executes each step with the corresponding input.
///
/// # Arguments
///
/// * `setup` - The setup parameters for the program
///
/// # Returns
///
/// A [`RecursiveSNARK`] representing the execution trace
///
/// # Errors
///
/// Returns a [`FrontendError`] if execution fails
pub fn run_rom(setup: &Setup<Ready<ROM>>) -> Result<RecursiveSNARK<E1>, FrontendError> {
  info!("Starting SuperNova program with ROM memory model...");

  let z0_primary = &setup.switchboard.public_input;
  let z0_secondary = &[grumpkin::Fr::ZERO];
  let time = std::time::Instant::now();

  let mut recursive_snark: Option<RecursiveSNARK<E1>> = None;

  // ROM-specific: iterate through predefined sequence of inputs
  for (idx, witness) in setup.switchboard.switchboard_inputs.iter().enumerate() {
    info!("Step {} of {} witnesses", idx + 1, setup.switchboard.switchboard_inputs.len());

    // TODO: We should not clone the witness here
    recursive_snark =
      prove_single_step(setup, recursive_snark, Some(witness.clone()), z0_primary, z0_secondary)?;
  }

  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());
  Ok(recursive_snark.unwrap())
}

/// Executes a program using the RAM memory model
///
/// In RAM mode, inputs are computed dynamically during execution. Each circuit
/// can influence the execution path by setting the program counter for the next step.
///
/// # Arguments
///
/// * `setup` - The setup parameters for the program
///
/// # Returns
///
/// A [`RecursiveSNARK`] representing the execution trace
///
/// # Errors
///
/// Returns a [`FrontendError`] if execution fails
pub fn run_ram(setup: &Setup<Ready<RAM>>) -> Result<RecursiveSNARK<E1>, FrontendError> {
  info!("Starting SuperNova program with RAM memory model...");

  let z0_primary = &setup.switchboard.public_input;
  let z0_secondary = &[grumpkin::Fr::ZERO];
  let time = std::time::Instant::now();

  let mut recursive_snark: Option<RecursiveSNARK<E1>> = None;
  let termination_pc = Scalar::ZERO - Scalar::ONE;

  // RAM-specific: loop until termination condition is met
  loop {
    // Check termination condition if we have a SNARK
    if let Some(snark) = &recursive_snark {
      let current_pc = snark.program_counter();
      if current_pc == termination_pc {
        break;
      }
    }

    recursive_snark = prove_single_step(
      setup,
      recursive_snark,
      None, // RAM doesn't use predefined witness values
      z0_primary,
      z0_secondary,
    )?;
  }

  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());
  Ok(recursive_snark.unwrap())
}

/// Helper function to prove a single step of execution
///
/// This handles the common logic between ROM and RAM execution modes.
fn prove_single_step<M: Memory>(
  setup: &Setup<Ready<M>>,
  recursive_snark: Option<RecursiveSNARK<E1>>,
  witness: Option<InputMap>,
  z0_primary: &[Scalar],
  z0_secondary: &[grumpkin::Fr],
) -> Result<Option<RecursiveSNARK<E1>>, FrontendError> {
  let program_counter = recursive_snark.as_ref().map_or_else(
    || setup.switchboard.initial_circuit_index(),
    |snark| {
      u32::from_le_bytes(snark.program_counter().to_repr().as_ref()[0..4].try_into().unwrap())
        as usize
    },
  );

  debug!("Program counter = {:?}", program_counter);

  let mut circuit_primary = setup.switchboard.primary_circuit(program_counter);

  if let Some(w) = witness {
    circuit_primary.witness = Some(w);
  } else {
    circuit_primary.witness = Some(InputMap::new());
  }

  let circuit_secondary = setup.switchboard.secondary_circuit();

  let mut result = recursive_snark;
  if result.is_none() {
    result = Some(RecursiveSNARK::new(
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
  let snark = result.as_mut().unwrap();
  snark.prove_step(&setup.params, &circuit_primary, &circuit_secondary)?;
  info!("Done proving single step...");

  Ok(result)
}

/// Compresses a recursive SNARK into a compact proof for efficient verification
///
/// # Arguments
///
/// * `setup` - The setup parameters for the program
/// * `recursive_snark` - The recursive SNARK to compress
///
/// # Returns
///
/// A `CompressedProof` that can be serialized and later verified
///
/// # Errors
///
/// Returns a `FrontendError` if compression fails
pub fn compress<M: Memory>(
  setup: &Setup<Ready<M>>,
  recursive_snark: &RecursiveSNARK<E1>,
) -> Result<CompressedSNARK, FrontendError> {
  let pk = CompressedSNARK::initialize_pk(
    &setup.params,
    setup.vk_digest_primary,
    setup.vk_digest_secondary,
  )?;
  trace!(
    "initialized pk pk_primary.digest={:?}, pk_secondary.digest={:?}",
    pk.pk_primary.vk_digest,
    pk.pk_secondary.vk_digest
  );

  debug!("`CompressedSNARK::prove STARTING PROVING!");
  let proof = CompressedSNARK::prove(&setup.params, &pk, recursive_snark)?;
  debug!("`CompressedSNARK::prove completed!");

  Ok(proof)
}
