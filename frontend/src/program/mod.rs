use client_side_prover::{
  supernova::{NonUniformCircuit, RecursiveSNARK},
  traits::snark::default_ck_hint,
};
use halo2curves::grumpkin;
use noirc_abi::InputMap;
use proof::FoldingProof;
use tracing::trace;

use super::*;
use crate::noir::NoirProgram;

pub mod data;

// TODO: Consider moving contents of mod.rs files to a separate files. mod.rs
// files should  only be used to adjust the visibility of exported items.

/// Compressed proof type
pub type CompressedProof = FoldingProof<CompressedSNARK<E1, S1, S2>, Scalar>;

// TODO: Use a mapping of program counter to circuit index
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
    // Set the index of each circuit given the order they are passed in
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

// TODO: This is like a one-time use setup that overlaps some with
// `ProgramData::into_online()`. Worth checking out how to make this simpler,
// clearer, more efficient.
// Setup function
// pub fn setup(setup_data: &UninitializedSetup) -> PublicParams<E1> {
//   // Optionally time the setup stage for the program
//   let time = std::time::Instant::now();

//   // TODO: I don't think we want to have to call `initialize_circuit_list` more
//   // than once on setup ever and it seems like it may get used more
//   // frequently.
//   let initilized_setup = initialize_setup_data(setup_data).unwrap();
//   let circuits = initialize_circuit_list(&initilized_setup); // TODO, change the type signature
// of trait to use arbitrary error types.   let memory = Switchboard { circuits };
//   let public_params = PublicParams::setup(&memory, &*default_ck_hint(), &*default_ck_hint());

//   trace!("`PublicParams::setup()` elapsed: {:?}", time.elapsed());

//   public_params
// }

pub fn run(switchboard: &Switchboard) -> Result<RecursiveSNARK<E1>, ProofError> {
  info!("Starting SuperNova program...");

  info!("Setting up PublicParams...");
  // Create a witness-free clone for setup
  let mut memory_clone = switchboard.clone();
  memory_clone.circuits.iter_mut().for_each(|circ| circ.witness = None);
  let public_params = PublicParams::setup(&memory_clone, &*default_ck_hint(), &*default_ck_hint());

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

    // TODO: For some reason this is failing
    // info!("Verifying single step...");
    // snark.verify(&public_params, snark.z0_primary(), z0_secondary)?;
    // info!("Single step verification done");
  }

  trace!("Recursive loop of `program::run()` elapsed: {:?}", time.elapsed());

  // Return the completed recursive SNARK
  Ok(recursive_snark.unwrap())
}

// /// Compresses a proof without performing the setup step.
// ///
// /// This function takes an existing `RecursiveSNARK` and compresses it into a
// /// `CompressedProof` using pre-initialized proving keys. This is useful when
// /// the setup step has already been performed and the proving keys are
// /// available, allowing for more efficient proof generation.
// ///
// /// # Arguments
// ///
// /// * `recursive_snark` - A reference to the `RecursiveSNARK` that needs to be compressed.
// /// * `public_params` - The public parameters required for the proof system.
// /// * `vk_digest_primary` - The primary verification key digest.
// /// * `vk_digest_secondary` - The secondary verification key digest.
// ///
// /// # Returns
// ///
// /// A `Result` containing the `CompressedProof` if successful, or a `ProofError`
// /// if an error occurs.
// ///
// /// # Errors
// ///
// /// This function will return a `ProofError` if the compression process fails at
// /// any step.
// pub fn compress_proof_no_setup(
//   recursive_snark: &RecursiveSNARK<E1>,
//   public_params: &PublicParams<E1>,
//   vk_digest_primary: <E1 as Engine>::Scalar,
//   vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
// ) -> Result<CompressedProof, ProofError> {
//   let pk = CompressedSNARK::<E1, S1, S2>::initialize_pk(
//     public_params,
//     vk_digest_primary,
//     vk_digest_secondary,
//   )
//   .unwrap();
//   debug!(
//     "initialized pk pk_primary.digest={:?}, pk_secondary.digest={:?}",
//     pk.pk_primary.vk_digest, pk.pk_secondary.vk_digest
//   );

//   debug!("`CompressedSNARK::prove STARTING PROVING!");
//   let proof = FoldingProof {
//     proof:           CompressedSNARK::<E1, S1, S2>::prove(public_params, &pk, recursive_snark)?,
//     verifier_digest: pk.pk_primary.vk_digest,
//   };
//   debug!("`CompressedSNARK::prove completed!");

//   Ok(proof)
// }

// /// Compresses a proof by performing the setup step and generating a compressed
// /// proof.
// ///
// /// This function initializes the proving keys by performing the setup step, and
// /// then uses these keys to generate a compressed proof from an existing
// /// `RecursiveSNARK`. This is useful when the setup step has not been performed
// /// yet, and the proving keys need to be initialized before generating the
// /// proof.
// ///
// /// # Arguments
// ///
// /// * `recursive_snark` - A reference to the `RecursiveSNARK` that needs to be compressed.
// /// * `public_params` - The public parameters required for the proof system.
// ///
// /// # Returns
// ///
// /// A `Result` containing the `CompressedProof` if successful, or a `ProofError`
// /// if an error occurs.
// ///
// /// # Errors
// ///
// /// This function will return a `ProofError` if the setup or compression process
// /// fails at any step.
// pub fn compress_proof(
//   recursive_snark: &RecursiveSNARK<E1>,
//   public_params: &PublicParams<E1>,
// ) -> Result<CompressedProof, ProofError> {
//   debug!("Setting up `CompressedSNARK`");
//   let time = std::time::Instant::now();
//   let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(public_params)?;
//   debug!("Done setting up `CompressedSNARK`");
//   trace!("`CompressedSNARK::setup` elapsed: {:?}", time.elapsed());

//   let time = std::time::Instant::now();

//   let proof = FoldingProof {
//     proof:           CompressedSNARK::<E1, S1, S2>::prove(public_params, &pk, recursive_snark)?,
//     verifier_digest: pk.pk_primary.vk_digest,
//   };
//   debug!("`CompressedSNARK::prove completed!");

//   trace!("`CompressedSNARK::prove` elapsed: {:?}", time.elapsed());

//   Ok(proof)
// }

// /// Initializes the setup data for the program.
// ///
// /// This function takes an `UninitializedSetup` and converts it into an
// /// `InitializedSetup` by iterating over the R1CS types and witness generator
// /// types, creating `R1CS` instances and collecting them into vectors. It then
// /// returns an `InitializedSetup` containing the R1CS and witness generator
// /// types, along with the maximum ROM length.
// ///
// /// # Arguments
// ///
// /// * `setup_data` - The `UninitializedSetup` to initialize.
// ///
// /// # Returns
// ///
// /// A `Result` containing the `InitializedSetup` if successful, or a
// /// `ProofError` if an error occurs.
// pub fn initialize_setup_data(
//   setup_data: &UninitializedSetup,
// ) -> Result<InitializedSetup, ProofError> {
//   let (r1cs, witness_generator_types) = setup_data
//     .r1cs_types
//     .iter()
//     .zip(setup_data.witness_generator_types.iter())
//     .map(|(r1cs_type, generator)| {
//       let r1cs = R1CS::try_from(r1cs_type)?;
//       Ok::<(Arc<circom::r1cs::R1CS>, data::WitnessGeneratorType), ProofError>((
//         Arc::new(r1cs),
//         generator.clone(),
//       ))
//     })
//     .collect::<Result<Vec<_>, _>>()?
//     .into_iter()
//     .unzip();

//   Ok(InitializedSetup { r1cs, witness_generator_types, max_rom_length: setup_data.max_rom_length
// }) }

// /// Initializes a list of ROM circuits from the provided setup data.
// ///
// /// This function takes an `InitializedSetup` and creates a vector of
// /// `RomCircuit` instances. Each `RomCircuit` is constructed using the R1CS and
// /// witness generator types from the setup data, and is assigned a unique
// /// circuit index and the maximum ROM length.
// ///
// /// # Arguments
// ///
// /// * `setup_data` - The `InitializedSetup` containing the R1CS and witness generator types.
// ///
// /// # Returns
// ///
// /// A vector of `RomCircuit` instances initialized with the provided setup data.
// pub fn initialize_circuit_list(setup_data: &InitializedSetup) -> Vec<RomCircuit> {
//   setup_data
//     .r1cs
//     .iter()
//     .zip(setup_data.witness_generator_types.iter())
//     .enumerate()
//     .map(|(i, (r1cs, generator))| {
//       let circuit = circom::CircomCircuit { r1cs: r1cs.clone(), witness: None };
//       RomCircuit {
//         circuit,
//         circuit_index: i,
//         rom_size: setup_data.max_rom_length,
//         nivc_io: None,
//         private_input: None,
//         witness_generator_type: generator.clone(),
//       }
//     })
//     .collect::<Vec<_>>()
// }
