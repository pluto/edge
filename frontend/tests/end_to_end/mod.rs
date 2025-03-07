use std::fs;

use acvm::acir::acir_field::GenericFieldElement;
use edge_frontend::{
  demo,
  program::{self, Configuration, Switchboard},
  setup::Setup,
  CompressedSNARK, Scalar,
};
use noirc_abi::{input_parser::InputValue, InputMap};
use tempfile::tempdir;

use super::*;

/// Note that this test goes through a flow that mimics the offline setup component, online proving
/// component, and a separate verification component.
#[test]
#[traced_test]
fn test_end_to_end_workflow() {
  // ----------------------------------------------------------------------------------------------------------------- //
  // Offline Setup Phase
  // ----------------------------------------------------------------------------------------------------------------- //
  // Step 1: Create demo programs for our test
  let swap_memory_program = demo::swap_memory();
  let square_program = demo::square_zeroth();
  println!("1. Read programs");

  // Step 2: Create switchboard with ROM memory model, no inputs are necessary since this is just
  // creating the setup
  let switchboard =
    Switchboard::<Configuration>::new(vec![swap_memory_program.clone(), square_program.clone()]);
  println!("2. Created switchboard");

  // Step 3: Initialize the setup
  let setup = Setup::new(switchboard.clone()).unwrap();
  println!("3. Initialized setup");

  // Step 4: Save the setup to a file
  let temp_dir = tempdir().unwrap();
  let file_path = temp_dir.path().join("test_setup.bytes");
  setup.store_file(&file_path).unwrap();
  println!("4. Saved setup to file");
  // ----------------------------------------------------------------------------------------------------------------- //

  // ----------------------------------------------------------------------------------------------------------------- //
  // Online Proving Phase
  // ----------------------------------------------------------------------------------------------------------------- //
  // Step 5: Read the setup from the file
  let psetup = Setup::load_file(&file_path).unwrap();
  println!("5. Read setup from file");

  // Step 6: Ready the setup for proving with the switchboard
  let input1 =
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(1_u64)))]);
  let input2 = InputMap::from([(
    "next_pc".to_string(),
    InputValue::Field(GenericFieldElement::from(-1_i128)),
  )]);
  // Briefly test the switchboard into_rom method
  let pswitchboard =
    switchboard.into_rom(0, vec![input1, input2], vec![Scalar::from(3), Scalar::from(5)]);
  let psetup = psetup.into_ready(pswitchboard);
  println!("6. Ready the setup for proving with the switchboard");

  // Step 7: Run a proof
  let recursive_snark = program::run(&psetup).unwrap();
  println!("7. Run a proof");

  // Step 8: Compress the proof
  let compressed_proof = program::compress(&psetup, &recursive_snark).unwrap();
  println!("8. Compressed the proof");

  // Step 9: Serialize and store the proof in a file
  let serialized_proof = bincode::serialize(&compressed_proof).unwrap();
  let proof_file_path = temp_dir.path().join("test_proof.bytes");
  fs::write(&proof_file_path, &serialized_proof).unwrap();
  println!("9. Saved the serialized proof to a file");
  // ----------------------------------------------------------------------------------------------------------------- //

  // ----------------------------------------------------------------------------------------------------------------- //
  // Separate Verification Phase
  // ----------------------------------------------------------------------------------------------------------------- //
  // Step 10: Read and deserialize the proof
  let proof_bytes_from_file = fs::read(&proof_file_path).unwrap();
  let deserialized_proof: CompressedSNARK = bincode::deserialize(&proof_bytes_from_file).unwrap();
  println!("10. Read and deserialized the proof");

  // Step 11: Verify the proof digests match by loading the setup from file as if we were a verifier
  let vsetup = Setup::load_file(&file_path).unwrap();
  let vswitchboard = Switchboard::<Configuration>::new(vec![swap_memory_program, square_program]);
  let vsetup = vsetup.into_ready(vswitchboard);
  let vk = vsetup.verifier_key().unwrap();
  deserialized_proof
    .verify(&vsetup.params, &vk, recursive_snark.z0_primary(), recursive_snark.z0_secondary())
    .unwrap();
  println!("11. Verified the proof");
  // ----------------------------------------------------------------------------------------------------------------- //
}
