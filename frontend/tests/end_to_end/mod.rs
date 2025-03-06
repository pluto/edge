use std::fs;

use acvm::acir::acir_field::GenericFieldElement;
use client_side_prover::supernova::snark::CompressedSNARK;
use client_side_prover_frontend::{
  demo,
  program::{self, Switchboard, ROM},
  proof::FoldingProof,
  setup::{Empty, Ready, Setup},
  Scalar,
};
use noirc_abi::{input_parser::InputValue, InputMap};
use tempfile::tempdir;

use super::*;

#[test]
#[traced_test]
fn test_end_to_end_workflow() {
  // Step 1: Create demo programs for our test
  let swap_memory_program = demo::swap_memory();
  let square_program = demo::square_zeroth();
  println!("1. Read programs");

  // Step 2: Create switchboard with ROM memory model, no inputs are necessary since this is just
  // creating the setup
  let switchboard = Switchboard::<ROM>::new(
    vec![swap_memory_program.clone(), square_program.clone()],
    vec![],
    vec![],
    0,
  );
  println!("2. Created switchboard");

  // Step 3: Initialize the setup
  let setup = Setup::<Ready<ROM>>::new(switchboard).unwrap();
  println!("3. Initialized setup");

  // Step 4: Save the setup to a file
  let temp_dir = tempdir().unwrap();
  let file_path = temp_dir.path().join("test_setup.bytes");
  setup.store_file(&file_path).unwrap();
  println!("4. Saved setup to file");

  // Step 5: Read the setup from the file
  let setup = Setup::<Empty<ROM>>::load_file(&file_path).unwrap();
  println!("5. Read setup from file");

  // Step 6: Ready the setup for proving with the switchboard
  let input1 =
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(1_u64)))]);
  let input2 =
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(1_i128)))]);
  let switchboard = Switchboard::<ROM>::new(
    vec![swap_memory_program, square_program],
    vec![input1, input2],
    vec![Scalar::from(3), Scalar::from(5)],
    0,
  );
  let setup = setup.into_ready(switchboard.clone());
  println!("6. Ready the setup for proving with the switchboard");

  // Step 7: Run a proof
  let recursive_snark = program::run(&setup).unwrap();
  println!("7. Run a proof");

  // Step 8: Compress the proof
  let compressed_proof = program::compress(&setup, &recursive_snark).unwrap();
  println!("8. Compressed the proof");

  // Step 9: Serialize the proof
  let serialized_proof = compressed_proof.serialize().unwrap();
  println!("9. Serialized the proof");

  // Step 10: Save the serialized proof to a file
  let proof_file_path = temp_dir.path().join("test_proof.bytes");
  let proof_bytes = bincode::serialize(&serialized_proof).unwrap();
  fs::write(&proof_file_path, &proof_bytes).unwrap();
  println!("10. Saved the serialized proof to a file");

  // Step 11: Read and deserialize the proof
  let proof_bytes_from_file = fs::read(&proof_file_path).unwrap();
  let deserialized_proof: FoldingProof<Vec<u8>, String> =
    bincode::deserialize(&proof_bytes_from_file).unwrap();
  println!("11. Read and deserialized the proof");

  // Step 12: Convert back to compressed proof
  let compressed_proof_from_file = deserialized_proof.deserialize().unwrap();
  println!("12. Converted back to compressed proof");

  // TODO: Set up a verifier from file
  // Step 13: Verify the proof digests match
  let vsetup = Setup::<Empty<ROM>>::load_file(&file_path).unwrap();
  let vsetup = vsetup.into_ready(switchboard);
  let (_pk, vk) = CompressedSNARK::setup(&vsetup.params).unwrap();
  compressed_proof_from_file.proof.verify(
    &vsetup.params,
    &vk,
    recursive_snark.z0_primary(),
    recursive_snark.z0_secondary(),
  );
}
