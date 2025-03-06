use acvm::acir::acir_field::GenericFieldElement;
use client_side_prover::supernova::snark::CompressedSNARK;
use client_side_prover_frontend::{
  program::{compress, run, Switchboard, RAM, ROM},
  setup::Setup,
  Scalar,
};
use ff::Field;
use halo2curves::grumpkin;
use noirc_abi::{input_parser::InputValue, InputMap};

use super::*;

#[test]
#[traced_test]
fn test_ivc() {
  let programs = vec![square_zeroth()];
  // TODO: This is a hack to get the correct number of folds when there are no external inputs.
  let switchboard_inputs = vec![
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
  ];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  dbg!(&snark.zi_primary());
  assert_eq!(snark.zi_primary()[0], Scalar::from(256));
  assert_eq!(snark.zi_primary()[1], Scalar::from(1));
}

#[test]
#[traced_test]
fn test_ivc_private_inputs() {
  let programs = vec![add_external()];
  let switchboard_inputs = vec![
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(3_u64)),
          InputValue::Field(GenericFieldElement::from(3_u64)),
        ]),
      ),
    ]),
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(420_u64)),
          InputValue::Field(GenericFieldElement::from(69_u64)),
        ]),
      ),
    ]),
  ];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(1), Scalar::from(2)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  assert_eq!(zi[0], Scalar::from(424));
  assert_eq!(zi[1], Scalar::from(74));
}

#[test]
#[traced_test]
fn test_nivc() {
  let programs = vec![add_external(), square_zeroth(), swap_memory()];
  let switchboard_inputs = vec![
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(1_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(5_u64)),
          InputValue::Field(GenericFieldElement::from(7_u64)),
        ]),
      ),
    ]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(2_u64)))]),
    InputMap::from([(
      "next_pc".to_string(),
      InputValue::Field(GenericFieldElement::from(-1_i128)),
    )]),
  ];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(1), Scalar::from(2)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  // First fold:
  // step_out[0] == 1 + 5 == 6
  // step_out[1] == 2 + 7 == 9
  // Second fold:
  // step_out[0] == 6 ** 2 == 36
  // step_out[1] == 9
  // Third fold:
  // step_out[0] == 9
  // step_out[1] == 36
  assert_eq!(zi[0], Scalar::from(9));
  assert_eq!(zi[1], Scalar::from(36));
}

#[test]
#[traced_test]
fn test_ivc_verify() {
  let programs = vec![square_zeroth()];
  let switchboard_inputs = vec![InputMap::from([(
    "next_pc".to_string(),
    InputValue::Field(GenericFieldElement::from(0_u64)),
  )])];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
  assert_eq!(z1_primary, vec![Scalar::from(4), Scalar::from(1)]);
  assert_eq!(z1_secondary, vec![grumpkin::Fr::ZERO]);
}

// TODO: Lots of clones here now.
#[test]
#[traced_test]
fn test_ivc_compression() {
  let programs = vec![square_zeroth()];
  let switchboard_inputs = vec![InputMap::from([(
    "next_pc".to_string(),
    InputValue::Field(GenericFieldElement::from(0_u64)),
  )])];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let compressed_proof = compress(&setup, &snark).unwrap();

  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof
    .proof
    .verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary())
    .unwrap();
}

#[test]
#[traced_test]
fn test_ivc_verify_basic() {
  let programs = vec![basic()];
  let switchboard_inputs = vec![InputMap::from([
    ("external_mul".to_string(), InputValue::Field(GenericFieldElement::from(3_u64))),
    ("external_add".to_string(), InputValue::Field(GenericFieldElement::from(10_u64))),
  ])];
  let switchboard = Switchboard::<ROM>::new(programs, switchboard_inputs, vec![Scalar::from(2)], 0);
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
  assert_eq!(z1_primary, vec![Scalar::from(436)]);
  assert_eq!(z1_secondary, vec![grumpkin::Fr::ZERO]);
}

#[test]
#[traced_test]
fn test_ivc_compression_basic() {
  let programs = vec![basic()];
  let switchboard_inputs = vec![InputMap::from([
    ("external_mul".to_string(), InputValue::Field(GenericFieldElement::from(3_u64))),
    ("external_add".to_string(), InputValue::Field(GenericFieldElement::from(10_u64))),
  ])];
  let switchboard = Switchboard::<ROM>::new(programs, switchboard_inputs, vec![Scalar::from(2)], 0);
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let compressed_proof = compress(&setup, &snark).unwrap();
  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof
    .proof
    .verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary())
    .unwrap();
}

#[test]
#[traced_test]
fn test_ivc_verify_poseidon() {
  let programs = vec![poseidon()];
  let switchboard_inputs = vec![InputMap::new()];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
}

#[test]
#[traced_test]
fn test_ivc_compression_poseidon() {
  let programs = vec![poseidon()];
  let switchboard_inputs = vec![InputMap::new()];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let compressed_proof = compress(&setup, &snark).unwrap();

  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof
    .proof
    .verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary())
    .unwrap();
}

#[test]
#[traced_test]
fn test_collatz() {
  let programs = vec![collatz_even(), collatz_odd()];
  let collatz_start = 19;
  let initial_circuit_index = collatz_start % 2;
  let switchboard = Switchboard::<RAM>::new(
    programs,
    vec![Scalar::from(collatz_start)],
    initial_circuit_index as usize,
  );
  let setup = Setup::new(switchboard);
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  dbg!(&z1_primary);
  dbg!(&snark.program_counter());
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
}
