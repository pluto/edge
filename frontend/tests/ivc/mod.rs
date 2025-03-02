use acvm::acir::acir_field::GenericFieldElement;
use client_side_prover_frontend::program::{run, Switchboard};
use noirc_abi::{input_parser::InputValue, InputMap};

use super::*;

#[test]
#[traced_test]
fn test_ivc() {
  let circuit = square_zeroth();
  let switchboard_inputs = vec![
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
  ];

  let memory = Switchboard {
    circuits: vec![circuit],
    public_input: vec![Scalar::from(2), Scalar::from(1)],
    initial_circuit_index: 0,
    switchboard_inputs,
  };

  let snark = run(&memory).unwrap();
  dbg!(&snark.zi_primary());
  assert_eq!(snark.zi_primary()[0], Scalar::from(256));
  assert_eq!(snark.zi_primary()[1], Scalar::from(1));
}

#[test]
#[traced_test]
fn test_ivc_private_inputs() {
  let circuit = add_external();
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

  let memory = Switchboard {
    circuits: vec![circuit],
    public_input: vec![Scalar::from(1), Scalar::from(2)],
    initial_circuit_index: 0,
    switchboard_inputs,
  };

  let snark = run(&memory).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  assert_eq!(zi[0], Scalar::from(424));
  assert_eq!(zi[1], Scalar::from(74));
}

// #[test]
// #[traced_test]
// fn test_mock_noir_nivc() {
//   let mut add_external = NoirProgram::new(ADD_EXTERNAL);
//   add_external.set_private_inputs(vec![Scalar::from(5), Scalar::from(7)]);
//   let add_external =
//     NoirRomCircuit { circuit: add_external, circuit_index: 0, rom_size: 3 };

//   // TODO: The issue is the private inputs need to be an empty vector or else this isn't computed
// at   // all. Be careful, this is insanely touchy and I hate that it is this way.
//   let mut square_zeroth = NoirProgram::new(SQUARE_ZEROTH);
//   square_zeroth.set_private_inputs(vec![]);
//   let square_zeroth =
//     NoirRomCircuit { circuit: square_zeroth, circuit_index: 1, rom_size: 3 };
//   let mut swap_memory = NoirProgram::new(SWAP_MEMORY);
//   swap_memory.set_private_inputs(vec![]);
//   let swap_memory =
//     NoirRomCircuit { circuit: swap_memory, circuit_index: 2, rom_size: 3 };

//   let memory = NoirMemory {
//     circuits:     vec![add_external, square_zeroth, swap_memory],
//     rom:          vec![0, 1, 2],
//     public_input: vec![
//       Scalar::from(1), // Actual input
//       Scalar::from(2), // Actual input
//       Scalar::from(0), // PC
//       Scalar::from(0), // ROM
//       Scalar::from(1), // ROM
//       Scalar::from(2), // ROM
//     ],
//   };

//   let snark = run(&memory).unwrap();
//   let zi = snark.zi_primary();
//   dbg!(zi);
//   // First fold:
//   // step_out[0] == 1 + 5 == 6
//   // step_out[1] == 2 + 7 == 9
//   // Second fold:
//   // step_out[0] == 6 ** 2 == 36
//   // step_out[1] == 9
//   // Third fold:
//   // step_out[0] == 9
//   // step_out[1] == 36
//   assert_eq!(zi[0], Scalar::from(9));
//   assert_eq!(zi[1], Scalar::from(36));
//   assert_eq!(zi[2], Scalar::from(3));
//   assert_eq!(zi[3], Scalar::from(0));
//   assert_eq!(zi[4], Scalar::from(1));
//   assert_eq!(zi[5], Scalar::from(2));
// }
