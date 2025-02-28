#[test]
#[traced_test]
fn test_mock_noir_ivc() {
  let mut circuit = noir_fold();
  circuit.set_private_inputs(vec![F::<G1>::from(3)]);

  let rom_circuit = NoirRomCircuit { circuit, circuit_index: 0, rom_size: 2 };

  let memory = NoirMemory {
    circuits:     vec![rom_circuit],
    rom:          vec![0, 0],
    public_input: vec![
      F::<G1>::from(1), // Actual input
      F::<G1>::from(2), // Actual input
      F::<G1>::from(0), // PC
      F::<G1>::from(0), // ROM
      F::<G1>::from(0), // ROM
    ],
  };

  let snark = run(&memory).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  // First fold:
  // step_out[0] == 3 * 1 + 2 + 1   == 6
  // step_out[1] == (3 + 3) * 2 + 1 == 13
  // Second fold:
  // step_out[0] == 3 * 6 + 13 + 1 == 32
  // step_out[1] == (3 + 3) * 13 + 6 == 84
  assert_eq!(zi[0], F::<G1>::from(32));
  assert_eq!(zi[1], F::<G1>::from(84));
  assert_eq!(zi[2], F::<G1>::from(2));
  assert_eq!(zi[3], F::<G1>::from(0));
  assert_eq!(zi[4], F::<G1>::from(0));
}

#[test]
#[traced_test]
fn test_mock_noir_nivc() {
  let mut add_external = NoirProgram::new(ADD_EXTERNAL);
  add_external.set_private_inputs(vec![F::<G1>::from(5), F::<G1>::from(7)]);
  let add_external =
    NoirRomCircuit { circuit: add_external, circuit_index: 0, rom_size: 3 };

  // TODO: The issue is the private inputs need to be an empty vector or else this isn't computed at
  // all. Be careful, this is insanely touchy and I hate that it is this way.
  let mut square_zeroth = NoirProgram::new(SQUARE_ZEROTH);
  square_zeroth.set_private_inputs(vec![]);
  let square_zeroth =
    NoirRomCircuit { circuit: square_zeroth, circuit_index: 1, rom_size: 3 };
  let mut swap_memory = NoirProgram::new(SWAP_MEMORY);
  swap_memory.set_private_inputs(vec![]);
  let swap_memory =
    NoirRomCircuit { circuit: swap_memory, circuit_index: 2, rom_size: 3 };

  let memory = NoirMemory {
    circuits:     vec![add_external, square_zeroth, swap_memory],
    rom:          vec![0, 1, 2],
    public_input: vec![
      F::<G1>::from(1), // Actual input
      F::<G1>::from(2), // Actual input
      F::<G1>::from(0), // PC
      F::<G1>::from(0), // ROM
      F::<G1>::from(1), // ROM
      F::<G1>::from(2), // ROM
    ],
  };

  let snark = run(&memory).unwrap();
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
  assert_eq!(zi[0], F::<G1>::from(9));
  assert_eq!(zi[1], F::<G1>::from(36));
  assert_eq!(zi[2], F::<G1>::from(3));
  assert_eq!(zi[3], F::<G1>::from(0));
  assert_eq!(zi[4], F::<G1>::from(1));
  assert_eq!(zi[5], F::<G1>::from(2));
}
