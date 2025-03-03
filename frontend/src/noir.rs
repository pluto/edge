use std::collections::HashMap;

use acvm::{
  acir::{
    acir_field::GenericFieldElement,
    circuit::{brillig::BrilligBytecode, Circuit, Opcode, Program},
    native_types::{Witness, WitnessMap},
  },
  blackbox_solver::StubbedBlackBoxSolver,
  pwg::ACVM,
  AcirField,
};
use ark_bn254::Fr;
use bellpepper_core::{
  num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable,
};
use client_side_prover::supernova::StepCircuit;
use ff::PrimeField;
use noirc_abi::{input_parser::InputValue, Abi, AbiType, InputMap};
use tracing::{debug, error, info, trace, warn};

use super::*;

// TODO: If we deserialize more here and get metadata, we could more easily look at witnesses, etc.
// Especially if we want to output a constraint to the PC. Using the abi would be handy for
// assigning inputs.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
  #[serde(rename = "noir_version")]
  pub version:       String,
  pub hash:          u64,
  pub abi:           Abi,
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode:      Program<GenericFieldElement<Fr>>,
  // TODO: We likely don't need these.
  pub debug_symbols: serde_json::Value,
  // TODO: We likely don't need these.
  pub file_map:      serde_json::Value,

  pub names:         Vec<String>,
  pub brillig_names: Vec<String>,
  #[serde(skip)]
  pub witness:       Option<InputMap>,
  #[serde(skip)]
  pub index:         usize,
}

impl NoirProgram {
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  pub fn set_inputs(&mut self, switchboard_witness: InputMap) {
    self.witness = Some(switchboard_witness);
  }
}

impl StepCircuit<Scalar> for NoirProgram {
  // TODO: This is a bit hacky. We need to add 1 for the PC
  fn arity(&self) -> usize { self.circuit().public_parameters.0.len() }

  fn circuit_index(&self) -> usize { self.index }

  #[allow(clippy::too_many_lines)]
  fn synthesize<CS: ConstraintSystem<Scalar>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<Scalar>>,
    z: &[AllocatedNum<Scalar>],
  ) -> Result<(Option<AllocatedNum<Scalar>>, Vec<AllocatedNum<Scalar>>), SynthesisError> {
    trace!("Synthesizing NoirProgram with {} inputs", z.len());

    // Create variable tracker and initialize ACVM
    let mut allocated_vars: HashMap<Witness, AllocatedNum<Scalar>> = HashMap::new();
    let acvm_witness_map = self.witness.as_ref().map(|inputs| {
      let mut acvm = ACVM::new(
        &StubbedBlackBoxSolver(false),
        &self.circuit().opcodes,
        WitnessMap::new(),
        self.unconstrained_functions(),
        &[],
      );

      // Prepare inputs with registers
      // TODO: Can we reove this clone?
      let mut inputs_with_registers = inputs.clone();
      inputs_with_registers.insert(
        "registers".to_string(),
        InputValue::Vec(
          z.iter()
            .filter_map(|var| var.get_value().map(|v| InputValue::Field(convert_to_acir_field(v))))
            .collect(),
        ),
      );

      // Encode inputs through ABI
      if let Ok(encoded_map) = self.abi.encode(&inputs_with_registers, None) {
        for (witness, value) in encoded_map {
          acvm.overwrite_witness(witness, value);
        }
      }

      // Solve and get resulting witness map
      trace!("Executing ACVM solve...");
      acvm.solve();
      acvm.finalize()
    });

    // Allocate variables from public inputs (z)
    for (i, witness) in self.circuit().public_parameters.0.iter().enumerate() {
      if i < z.len() {
        allocated_vars.insert(*witness, z[i].clone());
      }
    }

    // Helper for getting/creating variables
    let get_var = |witness: &Witness,
                   vars: &mut HashMap<Witness, AllocatedNum<Scalar>>,
                   cs: &mut CS| {
      if let Some(var) = vars.get(witness) {
        Ok::<_, SynthesisError>(var.get_variable())
      } else {
        let value = acvm_witness_map
          .as_ref()
          .and_then(|map| map.get(witness))
          .map(|&v| convert_to_halo2_field(v));

        let var = AllocatedNum::alloc(cs.namespace(|| format!("w{}", witness.as_usize())), || {
          Ok(value.unwrap_or_else(Scalar::zero))
        })?;

        vars.insert(*witness, var.clone());
        Ok(var.get_variable())
      }
    };

    // Process gates using R1CS approach
    for (idx, opcode) in self.circuit().opcodes.iter().enumerate() {
      if let Opcode::AssertZero(gate) = opcode {
        // Create a single linear combination that will be constrained to zero
        let mut zero_lc = LinearCombination::zero();

        // Handle mul terms by creating intermediate variables for each product
        for mul_term in &gate.mul_terms {
          let left_var = get_var(&mul_term.1, &mut allocated_vars, cs)?;
          let right_var = get_var(&mul_term.2, &mut allocated_vars, cs)?;

          // Get the values if available
          let left_val = acvm_witness_map
            .as_ref()
            .and_then(|map| map.get(&mul_term.1))
            .map(|&v| convert_to_halo2_field(v));

          let right_val = acvm_witness_map
            .as_ref()
            .and_then(|map| map.get(&mul_term.2))
            .map(|&v| convert_to_halo2_field(v));

          // Create a new variable for the product
          let product = AllocatedNum::alloc(
            cs.namespace(|| format!("prod_g{idx}_t{}", mul_term.1.as_usize())),
            || {
              let l = left_val.unwrap_or_else(Scalar::zero);
              let r = right_val.unwrap_or_else(Scalar::zero);
              Ok(l * r)
            },
          )?;

          // Enforce that this is indeed the product
          cs.enforce(
            || format!("prod_constraint_g{idx}_t{}", mul_term.1.as_usize()),
            |lc| lc + left_var,
            |lc| lc + right_var,
            |lc| lc + product.get_variable(),
          );

          // Add this product to our zero linear combination with the coefficient
          zero_lc = zero_lc + (convert_to_halo2_field(mul_term.0), product.get_variable());
        }

        // Handle linear terms (these go into the zero linear combination)
        for add_term in &gate.linear_combinations {
          let var = get_var(&add_term.1, &mut allocated_vars, cs)?;
          zero_lc = zero_lc + (convert_to_halo2_field(add_term.0), var);
        }

        // Handle constant term
        if !gate.q_c.is_zero() {
          zero_lc = zero_lc + (convert_to_halo2_field(gate.q_c), CS::one());
        }

        // Enforce that the entire expression equals zero
        cs.enforce(
          || format!("constraint_g{idx}"),
          |_| LinearCombination::zero() + CS::one(),
          |_| zero_lc.clone(),
          |_| LinearCombination::zero(),
        );
      } else {
        warn!("non-AssertZero gate {idx} of type {opcode:?}");
      }
    }

    // Prepare return values
    let mut return_values = vec![];
    for ret in &self.circuit().return_values.0 {
      // Ensure return witness has an allocated variable
      if !allocated_vars.contains_key(ret) {
        let value = acvm_witness_map
          .as_ref()
          .and_then(|map| map.get(ret))
          .map(|&v| convert_to_halo2_field(v));

        let var = AllocatedNum::alloc(cs.namespace(|| format!("ret{}", ret.as_usize())), || {
          Ok(value.unwrap_or_else(Scalar::zero))
        })?;

        allocated_vars.insert(*ret, var);
      }
      return_values.push(allocated_vars[ret].clone());
    }

    // Extract return structure (registers and next_pc)
    if let Some(noirc_abi::AbiReturnType { abi_type: AbiType::Struct { fields, .. }, .. }) =
      &self.abi.return_type
    {
      // TODO: This should be an error.
      let registers_length = fields
        .iter()
        .find(|(name, _)| name == "registers")
        .map(|(_, typ)| match typ {
          AbiType::Array { length, .. } => *length as usize,
          _ => panic!("Expected registers to be an array type"),
        })
        .unwrap_or_else(|| panic!("Missing 'registers' field"));

      let next_pc_index = registers_length;

      if next_pc_index < return_values.len() {
        let next_pc = Some(return_values[next_pc_index].clone());
        dbg!(&next_pc);
        let registers = return_values[..registers_length].to_vec();
        return Ok((next_pc, registers));
      }
    }

    Err(SynthesisError::Unsatisfiable)
  }
}

fn convert_to_halo2_field(f: GenericFieldElement<Fr>) -> Scalar {
  let bytes = f.to_be_bytes();
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes[..32]);
  arr.reverse();
  Scalar::from_repr(arr).unwrap()
}

fn convert_to_acir_field(f: Scalar) -> GenericFieldElement<Fr> {
  let mut bytes = f.to_bytes();
  bytes.reverse();
  GenericFieldElement::from_be_bytes_reduce(&bytes)
}

#[cfg(test)]
mod tests {
  use client_side_prover::bellpepper::shape_cs::ShapeCS;

  use super::*;
  use crate::demo::{basic, http, poseidon, square_zeroth};

  fn add_external() -> NoirProgram {
    let json_path = "../target/add_external.json";
    let json_data = std::fs::read(json_path).expect("Failed to read add_external.json");

    serde_json::from_slice(&json_data).expect("Failed to deserialize add_external.json")
  }

  #[test]
  fn test_conversions() {
    let f = Scalar::from(5);
    let acir_f = convert_to_acir_field(f);
    assert_eq!(acir_f, GenericFieldElement::from_repr(Fr::from(5)));

    let f = GenericFieldElement::from_repr(Fr::from(3));
    let halo2_f = convert_to_halo2_field(f);
    assert_eq!(halo2_f, Scalar::from(3));
  }

  #[test]
  fn test_deserialize_abi() {
    let program = add_external();

    // Verify basic structure
    assert_eq!(program.version, "1.0.0-beta.2+1a2a08cbcb68646ff1aaef383cfc1798933c1355");
    assert_eq!(program.hash, 4842196402509912449);

    // Verify parameters
    assert_eq!(program.abi.parameters.len(), 3);
    assert_eq!(program.abi.parameters[0].name, "registers");
    assert_eq!(program.abi.parameters[1].name, "external");
    assert_eq!(program.abi.parameters[2].name, "next_pc");

    // Verify return type
    if let AbiType::Struct { fields, path } = &program.abi.return_type.as_ref().unwrap().abi_type {
      assert_eq!(fields.len(), 2);
      assert_eq!(path, "nivc::FoldingOutput");
      assert_eq!(fields[0].0, "registers");
      assert_eq!(fields[1].0, "next_pc");
    } else {
      panic!("Expected tuple return type, got {:?}", program.abi.return_type);
    }
  }

  // TODO: Worth checking here that each gate has mul, add, and constant terms.
  #[test]
  fn test_constraint_system_basic() {
    let program = basic();

    let mut cs = ShapeCS::<E1>::new();
    let pc = Some(AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(0))).unwrap());
    let z = vec![
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(2))).unwrap(),
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(1))).unwrap(),
    ];

    let _ = program.synthesize(&mut cs, pc.as_ref(), z.as_ref()).unwrap();
    assert_eq!(cs.num_constraints(), 5);
  }

  #[test]
  fn test_constraint_system_add_external() {
    let program = add_external();

    let mut cs = ShapeCS::<E1>::new();
    let pc = Some(AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(0))).unwrap());
    let z = vec![
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(2))).unwrap(),
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(1))).unwrap(),
    ];

    let _ = program.synthesize(&mut cs, pc.as_ref(), z.as_ref()).unwrap();
    assert_eq!(cs.num_constraints(), 3);
  }

  #[test]
  fn test_constraint_system_square_zeroth() {
    let program = square_zeroth();

    let mut cs = ShapeCS::<E1>::new();
    let pc = Some(AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(0))).unwrap());
    let z = vec![
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(2))).unwrap(),
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(1))).unwrap(),
    ];

    let _ = program.synthesize(&mut cs, pc.as_ref(), z.as_ref()).unwrap();
    assert_eq!(cs.num_constraints(), 4);
  }

  #[test]
  fn test_constraint_system_poseidon() {
    let program = poseidon();

    let mut cs = ShapeCS::<E1>::new();
    let pc = Some(AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(0))).unwrap());
    let z = vec![
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(2))).unwrap(),
      AllocatedNum::alloc(&mut cs, || Ok(Scalar::from(1))).unwrap(),
    ];

    let _ = program.synthesize(&mut cs, pc.as_ref(), z.as_ref()).unwrap();
    assert_eq!(cs.num_constraints(), 560);
  }
}
