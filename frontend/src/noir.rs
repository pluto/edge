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
use noirc_abi::{input_parser::InputValue, Abi, AbiParameter, AbiType, AbiVisibility};
use tracing::trace;

use super::*;
use crate::program::SwitchboardInputs;

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
  pub debug_symbols: String,
  pub file_map:      HashMap<String, String>,
  pub names:         Vec<String>,
  pub brillig_names: Vec<String>,
  #[serde(skip)]
  pub witness:       Option<SwitchboardInputs>,
  #[serde(skip)]
  pub index:         usize,
}

impl NoirProgram {
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  pub fn set_inputs(&mut self, switchboard_witness: SwitchboardInputs) {
    self.witness = Some(switchboard_witness);
  }
}

impl StepCircuit<Scalar> for NoirProgram {
  // TODO: This is a bit hacky. We need to add 1 for the PC
  fn arity(&self) -> usize { self.circuit().public_parameters.0.len() }

  fn circuit_index(&self) -> usize { self.index }

  #[allow(clippy::too_many_lines)]
  #[allow(clippy::too_many_lines)]
  fn synthesize<CS: ConstraintSystem<Scalar>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<Scalar>>,
    z: &[AllocatedNum<Scalar>],
  ) -> Result<(Option<AllocatedNum<Scalar>>, Vec<AllocatedNum<Scalar>>), SynthesisError> {
    trace!("Synthesizing NoirProgram with {} inputs", z.len());
    trace!("Inner pc: {:?}", pc);
    trace!("Circuit index: {}", self.index);
    trace!("ABI parameters: {:?}", self.abi.parameters);
    trace!("ABI return type: {:?}", self.abi.return_type);
    trace!("Private parameters: {:?}", self.circuit().private_parameters);
    trace!("Public parameters: {:?}", self.circuit().public_parameters);
    trace!("Return values: {:?}", self.circuit().return_values);

    // Create a map to track allocated variables for the cs
    let mut allocated_vars: HashMap<Witness, AllocatedNum<Scalar>> = HashMap::new();

    // Initialize ACVM and populate witness map from inputs
    let mut acvm_witness_map = if let Some(inputs) = &self.witness {
      trace!("Witness is present, initializing ACVM");
      let mut acvm = ACVM::new(
        &StubbedBlackBoxSolver(false),
        &self.circuit().opcodes,
        WitnessMap::new(),
        self.unconstrained_functions(),
        &[],
      );

      // Convert InputMap to ACVM witness map
      // We need to convert from Scalar to GenericFieldElement<Fr>
      // TODO: Shouldn't clone here, but it works for now.
      let mut inputs = inputs.private_inputs.clone();
      inputs.insert(
        "registers".to_string(),
        InputValue::Vec(
          z.iter()
            .map(|z| InputValue::Field(convert_to_acir_field(z.get_value().unwrap())))
            .collect(),
        ),
      );
      if let Ok(encoded_map) = self.abi.encode(&inputs, None) {
        for (witness, value) in encoded_map {
          // Convert FieldElement to GenericFieldElement<Fr>
          acvm.overwrite_witness(witness, value);
        }
      }

      // Execute ACVM to get witness values
      trace!("Executing ACVM solve...");
      let status = acvm.solve();
      trace!("ACVM solve status: {:?}", status);

      let witness_map = acvm.finalize();
      Some(witness_map)
    } else {
      trace!("No witness provided, skipping ACVM initialization");
      None
    };

    // Allocate public variables from z
    for (i, witness) in self.circuit().public_parameters.0.iter().enumerate() {
      if i < z.len() {
        trace!("Allocating public input {} (witness {:?}) from z", i, witness);
        allocated_vars.insert(*witness, z[i].clone());
      }
    }

    // Allocate private variables
    for &witness in &self.circuit().private_parameters {
      if !allocated_vars.contains_key(&witness) {
        let value = acvm_witness_map
          .as_ref()
          .and_then(|map| map.get(&witness))
          .map(|&v| convert_to_halo2_field(v));

        trace!("Allocating private input (witness {:?}) with value: {:?}", witness, value);
        let var = AllocatedNum::alloc(
          &mut cs.namespace(|| format!("private_input_{}", witness.as_usize())),
          || Ok(value.unwrap_or_else(Scalar::zero)),
        )?;

        allocated_vars.insert(witness, var);
      }
    }

    // Helper function to get or create a variable for a witness
    let get_var = |witness: &Witness,
                   allocated_vars: &mut HashMap<Witness, AllocatedNum<Scalar>>,
                   cs: &mut CS,
                   gate_idx: usize|
     -> Result<Variable, SynthesisError> {
      if let Some(var) = allocated_vars.get(witness) {
        trace!("Using existing variable for witness {:?}", witness);
        Ok(var.get_variable())
      } else {
        trace!("Allocating new variable for witness {:?} in gate {}", witness, gate_idx);

        // Get value from ACVM if available
        let value = acvm_witness_map
          .as_ref()
          .and_then(|map| map.get(witness))
          .map(|&v| convert_to_halo2_field(v));

        let var = AllocatedNum::alloc(
          cs.namespace(|| format!("aux_{}_w{}", gate_idx, witness.as_usize())),
          || Ok(value.unwrap_or_else(Scalar::zero)),
        )?;

        allocated_vars.insert(*witness, var.clone());
        trace!("Added auxiliary witness {:?} to allocated_vars", witness);

        Ok(var.get_variable())
      }
    };

    // Process gates
    trace!("Processing {} gates", self.circuit().opcodes.len());
    for (gate_idx, opcode) in self.circuit().opcodes.iter().enumerate() {
      if let Opcode::AssertZero(gate) = opcode {
        // Initialize empty linear combinations for each part of our R1CS constraint
        let mut left_terms = LinearCombination::zero();
        let mut right_terms = LinearCombination::zero();
        let mut final_terms = LinearCombination::zero();

        // Process multiplication terms (these form the A and B matrices in R1CS)
        for mul_term in &gate.mul_terms {
          let coeff = convert_to_halo2_field(mul_term.0);
          let left_var = get_var(&mul_term.1, &mut allocated_vars, cs, gate_idx)?;
          let right_var = get_var(&mul_term.2, &mut allocated_vars, cs, gate_idx)?;

          // Build Az (left terms) with coefficient
          left_terms = left_terms + (coeff, left_var);
          // Build Bz (right terms) with coefficient 1
          right_terms = right_terms + (Scalar::one(), right_var);
        }

        // Process addition terms (these contribute to the C matrix in R1CS)
        for add_term in &gate.linear_combinations {
          let coeff = convert_to_halo2_field(add_term.0);
          let var = get_var(&add_term.1, &mut allocated_vars, cs, gate_idx)?;
          final_terms = final_terms + (coeff, var);
        }

        // Handle constant term if present
        if !gate.q_c.is_zero() {
          let const_coeff = convert_to_halo2_field(gate.q_c);
          // Negate the constant term since we're moving it to the other side of the equation
          final_terms = final_terms - (const_coeff, Variable::new_unchecked(Index::Input(0)));
        }

        // Enforce the R1CS constraint: Az ∘ Bz = Cz
        cs.enforce(
          || format!("gate_{gate_idx}"),
          |_| left_terms.clone(),
          |_| right_terms.clone(),
          |_| final_terms,
        );
      } else {
        panic!("non-AssertZero gate {} of type {:?}", gate_idx, opcode);
      }
    }

    // Prepare return values
    trace!("Preparing return values");
    let mut return_values = vec![];

    // Ensure all return witnesses have allocated variables
    for (i, ret) in self.circuit().return_values.0.iter().enumerate() {
      if !allocated_vars.contains_key(ret) {
        trace!("Return value {} (witness {:?}) not yet allocated, creating", i, ret);

        // Get value from ACVM if available
        let value = acvm_witness_map
          .as_ref()
          .and_then(|map| map.get(ret))
          .map(|&v| convert_to_halo2_field(v));

        let var = AllocatedNum::alloc(&mut cs.namespace(|| format!("return_value_{}", i)), || {
          Ok(value.unwrap_or_else(Scalar::zero))
        })?;

        allocated_vars.insert(*ret, var);
      }

      trace!("Adding return value {} (witness {:?}) to results", i, ret);
      return_values.push(allocated_vars[ret].clone());
    }

    // Extract return structure from ABI
    if let Some(return_type) = &self.abi.return_type {
      if let AbiType::Struct { fields, .. } = &return_type.abi_type {
        // Find the registers field in the struct
        let (registers_length, next_pc_index) = fields
        .iter()
        .find(|(name, _)| name == "registers")
        .map(|(_, typ)| match typ {
          AbiType::Array { length, .. } => (*length as usize, *length as usize), // next_pc follows registers
          _ => panic!("Expected registers to be an array type, found {:?}", typ),
        })
        .unwrap_or_else(|| panic!("Expected 'registers' field in return struct"));

        trace!(
          "Return struct has registers_length={}, next_pc_index={}",
          registers_length,
          next_pc_index
        );

        if next_pc_index < return_values.len() {
          // Extract next_pc and registers
          let next_pc = Some(return_values[next_pc_index].clone());
          let registers = return_values[..registers_length].to_vec();

          trace!(
            "Returning next_pc at index {} and {} register values",
            next_pc_index,
            registers.len()
          );
          return Ok((next_pc, registers));
        } else {
          trace!(
            "ERROR: next_pc_index {} out of bounds for return_values length {}",
            next_pc_index,
            return_values.len()
          );
          return Err(SynthesisError::Unsatisfiable);
        }
      } else {
        trace!("Return type is not a struct: {:?}", return_type.abi_type);
        return Err(SynthesisError::Unsatisfiable);
      }
    } else {
      trace!("No return type specified");
      return Err(SynthesisError::Unsatisfiable);
    }
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
  use super::*;

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
    let json_path = "../examples/add_external/target/add_external.json";
    let json_data = std::fs::read(json_path).expect("Failed to read add_external.json");

    let program: NoirProgram =
      serde_json::from_slice(&json_data).expect("Failed to deserialize add_external.json");

    // Verify basic structure
    assert_eq!(program.version, "1.0.0-beta.2+1a2a08cbcb68646ff1aaef383cfc1798933c1355");
    assert_eq!(program.hash, 2789485860577127199);

    // Verify parameters
    assert_eq!(program.abi.parameters.len(), 3);
    assert_eq!(program.abi.parameters[0].name, "external");
    assert_eq!(program.abi.parameters[1].name, "registers");
    assert_eq!(program.abi.parameters[2].name, "next_pc");

    // Verify return type
    if let AbiType::Struct { fields, path } = &program.abi.return_type.as_ref().unwrap().abi_type {
      assert_eq!(fields.len(), 2);
      assert_eq!(path, "FoldingIO");
      assert_eq!(fields[0].0, "registers");
      assert_eq!(fields[1].0, "next_pc");
    } else {
      panic!("Expected tuple return type, got {:?}", program.abi.return_type);
    }
  }
}
