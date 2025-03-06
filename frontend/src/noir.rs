//! # Noir Program Integration
//!
//! This module provides the integration between Noir programs and the NIVC system.
//! It handles the translation of Noir's ACIR (Abstract Circuit Intermediate Representation)
//! into constraints that can be used in the folding proof system. This allows Noir programs
//! to be used as circuit components in Non-uniform Incrementally Verifiable Computation.
//!
//! ## Key Components
//!
//! - `NoirProgram`: Represents a compiled Noir program with its bytecode and ABI
//! - `StepCircuit` implementation: Allows Noir programs to be used in the `SuperNova` NIVC system
//! - Field conversion functions: Convert between ACIR field representation and proof system fields

use std::collections::{BTreeMap, HashMap};

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
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, LinearCombination, SynthesisError};
use client_side_prover::supernova::StepCircuit;
use ff::PrimeField;
use noirc_abi::{input_parser::InputValue, Abi, AbiType, InputMap};
use tracing::{error, trace};

use super::*;

/// Represents a compiled Noir program ready for execution in the NIVC system
///
/// A `NoirProgram` contains the compiled bytecode of a Noir program along with its ABI
/// (Application Binary Interface) which describes the program's inputs and outputs.
/// It can be used as a circuit component in the `SuperNova` NIVC system.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NoirProgram {
  /// The program's ABI describing its inputs and outputs
  pub abi: Abi,

  /// The program's bytecode in ACIR format, serialized as base64
  #[serde(
    serialize_with = "Program::serialize_program_base64",
    deserialize_with = "Program::deserialize_program_base64"
  )]
  pub bytecode: Program<GenericFieldElement<Fr>>,

  /// Optional witness inputs for the program (is used internally by the [`program::run`] function)
  #[serde(skip)]
  pub witness: Option<InputMap>,

  /// The index of this program in the switchboard's circuit list
  #[serde(skip)]
  pub index: usize,
}

impl NoirProgram {
  /// Creates a new `NoirProgram` from JSON bytecode
  ///
  /// # Arguments
  ///
  /// * `bin` - The JSON bytecode of a compiled Noir program
  ///
  /// # Returns
  ///
  /// A new `NoirProgram` instance
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  /// Gets the main circuit from the program
  ///
  /// # Returns
  ///
  /// A reference to the main circuit function
  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  /// Gets the unconstrained functions from the program
  ///
  /// Unconstrained functions are functions that are executed during witness generation
  /// but do not contribute to the circuit's constraints. These are handled by the
  /// [`StubbedBlackBoxSolver`].
  ///
  /// # Returns
  ///
  /// A reference to the list of unconstrained functions
  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  /// Sets the witness inputs for the program
  ///
  /// # Arguments
  ///
  /// * `witness` - The input map containing witness values
  pub fn set_inputs(&mut self, witness: InputMap) { self.witness = Some(witness); }
}

impl StepCircuit<Scalar> for NoirProgram {
  /// Returns the number of registers in the folding state
  ///
  /// This is determined by examining the ABI to find the "registers" array
  /// in the `FoldingVariables` struct.
  fn arity(&self) -> usize {
    let input_type = self
      .abi
      .parameters
      .iter()
      .find(|param| {
        if let AbiType::Struct { path, .. } = &param.typ {
          path == "nivc::FoldingVariables"
        } else {
          false
        }
      })
      .map(|param| &param.typ);

    let return_type = self.abi.return_type.as_ref().map(|ret| &ret.abi_type);

    let get_register_length = |typ: &AbiType| -> usize {
      if let AbiType::Struct { fields, .. } = typ {
        if let Some((_, AbiType::Array { length, .. })) =
          fields.iter().find(|(name, _)| name == "registers")
        {
          *length as usize
        } else {
          panic!("FoldingVariables missing registers array or invalid type")
        }
      } else {
        panic!("Expected struct type for FoldingVariables")
      }
    };

    match (input_type, return_type) {
      (Some(input), Some(output)) => {
        if let (AbiType::Struct { path: in_path, .. }, AbiType::Struct { path: out_path, .. }) =
          (input, output)
        {
          if in_path == "nivc::FoldingVariables" && out_path == "nivc::FoldingVariables" {
            let in_len = get_register_length(input);
            let out_len = get_register_length(output);

            assert!(
              in_len == out_len,
              "Input and output must have same number of registers: {in_len} vs {out_len}",
            );

            return in_len;
          }
        }
        panic!("Both input and output must be nivc::FoldingVariables structs")
      },
      _ => panic!("Missing input or output FoldingVariables type"),
    }
  }

  /// Returns the index of this circuit in the switchboard
  fn circuit_index(&self) -> usize { self.index }

  /// Synthesizes the Noir program into a constraint system
  ///
  /// This is the core method that translates the Noir program's ACIR representation
  /// into constraints that can be used in the folding proof system. It processes
  /// each gate in the ACIR circuit and creates corresponding constraints in the
  /// target constraint system.
  ///
  /// # Arguments
  ///
  /// * `cs` - The constraint system to add constraints to
  /// * `pc` - The program counter (next circuit to execute)
  /// * `z` - The current folding state (register values)
  ///
  /// # Returns
  ///
  /// A tuple of the next program counter and updated register values
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

      // TODO: Can we remove this clone since it may be a lot of data?
      let mut inputs_with_folding_variables = inputs.clone();
      let folding_variables = InputValue::Struct(BTreeMap::from([
        (
          "registers".to_string(),
          InputValue::Vec(
            z.iter()
              .filter_map(|var| {
                var.get_value().map(|v| InputValue::Field(convert_to_acir_field(v)))
              })
              .collect(),
          ),
        ),
        (
          // TODO: This is a bit hacky with unwraps
          "program_counter".to_string(),
          InputValue::Field(convert_to_acir_field(pc.unwrap().get_value().unwrap())),
        ),
      ]));
      inputs_with_folding_variables.insert("folding_variables".to_string(), folding_variables);

      // Encode inputs through ABI
      if let Ok(encoded_map) = self.abi.encode(&inputs_with_folding_variables, None) {
        for (witness, value) in encoded_map {
          acvm.overwrite_witness(witness, value);
        }
      }

      // Solve and get resulting witness map
      debug!("Executing ACVM solve...");
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
          let left_variable = get_var(&mul_term.1, &mut allocated_vars, cs)?;
          let right_variable = get_var(&mul_term.2, &mut allocated_vars, cs)?;

          // Get the values if available
          let left_value = acvm_witness_map
            .as_ref()
            .and_then(|map| map.get(&mul_term.1))
            .map(|&v| convert_to_halo2_field(v));

          let right_value = acvm_witness_map
            .as_ref()
            .and_then(|map| map.get(&mul_term.2))
            .map(|&v| convert_to_halo2_field(v));

          // Create a new variable for the product
          let product = AllocatedNum::alloc(
            cs.namespace(|| format!("prod_g{idx}_t{}", mul_term.1.as_usize())),
            || {
              let l = left_value.unwrap_or_else(Scalar::zero);
              let r = right_value.unwrap_or_else(Scalar::zero);
              Ok(l * r)
            },
          )?;

          // Enforce that this is indeed the product
          cs.enforce(
            || format!("prod_constraint_g{idx}_t{}", mul_term.1.as_usize()),
            |lc| lc + left_variable,
            |lc| lc + right_variable,
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
      let registers_field = fields
        .iter()
        .find(|(name, _)| name == "registers")
        .unwrap_or_else(|| panic!("Missing 'registers' field"));

      let registers_length = match &registers_field.1 {
        AbiType::Array { length, .. } => *length as usize,
        _ => panic!("Expected registers to be an array type"),
      };

      if return_values.len() > registers_length {
        let registers = return_values[0..registers_length].to_vec();
        let next_pc = Some(return_values[registers_length].clone());

        trace!("Extracted {} registers and program counter", registers.len());
        return Ok((next_pc, registers));
      }
      error!(
        "Not enough return values. Expected at least {}, got {}",
        registers_length + 1,
        return_values.len()
      );
      return Err(SynthesisError::Unsatisfiable);
    }

    Err(SynthesisError::Unsatisfiable)
  }
}

/// Converts a field element from ACIR representation to Halo2 representation
///
/// # Arguments
///
/// * `f` - The field element in ACIR representation
///
/// # Returns
///
/// The field element in Halo2 representation
fn convert_to_halo2_field(f: GenericFieldElement<Fr>) -> Scalar {
  let bytes = f.to_be_bytes();
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes[..32]);
  arr.reverse();
  Scalar::from_repr(arr).unwrap()
}

/// Converts a field element from Halo2 representation to ACIR representation
///
/// # Arguments
///
/// * `f` - The field element in Halo2 representation
///
/// # Returns
///
/// The field element in ACIR representation
fn convert_to_acir_field(f: Scalar) -> GenericFieldElement<Fr> {
  let mut bytes = f.to_bytes();
  bytes.reverse();
  GenericFieldElement::from_be_bytes_reduce(&bytes)
}

#[cfg(test)]
mod tests {
  use client_side_prover::bellpepper::shape_cs::ShapeCS;

  use super::*;
  use crate::demo::{basic, poseidon, square_zeroth};

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

    // Verify parameters
    assert_eq!(program.abi.parameters.len(), 3);
    assert_eq!(program.abi.parameters[0].name, "folding_variables");
    assert_eq!(program.abi.parameters[1].name, "external");
    assert_eq!(program.abi.parameters[2].name, "next_pc");

    // Verify return type
    if let AbiType::Struct { fields, path } = &program.abi.return_type.as_ref().unwrap().abi_type {
      assert_eq!(fields.len(), 2);
      assert_eq!(path, "nivc::FoldingVariables");
      assert_eq!(fields[0].0, "registers");
      assert_eq!(fields[1].0, "program_counter");
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
    assert_eq!(cs.num_constraints(), 3);
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
