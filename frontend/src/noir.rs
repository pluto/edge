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
use noirc_abi::{Abi, AbiParameter, AbiType, AbiVisibility};
use tracing::trace;

use super::*;
use crate::program::SwitchboardWitness;

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
  pub witness:       Option<SwitchboardWitness>,
  #[serde(skip)]
  pub index:         usize,
}

impl NoirProgram {
  pub fn new(bin: &[u8]) -> Self { serde_json::from_slice(bin).unwrap() }

  pub fn circuit(&self) -> &Circuit<GenericFieldElement<Fr>> { &self.bytecode.functions[0] }

  pub fn unconstrained_functions(&self) -> &Vec<BrilligBytecode<GenericFieldElement<Fr>>> {
    &self.bytecode.unconstrained_functions
  }

  pub fn set_inputs(&mut self, switchboard_witness: SwitchboardWitness) {
    self.witness = Some(switchboard_witness);
  }
}

impl StepCircuit<F<G1>> for NoirProgram {
  // TODO: This is a bit hacky. We need to add 1 for the PC
  fn arity(&self) -> usize { self.circuit().public_parameters.0.len() }

  fn circuit_index(&self) -> usize { self.index }

  #[allow(clippy::too_many_lines)]
  fn synthesize<CS: ConstraintSystem<F<G1>>>(
    &self,
    cs: &mut CS,
    pc: Option<&AllocatedNum<F<G1>>>,
    z: &[AllocatedNum<F<G1>>],
  ) -> Result<(Option<AllocatedNum<F<G1>>>, Vec<AllocatedNum<F<G1>>>), SynthesisError> {
    trace!("Synthesizing NoirProgram with {} inputs", z.len());
    trace!("Inner pc:  {pc:?}");
    trace!("Circuit index: {}", self.index);
    trace!("ABI parameters: {:?}", self.abi.parameters);
    trace!("ABI return type: {:?}", self.abi.return_type);
    trace!("Private parameters count: {}", self.circuit().private_parameters.len());
    trace!("Public parameters count: {}", self.circuit().public_parameters.0.len());
    trace!("Return values count: {}", self.circuit().return_values.0.len());

    dbg!(&self);

    // Initialize ACVM with the circuit
    let mut acvm = if self.witness.is_some() {
      trace!("Witness is present, initializing ACVM");
      Some(ACVM::new(
        &StubbedBlackBoxSolver(false),
        &self.circuit().opcodes,
        WitnessMap::new(),
        self.unconstrained_functions(),
        &[],
      ))
    } else {
      trace!("No witness provided, skipping ACVM initialization");
      None
    };

    // Create a map to track allocated variables for the cs
    let mut allocated_vars: HashMap<Witness, AllocatedNum<F<G1>>> = HashMap::new();

    // Find the registers parameter in the ABI
    let registers_param = match self.abi.parameters.iter().find(|p| p.name == "registers") {
      Some(param) => {
        trace!("Found registers parameter: {:?}", param);
        param
      },
      None => {
        trace!("ERROR: No 'registers' parameter found in ABI");
        trace!(
          "Available parameters: {:?}",
          self.abi.parameters.iter().map(|p| &p.name).collect::<Vec<_>>()
        );
        panic!("Expected to find 'registers' parameter in ABI");
      },
    };

    // Get the length of registers array
    let registers_length = match &registers_param.typ {
      AbiType::Array { length, .. } => {
        trace!("Registers is an Array type with length {}", length);
        *length
      },
      _ => {
        trace!("ERROR: Unexpected registers type: {:?}", registers_param.typ);
        panic!("Expected 'registers' to be an array type, found {:?}", registers_param.typ);
      },
    };

    trace!("Using registers length: {}", registers_length);

    // Process private inputs first
    trace!("Processing {} private inputs", self.circuit().private_parameters.len());

    // Get only the private parameters from the ABI
    let private_params: Vec<&AbiParameter> =
      self.abi.parameters.iter().filter(|p| p.visibility == AbiVisibility::Private).collect();

    trace!("Found {} private parameters in ABI", private_params.len());

    for (i, witness) in self.circuit().private_parameters.iter().enumerate() {
      let param = if i < private_params.len() {
        private_params[i]
      } else {
        trace!(
          "WARNING: Private parameter index {} exceeds private ABI parameters length {}",
          i,
          private_params.len()
        );
        continue;
      };

      trace!(
        "Processing private input '{}' (witness {:?}) of type {:?}",
        param.name,
        witness,
        param.typ
      );

      let f = self.witness.as_ref().map(|inputs| {
        trace!("Witness map size: {}", inputs.witness.len());
        // TODO: This is a bit hacky. We need to subtract the registers length from the witness
        // index, and this assumes registers is the first parameter.
        let f =
          convert_to_acir_field(inputs.witness[witness.as_usize() - registers_length as usize]);
        trace!("Private input value: {:?}", f);
        acvm.as_mut().unwrap().overwrite_witness(*witness, f);
        f
      });

      let var =
        AllocatedNum::alloc(&mut cs.namespace(|| format!("private_input_{}", param.name)), || {
          let value = convert_to_halo2_field(f.unwrap_or_default());
          trace!("Allocated private input '{}' with value: {:?}", param.name, value);
          Ok(value)
        })?;

      allocated_vars.insert(*witness, var);
      trace!(
        "Added private input witness {:?} to allocated_vars (size now: {})",
        witness,
        allocated_vars.len()
      );
    }

    // Process public inputs (registers) from z
    trace!(
      "Processing {} public inputs (registers) from z (z.len = {})",
      self.circuit().public_parameters.0.len(),
      z.len()
    );

    if z.len() != registers_length as usize {
      trace!(
        "WARNING: z.len() ({}) is not equal to registers_length ({})",
        z.len(),
        registers_length
      );
    }

    for (i, witness) in self.circuit().public_parameters.0.iter().enumerate() {
      if i < registers_length as usize && i < z.len() {
        trace!("Processing public register at index {} (witness {:?})", i, witness);

        let var = z[i].clone();
        let value_str = var.get_value().map_or("None".to_string(), |v| format!("{:?}", v));
        trace!("Public input value from z[{}]: {}", i, value_str);

        if self.witness.is_some() {
          if let Some(value) = var.get_value() {
            trace!("Overwriting public witness {:?} with value from z: {:?}", witness, value);
            acvm.as_mut().unwrap().overwrite_witness(*witness, convert_to_acir_field(value));
          } else {
            trace!("WARNING: No value available for public input at index {}", i);
          }
        }

        allocated_vars.insert(*witness, var);
        trace!(
          "Added public input witness {:?} to allocated_vars (size now: {})",
          witness,
          allocated_vars.len()
        );
      } else if i >= registers_length as usize {
        trace!(
          "Skipping public parameter at index {} as it exceeds registers_length {}",
          i,
          registers_length
        );
      } else {
        trace!("ERROR: Public parameter index {} exceeds z.len() {}", i, z.len());
      }
    }

    // Execute ACVM to get witness values if we have inputs
    let acir_witness_map = if self.witness.is_some() {
      trace!("Executing ACVM solve...");
      let status = acvm.as_mut().unwrap().solve();
      trace!("ACVM solve status: {:?}", status);
      let witness_map = acvm.unwrap().finalize();
      Some(witness_map)
    } else {
      trace!("Skipping ACVM execution (no witness)");
      None
    };

    // Helper function to get witness values
    let get_witness_value = |witness: &Witness| -> F<G1> {
      let result = acir_witness_map.as_ref().map_or(F::<G1>::ONE, |map| {
        map.get(witness).map_or_else(
          || {
            trace!("WARNING: Witness {witness:?} not found in ACVM witness map, using default");
            F::<G1>::ONE
          },
          |value| {
            let converted = convert_to_halo2_field(*value);
            trace!("Got witness {:?} value: {:?}", witness, converted);
            converted
          },
        )
      });
      result
    };

    // Helper to get or create a variable for a witness
    let get_var = |witness: &Witness,
                   allocated_vars: &mut HashMap<Witness, AllocatedNum<F<G1>>>,
                   cs: &mut CS,
                   gate_idx: usize|
     -> Result<Variable, SynthesisError> {
      if let Some(var) = allocated_vars.get(witness) {
        trace!("Using existing variable for witness {:?}", witness);
        Ok(var.get_variable())
      } else {
        trace!("Allocating new variable for witness {:?} in gate {}", witness, gate_idx);
        let var = AllocatedNum::alloc(cs.namespace(|| format!("aux_{gate_idx}")), || {
          let value = get_witness_value(witness);
          trace!("Allocated auxiliary variable with value: {:?}", value);
          Ok(value)
        })?;
        allocated_vars.insert(*witness, var.clone());
        trace!(
          "Added auxiliary witness {:?} to allocated_vars (size now: {})",
          witness,
          allocated_vars.len()
        );
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
          right_terms = right_terms + (F::<G1>::one(), right_var);
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

    // Prepare output values
    trace!("Preparing return values");
    let mut return_values = vec![];
    for (i, ret) in self.circuit().return_values.0.iter().enumerate() {
      trace!("Processing return value {} (witness {:?})", i, ret);
      if let Some(var) = allocated_vars.get(ret) {
        let value_str = var.get_value().map_or("None".to_string(), |v| format!("{:?}", v));
        trace!("Found allocated variable for return value {}: {}", i, value_str);
        return_values.push(var.clone());
      } else {
        trace!("ERROR: Return value {} (witness {:?}) not found in allocated variables", i, ret);
        trace!("Available witnesses: {:?}", allocated_vars.keys().collect::<Vec<_>>());
        return Err(SynthesisError::AssignmentMissing);
      }
    }

    trace!("Return values count: {}", return_values.len());
    trace!("Return values witnesses: {:?}", self.circuit().return_values.0);

    // Check if the return type is a struct as expected
    if let Some(return_type) = &self.abi.return_type {
      if let AbiType::Struct { fields, path } = &return_type.abi_type {
        trace!("Return type is a struct: {} with {} fields", path, fields.len());

        if path != "FoldingIO" {
          panic!("Expected return type to be FoldingIO struct, found {}", path);
        }

        // Find the registers field in the struct and get its length
        let registers_length = fields
          .iter()
          .find(|(name, _)| name == "registers")
          .map(|(_, typ)| match typ {
            AbiType::Array { length, .. } => *length,
            _ => panic!("Expected registers to be an array type, found {:?}", typ),
          })
          .unwrap_or_else(|| panic!("Expected 'registers' field in FoldingIO struct"));

        trace!("registers_length: {}", registers_length);

        // The next_pc is after all the register values
        let next_pc_index = registers_length as usize;
        trace!("next_pc_index in flattened return values: {}", next_pc_index);

        if next_pc_index < return_values.len() {
          let next_pc = Some(return_values[next_pc_index].clone());
          trace!("Using return value at index {} as next_pc", next_pc_index);

          trace!(
            "Synthesis complete, returning next_pc and {} return values",
            return_values[..registers_length as usize].to_vec().len()
          );
          return Ok((next_pc, return_values[..registers_length as usize].to_vec()));
        } else {
          trace!(
            "ERROR: next_pc index {} is out of bounds for return_values length {}",
            next_pc_index,
            return_values.len()
          );
          panic!("next_pc index out of bounds");
        }
      } else {
        trace!("ERROR: Return type is not a struct: {:?}", return_type.abi_type);
        panic!("Expected return type to be a struct, found {:?}", return_type.abi_type);
      }
    } else {
      trace!("ERROR: No return type specified in ABI");
      panic!("Expected return type to be specified");
    }
  }
}

fn convert_to_halo2_field(f: GenericFieldElement<Fr>) -> F<G1> {
  let bytes = f.to_be_bytes();
  let mut arr = [0u8; 32];
  arr.copy_from_slice(&bytes[..32]);
  arr.reverse();
  F::<G1>::from_repr(arr).unwrap()
}

fn convert_to_acir_field(f: F<G1>) -> GenericFieldElement<Fr> {
  let mut bytes = f.to_bytes();
  bytes.reverse();
  GenericFieldElement::from_be_bytes_reduce(&bytes)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_conversions() {
    let f = F::<G1>::from(5);
    let acir_f = convert_to_acir_field(f);
    assert_eq!(acir_f, GenericFieldElement::from_repr(Fr::from(5)));

    let f = GenericFieldElement::from_repr(Fr::from(3));
    let halo2_f = convert_to_halo2_field(f);
    assert_eq!(halo2_f, F::<G1>::from(3));
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
