#![warn(missing_docs, clippy::missing_docs_in_private_items)]

//! # NIVC Folding for Noir Circuits
//!
//! This crate provides an frontend implementation to use Non-uniform Incrementally Verifiable
//! Computation (NIVC) folding for Noir circuits. NIVC allows for incremental verification of
//! computations across different circuit types, enabling complex proof systems that can switch
//! between different circuit implementations during execution.
//!
//! ## Key Components
//!
//! - **Noir Programs**: Representation and handling of Noir language programs
//! - **Switchboard**: Manages the flow between different circuit implementations
//! - **Setup**: Handles parameter generation and initialization for the proof system
//! - **Proof Generation**: Creation and verification of folding proofs
//!
//! ## Cryptographic Backends
//!
//! The crate uses several cryptographic backends:
//! - Primary curve: bn254 (also known as BN256)
//! - Secondary curve: Grumpkin
//! - Proof systems: SuperNova, Spartan R1CS SNARKs
//!
//! ## Memory Models
//!
//! The crate supports two memory models:
//! - **ROM (Read-Only Memory)**: All computation steps are known in advance
//! - **RAM (Random Access Memory)**: Computation steps are determined dynamically
//!
//! ## Example Usage
//!
//! The crate provides demo implementations accessible via the `demo` module when
//! built with the `demo` feature.

use client_side_prover::{
  provider::GrumpkinEngine,
  spartan::batched::BatchedRelaxedR1CSSNARK,
  supernova::TrivialCircuit,
  traits::{Engine, Group},
};
use halo2curves::ff::Field;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::error::FrontendError;

pub mod error;
pub mod noir;
pub mod program;
pub mod setup;

/// Represents the scalar field for the primary curve (bn254)
///
/// This type is used for representing field elements in the scalar field
/// of the primary elliptic curve used in the proof system.
pub type Scalar = <G1 as Group>::Scalar;

/// Represents the params needed to create `PublicParams` alongside the
/// circuits' R1CSs.
///
/// These auxiliary parameters contain the cryptographic context needed for
/// setting up the proof system.
pub type AuxParams = client_side_prover::supernova::AuxParams<E1>;
/// The `ProverKey` needed to create a `CompressedSNARK`.
///
/// This key is used by the prover to generate cryptographic proofs.
pub type ProverKey = client_side_prover::supernova::snark::ProverKey<E1, S1, S2>;
/// The `VerifierKey` needed to create a `CompressedSNARK`.
///
/// This key is used by the verifier to validate cryptographic proofs.  
pub type VerifierKey = client_side_prover::supernova::snark::VerifierKey<E1, S1, S2>;

/// Represents the `CompressedSNARK` which is a succinct proof of a `RecursiveSNARK`.
pub type CompressedSNARK = client_side_prover::supernova::snark::CompressedSNARK<E1, S1, S2>;

/// Represents the first elliptic curve engine used in the proof system.
///
/// The primary engine uses BN256 with KZG polynomial commitments.
type E1 = client_side_prover::provider::Bn256EngineKZG;
/// Represents the second elliptic curve engine used in the proof system.
///
/// The secondary engine uses the Grumpkin curve, which is cycle-friendly with BN256.
type E2 = GrumpkinEngine;
/// Represents the group associated with the first elliptic curve engine.
///
/// This group is used for cryptographic operations in the primary curve.
type G1 = <E1 as Engine>::GE;
/// Represents the evaluation engine for the first elliptic curve.
///
/// This evaluation engine handles polynomial evaluations for the primary curve.
type EE1 = client_side_prover::provider::hyperkzg::EvaluationEngine<halo2curves::bn256::Bn256, E1>;
/// Represents the evaluation engine for the second elliptic curve.
///
/// This evaluation engine handles polynomial evaluations for the secondary curve.
type EE2 = client_side_prover::provider::ipa_pc::EvaluationEngine<E2>;
/// Represents the SNARK for the first elliptic curve.
///
/// This SNARK implementation is used for generating proofs on the primary curve.
type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
/// Represents the SNARK for the second elliptic curve.
///
/// This SNARK implementation is used for generating proofs on the secondary curve.
type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

#[cfg(any(test, feature = "demo"))]
/// Demo module providing example Noir programs for testing and demonstration
///
/// This module is only available when the crate is built with the `demo` feature
/// or in test mode. It is also used to test the crate's functionality.
pub mod demo {
  use crate::noir::NoirProgram;

  /// Creates a basic Noir program example
  ///
  /// Loads a compiled Noir program that performs simple operations that comprise a single ACIR
  /// gate.
  pub fn basic() -> NoirProgram {
    let bytecode = std::fs::read("../target/basic.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  /// Loads a compiled Noir program that demonstrates adding external private values to the running
  /// state.
  pub fn add_external() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/add_external.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  /// Creates a Noir program that squares the zeroth element of its input
  pub fn square_zeroth() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/square_zeroth.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  /// Creates a Noir program that demonstrates memory swapping between the running state and the
  /// folding memory.
  pub fn swap_memory() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/swap_memory.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  /// Creates a Noir program implementing the Poseidon hash function on the running state.
  pub fn poseidon() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/poseidon.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  /// Creates a Noir program that is the even case of the function in the Collatz conjecture.
  pub fn collatz_even() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/collatz_even.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  /// Creates a Noir program that is the odd case of the function in the Collatz conjecture.
  pub fn collatz_odd() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/collatz_odd.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }
}
