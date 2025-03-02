// TODO: Add back missing docs
// #![warn(missing_docs, clippy::missing_docs_in_private_items)]

//! # Proofs Crate
//!
//! The `proofs` crate provides a comprehensive framework for creating and
//! verifying zero-knowledge proofs. It includes various modules and utilities
//! to facilitate the construction of proofs, circuits, and the necessary
//! cryptographic primitives.
//!
//! ## Modules
//!
//! - `circom`: Contains utilities for working with Circom circuits.
//! - `circuits`: Provides the implementation of various circuits used in the proof system.
//! - `errors`: Defines error types used throughout the crate.
//! - `program`: Contains the core logic for setting up and running the proof system.
//! - `proof`: Provides the implementation of the proof generation and verification.
//! - `setup`: Contains utilities for setting up the proof system.
//! - `tests`: Contains tests for the proof system.
//!
//! ## Types
//!
//! - `E1`: Represents the first elliptic curve engine used in the proof system.
//! - `E2`: Represents the second elliptic curve engine used in the proof system.
//! - `G1`: Represents the group associated with the first elliptic curve engine.
//! - `G2`: Represents the group associated with the second elliptic curve engine.
//! - `EE1`: Represents the evaluation engine for the first elliptic curve.
//! - `EE2`: Represents the evaluation engine for the second elliptic curve.
//! - `S1`: Represents the SNARK for the first elliptic curve.
//! - `S2`: Represents the SNARK for the second elliptic curve.
//! - `F<G>`: Represents the scalar field associated with a given group.
//! - `AuxParams`: Represents the auxiliary parameters needed to create `PublicParams`.
//! - `ProverKey`: Represents the prover key needed to create a `CompressedSNARK`.
//! - `VerifierKey`: Represents the verifier key needed to create a `CompressedSNARK`.

use client_side_prover::{
  provider::GrumpkinEngine,
  spartan::batched::BatchedRelaxedR1CSSNARK,
  supernova::{snark::CompressedSNARK, PublicParams, TrivialCircuit},
  traits::{Engine, Group},
};
use ff::Field;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::error::ProofError;

pub mod error;
pub mod noir;
pub mod program;
pub mod proof;
pub mod setup;

/// Represents the scalar field for the primary curve (bn254)
pub type Scalar = <G1 as Group>::Scalar;

/// Represents the params needed to create `PublicParams` alongside the
/// circuits' R1CSs. Specifically typed to the `proofs` crate choices of curves
/// and engines.
pub type AuxParams = client_side_prover::supernova::AuxParams<E1>;
/// The `ProverKey` needed to create a `CompressedSNARK` using the `proofs`
/// crate choices of curves and engines.
pub type ProverKey = client_side_prover::supernova::snark::ProverKey<E1, S1, S2>;
/// The `VerifierKey` needed to create a `CompressedSNARK` using the `proofs`
/// crate choices of curves and engines.
pub type VerifierKey = client_side_prover::supernova::snark::VerifierKey<E1, S1, S2>;

/// Represents the first elliptic curve engine used in the proof system.
type E1 = client_side_prover::provider::Bn256EngineKZG;
/// Represents the second elliptic curve engine used in the proof system.
type E2 = GrumpkinEngine;
/// Represents the group associated with the first elliptic curve engine.
type G1 = <E1 as Engine>::GE;
/// Represents the evaluation engine for the first elliptic curve.
type EE1 = client_side_prover::provider::hyperkzg::EvaluationEngine<halo2curves::bn256::Bn256, E1>;
/// Represents the evaluation engine for the second elliptic curve.
type EE2 = client_side_prover::provider::ipa_pc::EvaluationEngine<E2>;
/// Represents the SNARK for the first elliptic curve.
type S1 = BatchedRelaxedR1CSSNARK<E1, EE1>;
/// Represents the SNARK for the second elliptic curve.
type S2 = BatchedRelaxedR1CSSNARK<E2, EE2>;

#[cfg(any(test, feature = "demo"))]
pub mod demo {
  use crate::noir::NoirProgram;

  pub fn add_external() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/add_external.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  pub fn square_zeroth() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/square_zeroth.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }

  pub fn swap_memory() -> NoirProgram {
    let bytecode =
      std::fs::read("../target/swap_memory.json").expect("Failed to read Noir program file");
    NoirProgram::new(&bytecode)
  }
}
