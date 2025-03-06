//! # Proof Module
//!
//! This module provides the implementation for generating and verifying proofs.
//! It includes functionalities for serializing and deserializing folding proofs,
//! which are used in the proof system to ensure the integrity and correctness of computations.
//!
//! ## Structs
//!
//! - `FoldingProof<T, V>`: Represents a folding proof with a generic proof type `T` and verifier
//!   digest type `V`.
//!
//! ## Functions
//!
//! - `serialize`: Serializes a `FoldingProof` into a format suitable for storage or transmission.
//! - `deserialize`: Deserializes a `FoldingProof` from a stored or transmitted format back into its
//!   original form.

use hex;

use super::*;
use crate::program::CompressedProof;

/// Represents a folding proof with associated verifier digest
///
/// A folding proof contains the actual cryptographic proof data along with
/// the verifier digest needed for verification. This is a generic structure
/// that can work with different proof and digest formats.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FoldingProof<T, V> {
  /// The cryptographic proof data
  pub proof:           T,
  /// Digest used by the verifier to check the proof's validity
  pub verifier_digest: V,
}

impl CompressedProof {
  /// Serializes a `CompressedProof` into a format suitable for storage or transmission.
  ///
  /// Converts the internal proof representation to a binary format and
  /// encodes the verifier digest as a hexadecimal string.
  ///
  /// # Returns
  ///
  /// A `FoldingProof` with a `Vec<u8>` proof and a `String` verifier digest.
  ///
  /// # Errors
  ///
  /// Returns a `FrontendError` if serialization fails.
  pub fn serialize(self) -> Result<FoldingProof<Vec<u8>, String>, FrontendError> {
    let proof = bincode::serialize(&self.proof)?;

    Ok(FoldingProof { proof, verifier_digest: hex::encode(self.verifier_digest.to_bytes()) })
  }
}

impl FoldingProof<Vec<u8>, String> {
  /// Deserializes a `FoldingProof` from a stored or transmitted format back into its original form.
  ///
  /// Converts the binary proof data back into a `CompressedSNARK` instance and
  /// decodes the verifier digest from hexadecimal to its field element representation.
  ///
  /// # Returns
  ///
  /// A `CompressedProof` with a `CompressedSNARK<E1, S1, S2>` proof and a `Scalar` verifier digest.
  ///
  /// # Errors
  ///
  /// Returns a `FrontendError` if deserialization fails or if the hex string cannot be converted
  /// to the expected field element.
  pub fn deserialize(self) -> Result<CompressedProof, FrontendError> {
    let proof = bincode::deserialize(&self.proof[..])?;

    // Decode the hex string to bytes
    let digest_bytes = hex::decode(&self.verifier_digest)?;

    // Convert to fixed-size array safely
    let digest_array: [u8; 32] = digest_bytes
      .try_into()
      .map_err(|_| FrontendError::Other("Invalid digest length".to_string()))?;

    // Convert to Scalar, handling the case where from_bytes returns CtOption
    let verifier_digest = Scalar::from_bytes(&digest_array)
      .into_option()
      .ok_or_else(|| FrontendError::Other("Invalid scalar encoding".to_string()))?;

    Ok(FoldingProof { proof, verifier_digest })
  }
}
