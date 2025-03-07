//! # Error Handling
//!
//! This module defines the error types used throughout the crate.
//! `FrontendError` is the primary error type that encapsulates various
//! lower-level errors that might occur during proof generation, verification,
//! and other operations.

use thiserror::Error;

/// Represents errors that can occur in the frontend operations of the NIVC system.
///
/// This enum encapsulates various error types from dependent libraries as well as
/// custom error conditions specific to this crate.
#[derive(Debug, Error)]
pub enum FrontendError {
  /// The error is a `bellpepper_core::SynthesisError`
  #[error(transparent)]
  Synthesis(#[from] bellpepper_core::SynthesisError),

  /// The error is a `std::io::Error`
  #[error(transparent)]
  Io(#[from] std::io::Error),

  /// The error is a `edge_prover::errors::NovaError`
  #[error(transparent)]
  Nova(#[from] edge_prover::errors::NovaError),

  /// The error is a `edge_prover::supernova::error::SuperNovaError`
  #[error(transparent)]
  SuperNova(#[from] edge_prover::supernova::error::SuperNovaError),

  /// The error is a [`edge_prover::fast_serde::SerdeByteError`]
  #[error(transparent)]
  FastSerde(#[from] edge_prover::fast_serde::SerdeByteError),
}
