//! # Setup and Parameter Management
//!
//! This module handles the setup and parameter management for the NIVC system.
//! It provides functionality for:
//!
//! - Creating and managing cryptographic parameters
//! - Storing and loading setup data
//! - Converting between different setup states
//!
//! ## Setup States
//!
//! The setup can be in one of two states:
//! - **Offline**: Contains only auxiliary parameters without a switchboard (can be serialized for
//!   storage)
//! - **Ready**: Complete setup with a switchboard that's ready for program execution
//!
//! ## Storage
//!
//! Setup parameters can be serialized and stored to disk, then later deserialized and
//! combined with a switchboard to create a ready setup.

use std::io::Cursor;

use edge_prover::{
  fast_serde::{self, FastSerde, SerdeByteError, SerdeByteTypes},
  supernova::{get_circuit_shapes, snark::CompressedSNARK, PublicParams},
  traits::{snark::default_ck_hint, Dual, Engine},
};
use tracing::debug;

use super::*;
use crate::program::{Memory, Switchboard};

/// Trait that defines the status of a setup
///
/// This sealed trait can only be implemented by the predefined status types:
/// - `Ready<M>`: A setup that is ready for execution with a specific memory model
/// - `Offline<M>`: A setup that only contains cryptographic parameters without a switchboard
pub trait Status: private::Sealed {
  /// The switchboard type associated with this status
  type Switchboard;

  /// The public parameters type associated with this status
  type PublicParams;
}

/// Private module for sealing the Status trait
mod private {
  use super::{Offline, Ready};

  /// Sealed trait implementation to restrict Status implementations
  pub trait Sealed {}
  impl<M: crate::program::Memory> Sealed for Ready<M> {}
  impl Sealed for Offline {}
}

/// Represents a setup that is ready for execution with a specific memory model
///
/// A `Ready` setup contains both the cryptographic parameters and a switchboard,
/// making it ready to execute programs.
#[derive(Debug, Clone)]
pub struct Ready<M: Memory> {
  /// Marker for the memory model type
  _marker: std::marker::PhantomData<M>,
}

impl<M: Memory> Status for Ready<M> {
  /// A ready setup uses a switchboard with the specified memory model
  type PublicParams = PublicParams<E1>;
  /// A ready setup has a specific switchboard associated with it
  type Switchboard = Switchboard<M>;
}

/// Represents a setup that only contains cryptographic parameters without a switchboard
///
/// An `Offline` setup can be serialized and stored, making it useful for saving
/// computationally expensive cryptographic parameters.
#[derive(Debug, Clone)]
pub struct Offline;

impl Status for Offline {
  /// An offline setup only contains auxiliary parameters
  type PublicParams = AuxParams;
  /// An offline setup doesn't have a switchboard
  type Switchboard = ();
}

/// Setup parameters for NIVC computation
///
/// This structure holds the cryptographic parameters, verification key digests,
/// and optionally a switchboard depending on its status.
#[derive(Clone, Debug)]
pub struct Setup<S: Status> {
  /// Cryptographic parameters (type depends on the status)
  pub params: S::PublicParams,

  /// Primary verification key digest
  pub vk_digest_primary: <E1 as Engine>::Scalar,

  /// Secondary verification key digest
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,

  /// Switchboard (if the setup is [`Ready`]) or unit (if [`Offline`])
  pub switchboard: S::Switchboard,
}

#[cfg(test)]
impl<S: Status> PartialEq for Setup<S> {
  fn eq(&self, other: &Self) -> bool {
    self.vk_digest_primary == other.vk_digest_primary
      && self.vk_digest_secondary == other.vk_digest_secondary
  }
}

// TODO: Possibly have a `get_vk` method that returns the verification key for the given setup

impl<M: Memory> Setup<Ready<M>> {
  /// Creates a new ready setup with the given switchboard
  ///
  /// This initializes the cryptographic parameters based on the circuits in the switchboard
  /// and generates the verification key digests.
  ///
  /// # Arguments
  ///
  /// * `switchboard` - The switchboard containing the circuits to be executed
  ///
  /// # Returns
  ///
  /// A new ready setup that can be used to execute programs
  pub fn new(switchboard: Switchboard<M>) -> Result<Self, FrontendError> {
    let public_params = PublicParams::setup(&switchboard, &*default_ck_hint(), &*default_ck_hint());
    let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params)?;

    Ok(Self {
      params: public_params,
      vk_digest_primary: pk.pk_primary.vk_digest,
      vk_digest_secondary: pk.pk_secondary.vk_digest,
      switchboard,
    })
  }

  /// Converts a ready setup to an offline setup
  ///
  /// This extracts the auxiliary parameters from the public parameters and
  /// creates an offline setup without the switchboard, which can be serialized.
  ///
  /// # Returns
  ///
  /// An offline setup containing only the auxiliary parameters
  fn into_offline(self) -> Setup<Offline> {
    Setup {
      params:              self.params.into_parts().1,
      vk_digest_primary:   self.vk_digest_primary,
      vk_digest_secondary: self.vk_digest_secondary,
      switchboard:         (),
    }
  }

  /// Serializes the setup and stores it to a file
  ///
  /// This converts the setup to an offline setup, serializes it, and writes
  /// the resulting bytes to the specified file path.
  ///
  /// # Arguments
  ///
  /// * `path` - The file path where the setup should be stored
  ///
  /// # Returns
  ///
  /// The serialized bytes on success, or a `FrontendError` on failure
  pub fn store_file(self, path: &std::path::PathBuf) -> Result<Vec<u8>, FrontendError> {
    let bytes = self.into_offline().to_bytes();
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }

    debug!("using path={:?}", path);
    std::io::Write::write_all(&mut std::fs::File::create(path)?, &bytes)?;

    Ok(bytes)
  }

  /// Returns the verifier key for the setup
  ///
  /// This method generates the verifier key for the setup using the public parameters.
  ///
  /// # Returns
  ///
  /// The verifier key for the setup
  pub fn verifier_key(&self) -> Result<VerifierKey, FrontendError> {
    let (_, vk) = CompressedSNARK::setup(&self.params)?;
    Ok(vk)
  }
}

impl Setup<Offline> {
  /// Converts an offline setup to a ready setup
  ///
  /// This combines the auxiliary parameters with a switchboard to create
  /// a ready setup that can be used to execute programs.
  ///
  /// # Arguments
  ///
  /// * `switchboard` - The switchboard to be used for execution
  ///
  /// # Returns
  ///
  /// A ready setup containing the parameters and switchboard
  pub fn into_ready<M: Memory>(self, switchboard: Switchboard<M>) -> Setup<Ready<M>> {
    Setup {
      params: PublicParams::from_parts(get_circuit_shapes(&switchboard), self.params),
      vk_digest_primary: self.vk_digest_primary,
      vk_digest_secondary: self.vk_digest_secondary,
      switchboard,
    }
  }

  /// Deserializes a setup from a file
  ///
  /// # Arguments
  ///
  /// * `path` - The file path where the setup should be stored
  ///
  /// # Returns
  ///
  /// The deserialized setup, or a [`FrontendError`] on failure
  pub fn load_file(path: &std::path::PathBuf) -> Result<Self, FrontendError> {
    let bytes = std::fs::read(path)?;
    Ok(Self::from_bytes(&bytes)?)
  }
}

// TODO: We should consider using `rkyv` for serialization and deserialization
impl FastSerde for Setup<Offline> {
  /// Deserializes a setup from bytes
  ///
  /// # Arguments
  ///
  /// * `bytes` - The serialized setup data
  ///
  /// # Returns
  ///
  /// The deserialized offline setup, or a `SerdeByteError` on failure
  fn from_bytes(bytes: &[u8]) -> Result<Self, SerdeByteError> {
    let mut cursor = Cursor::new(bytes);
    Self::validate_header(&mut cursor, SerdeByteTypes::ProverParams, 3)?;

    let params =
      Self::read_section_bytes(&mut cursor, 1).map(|bytes| AuxParams::from_bytes(&bytes))??;

    let vk_digest_primary = Self::read_section_bytes(&mut cursor, 2)
      .and_then(|bytes| bytes.try_into().map_err(|_| SerdeByteError::G1DecodeError))
      .map(|bytes| <E1 as Engine>::Scalar::from_bytes(&bytes))?
      .into_option()
      .ok_or(SerdeByteError::G1DecodeError)?;

    let vk_digest_secondary = Self::read_section_bytes(&mut cursor, 3)
      .and_then(|bytes| bytes.try_into().map_err(|_| SerdeByteError::G2DecodeError))
      .map(|bytes| <Dual<E1> as Engine>::Scalar::from_bytes(&bytes))?
      .into_option()
      .ok_or(SerdeByteError::G1DecodeError)?;

    Ok(Self { params, vk_digest_primary, vk_digest_secondary, switchboard: () })
  }

  /// Serializes a setup to bytes
  ///
  /// # Returns
  ///
  /// The serialized setup data
  fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&fast_serde::MAGIC_NUMBER);
    out.push(SerdeByteTypes::ProverParams as u8);
    out.push(3); // num_sections

    Self::write_section_bytes(&mut out, 1, &self.params.to_bytes());
    Self::write_section_bytes(&mut out, 2, &self.vk_digest_primary.to_bytes());
    Self::write_section_bytes(&mut out, 3, &self.vk_digest_secondary.to_bytes());

    out
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{demo::square_zeroth, program::Configuration};

  #[test]
  fn test_setup_and_params() {
    let setup = Setup::new(Switchboard::<Configuration>::new(vec![square_zeroth()])).unwrap();
    assert_eq!(setup.params.num_constraints_and_variables(0), (10009, 10001));
  }

  #[test]
  fn test_setup_serialize() {
    let setup = Setup::new(Switchboard::<Configuration>::new(vec![square_zeroth()])).unwrap();
    let offline_setup = setup.into_offline();
    let serialized = offline_setup.to_bytes();
    let deserialized = Setup::<Offline>::from_bytes(&serialized).unwrap();
    assert_eq!(offline_setup, deserialized);
  }

  #[test]
  fn test_setup_store_file() {
    let switchboard = Switchboard::<Configuration>::new(vec![square_zeroth()]);
    let setup = Setup::new(switchboard.clone()).unwrap();
    let vk_digest_primary = setup.vk_digest_primary;
    let vk_digest_secondary = setup.vk_digest_secondary;
    let path = tempfile::tempdir().unwrap().into_path();
    let _bytes = setup.store_file(&path.join("setup.bytes")).unwrap();
    let stored_bytes = std::fs::read(path.join("setup.bytes")).unwrap();
    let deserialized = Setup::<Offline>::from_bytes(&stored_bytes).unwrap();
    let ready_setup = deserialized.into_ready(switchboard);
    assert_eq!(vk_digest_primary, ready_setup.vk_digest_primary);
    assert_eq!(vk_digest_secondary, ready_setup.vk_digest_secondary);
  }
}
