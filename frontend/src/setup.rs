use std::io::Cursor;

use client_side_prover::{
  fast_serde::{self, FastSerde, SerdeByteError, SerdeByteTypes},
  supernova::{get_circuit_shapes, snark::CompressedSNARK, PublicParams},
  traits::{snark::default_ck_hint, Dual, Engine},
};
use tracing::debug;

use crate::{
  error::FrontendError,
  program::{Memory, Switchboard},
  AuxParams, E1, S1, S2,
};

pub trait Status: private::Sealed {
  type Switchboard;
  type PublicParams;
}

mod private {
  use super::{Empty, Ready};
  pub trait Sealed {}
  impl<M: crate::program::Memory> Sealed for Ready<M> {}
  impl<M: crate::program::Memory> Sealed for Empty<M> {}
}

#[derive(Debug, Clone)]
pub struct Ready<M: Memory> {
  _marker: std::marker::PhantomData<M>,
}

impl<M: Memory> Status for Ready<M> {
  type PublicParams = PublicParams<E1>;
  type Switchboard = Switchboard<M>;
}

#[derive(Debug, Clone)]
pub struct Empty<M: Memory> {
  _marker: std::marker::PhantomData<M>,
}

impl<M: Memory> Status for Empty<M> {
  type PublicParams = AuxParams;
  type Switchboard = ();
}

// TODO: This could probably just store the programs with it
#[derive(Clone, Debug)]
pub struct Setup<S: Status> {
  /// Auxiliary parameters
  pub params:              S::PublicParams,
  /// Primary verification key digest
  pub vk_digest_primary:   <E1 as Engine>::Scalar,
  /// Secondary verification key digest
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,

  pub switchboard: S::Switchboard,
}

#[cfg(test)]
impl<S: Status> PartialEq for Setup<S> {
  fn eq(&self, other: &Self) -> bool {
    self.vk_digest_primary == other.vk_digest_primary
      && self.vk_digest_secondary == other.vk_digest_secondary
  }
}

impl<M: Memory> Setup<Ready<M>> {
  pub fn new(switchboard: Switchboard<M>) -> Self {
    let public_params = PublicParams::setup(&switchboard, &*default_ck_hint(), &*default_ck_hint());
    let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();

    Setup {
      params: public_params,
      vk_digest_primary: pk.pk_primary.vk_digest,
      vk_digest_secondary: pk.pk_secondary.vk_digest,
      switchboard,
    }
  }

  fn into_empty(self) -> Setup<Empty<M>> {
    Setup {
      params:              self.params.into_parts().1,
      vk_digest_primary:   self.vk_digest_primary,
      vk_digest_secondary: self.vk_digest_secondary,
      switchboard:         (),
    }
  }

  pub fn store_file(self, path: &std::path::PathBuf) -> Result<Vec<u8>, FrontendError> {
    let bytes = self.into_empty().to_bytes();
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }

    debug!("using path={:?}", path);
    std::io::Write::write_all(&mut std::fs::File::create(path)?, &bytes)?;

    Ok(bytes)
  }
}

impl<M: Memory> Setup<Empty<M>> {
  pub fn into_ready(self, switchboard: Switchboard<M>) -> Setup<Ready<M>> {
    Setup {
      params: PublicParams::from_parts(get_circuit_shapes(&switchboard), self.params),
      vk_digest_primary: self.vk_digest_primary,
      vk_digest_secondary: self.vk_digest_secondary,
      switchboard,
    }
  }
}
// TODO: We may be able to just use rkyv
impl<M: Memory> FastSerde for Setup<Empty<M>> {
  /// Initialize ProvingParams from an efficiently serializable data format.
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

    Ok(Setup { params, vk_digest_primary, vk_digest_secondary, switchboard: () })
  }

  /// Convert ProvingParams to an efficient serialization.
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
  use crate::{demo::square_zeroth, program::RAM};

  #[test]
  fn test_setup_and_params() {
    let setup = Setup::new(Switchboard::<RAM>::new(vec![square_zeroth()], vec![], 0));
    assert_eq!(setup.params.num_constraints_and_variables(0), (10009, 10001));
  }

  #[test]
  fn test_setup_serialize() {
    let setup = Setup::new(Switchboard::<RAM>::new(vec![square_zeroth()], vec![], 0));
    let empty_setup = setup.into_empty();
    let serialized = empty_setup.to_bytes();
    let deserialized = Setup::<Empty<RAM>>::from_bytes(&serialized).unwrap();
    assert_eq!(empty_setup, deserialized);
  }

  #[test]
  fn test_setup_store_file() {
    let switchboard = Switchboard::<RAM>::new(vec![square_zeroth()], vec![], 0);
    let setup = Setup::new(switchboard.clone());
    let vk_digest_primary = setup.vk_digest_primary;
    let vk_digest_secondary = setup.vk_digest_secondary;
    let path = tempfile::tempdir().unwrap().into_path();
    let bytes = setup.store_file(&path.join("setup.bytes")).unwrap();
    assert!(!bytes.is_empty());
    let stored_bytes = std::fs::read(path.join("setup.bytes")).unwrap();
    let deserialized = Setup::<Empty<RAM>>::from_bytes(&stored_bytes).unwrap();
    let ready_setup = deserialized.into_ready(switchboard);
    assert_eq!(vk_digest_primary, ready_setup.vk_digest_primary);
    assert_eq!(vk_digest_secondary, ready_setup.vk_digest_secondary);
  }
}
