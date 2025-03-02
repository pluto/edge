use std::io::Cursor;

use client_side_prover::{
  fast_serde::{self, FastSerde, SerdeByteError, SerdeByteTypes},
  supernova::{get_circuit_shapes, snark::CompressedSNARK, PublicParams},
  traits::{snark::default_ck_hint, Dual, Engine},
};

use crate::{error::ProofError, noir::NoirProgram, program, AuxParams, ProverKey, E1, S1, S2};

// TODO: This could probably just store the programs with it
#[derive(Clone, Debug)]
pub struct Setup {
  /// Auxiliary parameters
  pub aux_params:          AuxParams,
  /// Primary verification key digest
  pub vk_digest_primary:   <E1 as Engine>::Scalar,
  /// Secondary verification key digest
  pub vk_digest_secondary: <Dual<E1> as Engine>::Scalar,
}

impl Setup {
  pub fn new(programs: &[NoirProgram]) -> Self {
    let switchboard = program::Switchboard::new(programs.to_vec(), vec![], vec![], 0);
    let public_params = PublicParams::setup(&switchboard, &*default_ck_hint(), &*default_ck_hint());
    let (pk, _vk) = CompressedSNARK::<E1, S1, S2>::setup(&public_params).unwrap();
    let (_, aux_params) = public_params.into_parts();

    Setup {
      aux_params,
      vk_digest_primary: pk.pk_primary.vk_digest,
      vk_digest_secondary: pk.pk_secondary.vk_digest,
    }
  }

  pub fn into_public_params(self, programs: &[NoirProgram]) -> PublicParams<E1> {
    let switchboard = program::Switchboard::new(programs.to_vec(), vec![], vec![], 0);
    // TODO: This can print out the constraints and variables for each circuit
    PublicParams::from_parts(get_circuit_shapes(&switchboard), self.aux_params)
  }
}

// TODO: We may be able to just use rkyv
impl FastSerde for Setup {
  /// Initialize ProvingParams from an efficiently serializable data format.
  fn from_bytes(bytes: &[u8]) -> Result<Self, SerdeByteError> {
    let mut cursor = Cursor::new(bytes);
    Self::validate_header(&mut cursor, SerdeByteTypes::ProverParams, 3)?;

    let aux_params =
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

    Ok(Setup { aux_params, vk_digest_primary, vk_digest_secondary })
  }

  /// Convert ProvingParams to an efficient serialization.
  fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&fast_serde::MAGIC_NUMBER);
    out.push(SerdeByteTypes::ProverParams as u8);
    out.push(3); // num_sections

    Self::write_section_bytes(&mut out, 1, &self.aux_params.to_bytes());
    Self::write_section_bytes(&mut out, 2, &self.vk_digest_primary.to_bytes());
    Self::write_section_bytes(&mut out, 3, &self.vk_digest_secondary.to_bytes());

    out
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::demo::square_zeroth;

  #[test]
  fn test_setup() {
    let setup = Setup::new(&[square_zeroth()]);
    todo!("Actually do something here. ");
  }
}
