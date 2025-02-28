//! This module implements Nova's traits using the following several different
//! combinations

// public modules to be used as an evaluation engine with Spartan
pub mod hyperkzg;
pub mod ipa_pc;

// crate-public modules, made crate-public mostly for tests
pub(crate) mod bn256_grumpkin;
mod pedersen;
pub(crate) mod poseidon;
pub(crate) mod traits;
// a non-hiding variant of kzg
mod kzg_commitment;
pub(crate) mod util;

// crate-private modules
mod keccak;
mod tests;

use halo2curves::bn256::Bn256;

use self::kzg_commitment::KZGCommitmentEngine;
use crate::{
  provider::{
    bn256_grumpkin::{bn256, grumpkin},
    keccak::Keccak256Transcript,
    pedersen::CommitmentEngine as PedersenCommitmentEngine,
    poseidon::{PoseidonRO, PoseidonROCircuit},
  },
  traits::{CurveCycleEquipped, Engine},
};

/// An implementation of the Nova `Engine` trait with Grumpkin curve and
/// Pedersen commitment scheme
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrumpkinEngine;

/// An implementation of the Nova `Engine` trait with BN254 curve and Pedersen
/// commitment scheme
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bn256EngineIPA;

impl Engine for Bn256EngineIPA {
  type Base = bn256::Base;
  type CE = PedersenCommitmentEngine<Self>;
  type GE = bn256::Point;
  type RO = PoseidonRO<Self::Base, Self::Scalar>;
  type ROCircuit = PoseidonROCircuit<Self::Base>;
  type Scalar = bn256::Scalar;
  type TE = Keccak256Transcript<Self>;
}

impl Engine for GrumpkinEngine {
  type Base = grumpkin::Base;
  type CE = PedersenCommitmentEngine<Self>;
  type GE = grumpkin::Point;
  type RO = PoseidonRO<Self::Base, Self::Scalar>;
  type ROCircuit = PoseidonROCircuit<Self::Base>;
  type Scalar = grumpkin::Scalar;
  type TE = Keccak256Transcript<Self>;
}

/// An implementation of the Nova `Engine` trait with BN254 curve and Zeromorph
/// commitment scheme
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bn256EngineZM;

impl Engine for Bn256EngineZM {
  type Base = bn256::Base;
  type CE = KZGCommitmentEngine<Bn256>;
  type GE = bn256::Point;
  type RO = PoseidonRO<Self::Base, Self::Scalar>;
  type ROCircuit = PoseidonROCircuit<Self::Base>;
  type Scalar = bn256::Scalar;
  type TE = Keccak256Transcript<Self>;
}
/// An implementation of Nova traits with HyperKZG over the BN256 curve
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bn256EngineKZG;

impl Engine for Bn256EngineKZG {
  type Base = bn256::Base;
  type CE = KZGCommitmentEngine<Bn256>;
  type GE = bn256::Point;
  type RO = PoseidonRO<Self::Base, Self::Scalar>;
  type ROCircuit = PoseidonROCircuit<Self::Base>;
  type Scalar = bn256::Scalar;
  type TE = Keccak256Transcript<Self>;
}

impl CurveCycleEquipped for Bn256EngineIPA {
  type Secondary = GrumpkinEngine;
}

impl CurveCycleEquipped for Bn256EngineKZG {
  type Secondary = GrumpkinEngine;
}

impl CurveCycleEquipped for Bn256EngineZM {
  type Secondary = GrumpkinEngine;
}

#[cfg(test)]
mod test {
  use std::io::Read;

  use digest::{ExtendableOutput, Update};
  use group::{ff::Field, Curve, Group};
  use halo2curves::{CurveAffine, CurveExt};
  use itertools::Itertools as _;
  use rand_core::OsRng;
  use sha3::Shake256;

  use crate::provider::{
    bn256_grumpkin::{bn256, grumpkin},
    traits::DlogGroup,
    util::msm::cpu_best_msm,
  };

  macro_rules! impl_cycle_pair_test {
    ($curve:ident) => {
      fn from_label_serial(label: &'static [u8], n: usize) -> Vec<$curve::Affine> {
        let mut shake = Shake256::default();
        shake.update(label);
        let mut reader = shake.finalize_xof();
        (0..n)
          .map(|_| {
            let mut uniform_bytes = [0u8; 32];
            reader.read_exact(&mut uniform_bytes).unwrap();
            let hash = $curve::Point::hash_to_curve("from_uniform_bytes");
            hash(&uniform_bytes).to_affine()
          })
          .collect()
      }

      let label = b"test_from_label";
      for n in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 1021] {
        let ck_par = <$curve::Point as DlogGroup>::from_label(label, n);
        let ck_ser = from_label_serial(label, n);
        assert_eq!(ck_par.len(), n);
        assert_eq!(ck_ser.len(), n);
        assert_eq!(ck_par, ck_ser);
      }
    };
  }

  fn test_msm_with<F: Field, A: CurveAffine<ScalarExt = F>>() {
    let n = 8;
    let coeffs = (0..n).map(|_| F::random(OsRng)).collect::<Vec<_>>();
    let bases = (0..n).map(|_| A::from(A::generator() * F::random(OsRng))).collect::<Vec<_>>();
    let naive = coeffs
      .iter()
      .zip_eq(bases.iter())
      .fold(A::CurveExt::identity(), |acc, (coeff, base)| acc + *base * coeff);

    assert_eq!(naive, cpu_best_msm(&bases, &coeffs))
  }

  #[test]
  fn test_msm() {
    test_msm_with::<bn256::Scalar, bn256::Affine>();
    test_msm_with::<grumpkin::Scalar, grumpkin::Affine>();
  }

  #[test]
  fn test_bn256_from_label() {
    impl_cycle_pair_test!(bn256);
  }
}
