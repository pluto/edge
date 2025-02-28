//! Commitment engine for KZG commitments

use std::{io::Cursor, marker::PhantomData, sync::Arc};

use ff::{Field, PrimeField, PrimeFieldBits};
use group::{prime::PrimeCurveAffine, Curve, Group as _};
use halo2curves::serde::SerdeObject;
use pairing::Engine;
use rand::rngs::StdRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::{
  digest::SimpleDigestible,
  fast_serde,
  fast_serde::{FastSerde, SerdeByteError, SerdeByteTypes},
  provider::{pedersen::Commitment, traits::DlogGroup, util::fb_msm},
  traits::{
    commitment::{CommitmentEngineTrait, Len},
    Engine as NovaEngine, Group, TranscriptReprTrait,
  },
};

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
#[serde(bound(
  serialize = "E::G1Affine: Serialize, E::G2Affine: Serialize",
  deserialize = "E::G1Affine: Deserialize<'de>, E::G2Affine: Deserialize<'de>"
))]
pub struct UniversalKZGParam<E: Engine> {
  /// Group elements of the form `{ β^i G }`, where `i` ranges from 0 to
  /// `degree`.
  pub powers_of_g: Vec<E::G1Affine>,
  /// Group elements of the form `{ β^i H }`, where `i` ranges from 0 to
  /// `degree`.
  pub powers_of_h: Vec<E::G2Affine>,
}

impl<E: Engine> PartialEq for UniversalKZGParam<E> {
  fn eq(&self, other: &Self) -> bool {
    self.powers_of_g == other.powers_of_g && self.powers_of_h == other.powers_of_h
  }
}
// for the purpose of the Len trait, we count commitment bases, i.e. G1 elements
impl<E: Engine> Len for UniversalKZGParam<E> {
  fn length(&self) -> usize { self.powers_of_g.len() }
}

/// `UnivariateProverKey` is used to generate a proof
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(
  serialize = "E::G1Affine: Serialize, E::G2Affine: Serialize",
  deserialize = "E::G1Affine: Deserialize<'de>, E::G2Affine: Deserialize<'de>"
))]
pub struct KZGProverKey<E: Engine> {
  /// generators from the universal parameters
  uv_params:      Arc<UniversalKZGParam<E>>,
  /// offset at which we start reading into the SRS
  offset:         usize,
  /// maximum supported size
  supported_size: usize,
}

impl<E: Engine> KZGProverKey<E> {
  pub(in crate::provider) fn new(
    uv_params: Arc<UniversalKZGParam<E>>,
    offset: usize,
    supported_size: usize,
  ) -> Self {
    assert!(
      uv_params.max_degree() >= offset + supported_size,
      "not enough bases (req: {} from offset {}) in the UVKZGParams (length: {})",
      supported_size,
      offset,
      uv_params.max_degree()
    );
    Self { uv_params, offset, supported_size }
  }

  pub fn powers_of_g(&self) -> &[E::G1Affine] {
    &self.uv_params.powers_of_g[self.offset..self.offset + self.supported_size]
  }
}

/// `UVKZGVerifierKey` is used to check evaluation proofs for a given
/// commitment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize = "E::G1Affine: Serialize, E::G2Affine: Serialize",))]
pub struct KZGVerifierKey<E: Engine> {
  /// The generator of G1.
  pub g:      E::G1Affine,
  /// The generator of G2.
  pub h:      E::G2Affine,
  /// β times the above generator of G2.
  pub beta_h: E::G2Affine,
}

impl<E: Engine> SimpleDigestible for KZGVerifierKey<E>
where
  E::G1Affine: Serialize,
  E::G2Affine: Serialize,
{
}

impl<E: Engine> UniversalKZGParam<E> {
  /// Returns the maximum supported degree
  pub fn max_degree(&self) -> usize { self.powers_of_g.len() }

  /// Trim the universal parameters to specialize the public parameters
  /// for univariate polynomials to the given `supported_size`, and
  /// returns prover key and verifier key. `supported_size` should
  /// be in range `1..params.len()`
  ///
  /// # Panics
  /// If `supported_size` is greater than `self.max_degree()`, or
  /// `self.max_degree()` is zero.
  pub fn trim(ukzg: Arc<Self>, supported_size: usize) -> (KZGProverKey<E>, KZGVerifierKey<E>) {
    assert!(ukzg.max_degree() > 0, "max_degree is zero");
    let g = ukzg.powers_of_g[0];
    let h = ukzg.powers_of_h[0];
    let beta_h = ukzg.powers_of_h[1];
    let pk = KZGProverKey::new(ukzg, 0, supported_size + 1);
    let vk = KZGVerifierKey { g, h, beta_h };
    (pk, vk)
  }
}

impl<E: Engine> FastSerde for UniversalKZGParam<E>
where
  E::G1Affine: SerdeObject,
  E::G2Affine: SerdeObject,
{
  /// Byte format:
  ///
  /// [0..4]   - Magic number (4 bytes)
  /// [4]      - Serde type: UniversalKZGParam (u8)
  /// [5]      - Number of sections (u8 = 2)
  /// [6]      - Section 1 type: powers_of_g (u8)
  /// [7..11]  - Section 1 size (u32)
  /// [11..]   - Section 1 data
  /// [...+1]  - Section 2 type: powers_of_h (u8)
  /// [...+5]  - Section 2 size (u32)
  /// [...end] - Section 2 data
  fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&fast_serde::MAGIC_NUMBER);
    out.push(fast_serde::SerdeByteTypes::UniversalKZGParam as u8);
    out.push(2); // num_sections

    Self::write_section_bytes(
      &mut out,
      1,
      &self.powers_of_g.iter().flat_map(|p| p.to_raw_bytes()).collect::<Vec<u8>>(),
    );

    Self::write_section_bytes(
      &mut out,
      2,
      &self.powers_of_h.iter().flat_map(|p| p.to_raw_bytes()).collect::<Vec<u8>>(),
    );

    out
  }

  fn from_bytes(bytes: &[u8]) -> Result<Self, SerdeByteError> {
    let mut cursor = Cursor::new(bytes);

    Self::validate_header(&mut cursor, SerdeByteTypes::UniversalKZGParam, 2)?;

    // Read sections of points
    let powers_of_g = Self::read_section_bytes(&mut cursor, 1)?
      .chunks(E::G1Affine::identity().to_raw_bytes().len())
      .map(|bytes| E::G1Affine::from_raw_bytes(bytes).ok_or(SerdeByteError::G1DecodeError))
      .collect::<Result<Vec<_>, _>>()?;

    let powers_of_h = Self::read_section_bytes(&mut cursor, 2)?
      .chunks(E::G2Affine::identity().to_raw_bytes().len())
      .map(|bytes| E::G2Affine::from_raw_bytes(bytes).ok_or(SerdeByteError::G2DecodeError))
      .collect::<Result<Vec<_>, _>>()?;

    Ok(Self { powers_of_g, powers_of_h })
  }
}

impl<E: Engine> UniversalKZGParam<E>
where E::Fr: PrimeFieldBits
{
  /// Build SRS for testing.
  /// WARNING: THIS FUNCTION IS FOR TESTING PURPOSE ONLY.
  /// THE OUTPUT SRS SHOULD NOT BE USED IN PRODUCTION.
  pub fn gen_srs_for_testing<R: RngCore + CryptoRng>(mut rng: &mut R, max_degree: usize) -> Self {
    let beta = E::Fr::random(&mut rng);
    let g = E::G1::random(&mut rng);
    let h = E::G2::random(rng);

    let nz_powers_of_beta = (0..=max_degree)
      .scan(beta, |acc, _| {
        let val = *acc;
        *acc *= beta;
        Some(val)
      })
      .collect::<Vec<E::Fr>>();

    let window_size = fb_msm::get_mul_window_size(max_degree);
    let scalar_bits = E::Fr::NUM_BITS as usize;

    let (powers_of_g_projective, powers_of_h_projective) = rayon::join(
      || {
        let g_table = fb_msm::get_window_table(scalar_bits, window_size, g);
        fb_msm::multi_scalar_mul::<E::G1>(scalar_bits, window_size, &g_table, &nz_powers_of_beta)
      },
      || {
        let h_table = fb_msm::get_window_table(scalar_bits, window_size, h);
        fb_msm::multi_scalar_mul::<E::G2>(scalar_bits, window_size, &h_table, &nz_powers_of_beta)
      },
    );

    let mut powers_of_g = vec![E::G1Affine::identity(); powers_of_g_projective.len()];
    let mut powers_of_h = vec![E::G2Affine::identity(); powers_of_h_projective.len()];

    rayon::join(
      || E::G1::batch_normalize(&powers_of_g_projective, &mut powers_of_g),
      || E::G2::batch_normalize(&powers_of_h_projective, &mut powers_of_h),
    );

    Self { powers_of_g, powers_of_h }
  }
}

/// Commitments
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound(
  serialize = "E::G1Affine: Serialize",
  deserialize = "E::G1Affine: Deserialize<'de>"
))]
pub struct UVKZGCommitment<E: Engine>(
  /// the actual commitment is an affine point.
  pub E::G1Affine,
);

impl<E: Engine> TranscriptReprTrait<E::G1> for UVKZGCommitment<E>
where
  E::G1: DlogGroup,
  // Note: due to the move of the bound TranscriptReprTrait<G> on G::Base from Group to Engine
  <E::G1 as Group>::Base: TranscriptReprTrait<E::G1>,
{
  fn to_transcript_bytes(&self) -> Vec<u8> {
    // TODO: avoid the round-trip through the group (to_curve .. to_coordinates)
    let (x, y, is_infinity) = self.0.to_curve().to_coordinates();
    let is_infinity_byte = (!is_infinity).into();
    [x.to_transcript_bytes(), y.to_transcript_bytes(), [is_infinity_byte].to_vec()].concat()
  }
}

/// Provides a commitment engine
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZGCommitmentEngine<E> {
  _p: PhantomData<E>,
}

impl<E: Engine, NE: NovaEngine<GE = E::G1, Scalar = E::Fr>> CommitmentEngineTrait<NE>
  for KZGCommitmentEngine<E>
where
  E::G1: DlogGroup<ScalarExt = E::Fr, AffineExt = E::G1Affine>,
  E::G1Affine: Serialize + for<'de> Deserialize<'de>,
  E::G2Affine: Serialize + for<'de> Deserialize<'de>,
  E::Fr: PrimeFieldBits, // TODO due to use of gen_srs_for_testing, make optional
{
  type Commitment = Commitment<NE>;
  type CommitmentKey = UniversalKZGParam<E>;

  fn setup(label: &'static [u8], n: usize) -> Self::CommitmentKey {
    // TODO: this is just for testing, replace by grabbing from a real setup for
    // production
    let mut bytes = [0u8; 32];
    let len = label.len().min(32);
    bytes[..len].copy_from_slice(&label[..len]);
    let rng = &mut StdRng::from_seed(bytes);
    UniversalKZGParam::gen_srs_for_testing(rng, n.next_power_of_two())
  }

  fn commit(ck: &Self::CommitmentKey, v: &[<E::G1 as Group>::Scalar]) -> Self::Commitment {
    assert!(ck.length() >= v.len());
    Commitment { comm: E::G1::vartime_multiscalar_mul(v, &ck.powers_of_g[..v.len()]) }
  }
}

impl<E: Engine, NE: NovaEngine<GE = E::G1, Scalar = E::Fr>> From<Commitment<NE>>
  for UVKZGCommitment<E>
where E::G1: Group
{
  fn from(c: Commitment<NE>) -> Self { Self(c.comm.to_affine()) }
}

impl<E: Engine, NE: NovaEngine<GE = E::G1, Scalar = E::Fr>> From<UVKZGCommitment<E>>
  for Commitment<NE>
where E::G1: Group
{
  fn from(c: UVKZGCommitment<E>) -> Self { Self { comm: c.0.to_curve() } }
}
