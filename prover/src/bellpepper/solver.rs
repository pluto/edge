//! Support for generating R1CS witness using bellpepper.

use bellpepper::util_cs::witness_cs::WitnessCS;

use crate::traits::Engine;

/// A `ConstraintSystem` which calculates witness values for a concrete instance
/// of an R1CS circuit.
pub type SatisfyingAssignment<E> = WitnessCS<<E as Engine>::Scalar>;
