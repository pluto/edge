//! This test module is effectively testing a static (comptime) circuit dispatch
//! supernova program

use client_side_prover::supernova::RecursiveSNARK;

use super::*;
use crate::program::{
  data::{CircuitData, NotExpanded, ProofParams, SetupParams},
  initialize_setup_data,
};

pub(crate) mod inputs;
mod witnesscalc;
