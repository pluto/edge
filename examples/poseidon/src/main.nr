use nivc::FoldingVariables;
use std::hash::poseidon::bn254::hash_2;

pub fn main(folding_variables: pub FoldingVariables<2>) -> pub FoldingVariables<2> {
    FoldingVariables {
        registers: [hash_2(folding_variables.registers), 0],
        program_counter: folding_variables.program_counter,
    }
}
