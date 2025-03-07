use nivc::FoldingVariables;

/// Checks general arithmetic operations.
pub fn main(
    folding_variables: pub FoldingVariables<1>,
    external_mul: Field,
    external_add: Field,
) -> pub FoldingVariables<1> {
    FoldingVariables {
        registers: [
            external_mul * folding_variables.registers[0] + external_add + 420,
        ],
        program_counter: folding_variables.program_counter,
    }
}
