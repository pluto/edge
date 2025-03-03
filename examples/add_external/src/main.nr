use nivc::FoldingVariables;

/// Add two external values to two registers that are folded across circuits.
pub fn main(
    folding_variables: pub FoldingVariables<2>,
    external: [Field; 2],
    next_pc: Field,
) -> pub FoldingVariables<2> {
    FoldingVariables {
        registers: [
            external[0] + folding_variables.registers[0],
            external[1] + folding_variables.registers[1],
        ],
        program_counter: next_pc,
    }
}
