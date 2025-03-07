use nivc::FoldingVariables;

/// Square only the first register.
pub fn main(folding_variables: pub FoldingVariables<2>, next_pc: Field) -> pub FoldingVariables<2> {
    FoldingVariables {
        registers: [
            folding_variables.registers[0] * folding_variables.registers[0],
            folding_variables.registers[1],
        ],
        program_counter: next_pc,
    }
}

