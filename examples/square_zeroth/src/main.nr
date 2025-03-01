use nivc::FoldingOutput;

/// Square only the first register.
pub fn main(registers: pub [Field; 2], next_pc: Field) -> pub FoldingOutput<2> {
    FoldingOutput {
        registers: [registers[0] * registers[0], registers[1]],
        next_pc: Option::some(next_pc),
    }
}

