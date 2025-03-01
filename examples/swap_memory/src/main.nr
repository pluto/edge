use nivc::FoldingOutput;

/// Swap the two registers.
pub fn main(registers: pub [Field; 2], next_pc: Field) -> pub FoldingOutput<2> {
    FoldingOutput { registers: [registers[1], registers[0]], next_pc: Option::some(next_pc) }
}
