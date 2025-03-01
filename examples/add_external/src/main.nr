use nivc::FoldingOutput;

/// Add two external values to two registers that are folded across circuits.
pub fn main(
    registers: pub [Field; 2],
    external: [Field; 2],
    next_pc: Field,
) -> pub FoldingOutput<2> {
    FoldingOutput { registers: [external[0] + registers[0], external[1] + registers[1]], next_pc }
}
