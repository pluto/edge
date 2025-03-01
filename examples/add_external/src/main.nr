pub struct FoldingIO {
    pub registers: [Field; 2],
    pub next_pc: Field,
}

/// Add two external values to two registers that are folded across circuits.
pub fn main(external: [Field; 2], registers: pub [Field; 2], next_pc: Field) -> pub FoldingIO {
    FoldingIO {
        registers: [external[0] + registers[0], external[1] + registers[1]],
        next_pc: next_pc,
    }
}
