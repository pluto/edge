pub struct FoldingIO {
    pub registers: [Field; 2],
    pub next_pc: Field,
}

/// Square only the first register.
pub fn main(registers: pub [Field; 2], next_pc: Field) -> pub FoldingIO {
    FoldingIO { registers: [registers[0] * registers[0], registers[1]], next_pc: next_pc }
}
