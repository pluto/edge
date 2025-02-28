/// Swap the two registers.
pub fn main(registers: [Field; 2], next_pc: Field) -> pub ([Field; 2], Field) {
    ([registers[1], registers[0]], next_pc)
}
