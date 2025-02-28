/// Swap the two registers.
pub fn main(registers: pub [Field; 2], next_pc: pub Field) -> pub (Field, [Field; 2]) {
    (next_pc, [registers[1], registers[0]])
}
