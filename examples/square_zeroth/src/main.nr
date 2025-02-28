/// Square only the first register.
pub fn main(registers: pub [Field; 2], next_pc: pub Field) -> pub (Field, [Field; 2]) {
    (next_pc, [registers[0] * registers[0], registers[1]])
}
