/// Square only the first register.
pub fn main(registers: [Field; 2], next_pc: Field) -> pub (Field, [Field; 2]) {
    (next_pc, [registers[0] * registers[0], registers[1]])
}
