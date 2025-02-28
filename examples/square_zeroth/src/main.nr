/// Square only the first register.
pub fn main(registers: [Field; 2], next_pc: Field) -> pub ([Field; 2], Field) {
    ([registers[0] * registers[0], registers[1]], next_pc)
}
