/// Add two external values to two registers that are folded across circuits.
pub fn main(
    external: [Field; 2],
    registers: [Field; 2],
    next_pc: Field,
) -> pub ([Field; 2], Field) {
    ([external[0] + registers[0], external[1] + registers[1]], next_pc)
}
