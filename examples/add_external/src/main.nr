/// Add two external values to two registers that are folded across circuits.
pub fn main(
    external: [Field; 2],
    registers: pub [Field; 2],
    next_pc: pub Field,
) -> pub (Field, [Field; 2]) {
    (next_pc, [external[0] + registers[0], external[1] + registers[1]])
}
