use nivc::FoldingOutput;

/// Checks general arithmetic operations.
pub fn main(
    registers: pub [Field; 2],
    external_mul: [Field; 2],
    external_add: [Field; 2],
    next_pc: Field,
) -> pub FoldingOutput<2> {
    FoldingOutput {
        registers: [
            external_mul[0] * registers[0] + external_add[0] + 420,
            external_mul[1] * registers[1] + external_add[1] + 69,
        ],
        next_pc,
    }
}
