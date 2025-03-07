use nivc::FoldingVariables;

/// When the value is odd, multiply it by 3 and add 1.
/// If the result is even, return 0 to indicate the next program counter, i.e., collatz_even.
/// Otherwise, return 1 to indicate the next program counter, i.e., collatz_odd.
/// Note, { f(n) = 3n + 1 } can never be 1, so we don't need to check for that.
pub fn main(folding_variables: pub FoldingVariables<1>) -> pub FoldingVariables<1> {
    let value = folding_variables.registers[0] as u64;

    let next_value = 3 * value + 1;
    let next_pc = if next_value % 2 == 0 { 0 } else { 1 };

    FoldingVariables { registers: [next_value as Field], program_counter: next_pc }
}
