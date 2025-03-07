use nivc::FoldingVariables;

/// When the value is even, divide it by 2.
/// If the value is 1, return -1 to indicate the end of the sequence.
/// Otherwise, return 0 or 1 to indicate the next program counter, i.e., collatz_even or collatz_odd.
pub fn main(folding_variables: pub FoldingVariables<1>) -> pub FoldingVariables<1> {
    // Get the value from the first register as a u64 for easier manipulation.
    let value = folding_variables.registers[0] as u64;

    // Run the even-value transformation. { f(n) = n / 2 }
    let next_value = value / 2;

    // If the next value is 1, we've reached the end of the sequence (the fixed cycle predicted by the Collatz conjecture).
    // We return -1 to indicate that the sequence has ended.
    let next_pc = if next_value % 2 == 0 {
        0
    } else if next_value == 1 {
        -1
    } else {
        1
    };

    // Return the updated folding variables with the new value and program counter.
    FoldingVariables { registers: [next_value as Field], program_counter: next_pc }
}
