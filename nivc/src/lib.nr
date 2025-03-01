pub struct FoldingOutput<let N: u32> {
    pub registers: [Field; N],
    pub next_pc: Field,
}

// TODO: It would be nice to be able to force the `main` function to have a specific signature. In particular, we want:
// pub fn main(registers: pub [Field; N], input: T) -> pub FoldingOutput<N> { .. }
// Perhaps this can be done with a macro almost like `#[nivc_main]`?
