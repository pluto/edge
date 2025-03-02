use nivc::FoldingOutput;
use std::hash::poseidon::bn254::hash_2;

pub fn main(registers: pub [Field; 2], next_pc: Field) -> pub FoldingOutput<2> {
    FoldingOutput { registers: [hash_2(registers), 0], next_pc }
}
