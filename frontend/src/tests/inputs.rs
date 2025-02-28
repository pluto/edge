pub const ADD_EXTERNAL_R1CS: &[u8] = include_bytes!("examples/circuit_data/add_external.r1cs");
pub const SQUARE_ZEROTH_R1CS: &[u8] = include_bytes!("examples/circuit_data/square_zeroth.r1cs");
pub const SWAP_MEMORY_R1CS: &[u8] = include_bytes!("examples/circuit_data/swap_memory.r1cs");

pub const EXTERNAL_INPUTS: [[u64; 2]; 2] = [[5, 7], [13, 1]];
pub const ADD_EXTERNAL_GRAPH: &[u8] = include_bytes!("examples/circuit_data/add_external.bin");
pub const SQUARE_ZEROTH_GRAPH: &[u8] = include_bytes!("examples/circuit_data/square_zeroth.bin");
pub const SWAP_MEMORY_GRAPH: &[u8] = include_bytes!("examples/circuit_data/swap_memory.bin");
