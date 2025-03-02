use client_side_prover_frontend::{noir::NoirProgram, Scalar};
use tracing_test::traced_test;

mod ivc;

pub fn add_external() -> NoirProgram {
  let bytecode =
    std::fs::read("../target/add_external.json").expect("Failed to read Noir program file");
  NoirProgram::new(&bytecode)
}

pub fn square_zeroth() -> NoirProgram {
  let bytecode =
    std::fs::read("../target/square_zeroth.json").expect("Failed to read Noir program file");
  NoirProgram::new(&bytecode)
}

pub fn swap_memory() -> NoirProgram {
  let bytecode =
    std::fs::read("../target/swap_memory.json").expect("Failed to read Noir program file");
  NoirProgram::new(&bytecode)
}
