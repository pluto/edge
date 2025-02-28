use client_side_prover_frontend::{noir::NoirProgram, F, G1};
use tracing_test::traced_test;

mod ivc;

pub fn add_external() -> NoirProgram {
  let bytecode = std::fs::read("../examples/add_external/target/add_external.json")
    .expect("Failed to read Noir program file");
  NoirProgram::new(&bytecode)
}

pub fn square_zeroth() -> NoirProgram {
  let bytecode = std::fs::read("../examples/square_zeroth/target/square_zeroth.json")
    .expect("Failed to read Noir program file");
  NoirProgram::new(&bytecode)
}

pub fn swap_memory() -> NoirProgram {
  let bytecode = std::fs::read("../examples/swap_memory/target/swap_memory.json")
    .expect("Failed to read Noir program file");
  NoirProgram::new(&bytecode)
}
