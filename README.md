<p align="center">
  <img src="https://raw.githubusercontent.com/pluto/.github/main/profile/assets/assets_ios_Pluto-1024%401x.png" alt="Pluto Logo" width="50" height="50">
  <br>
  <b style="font-size: 24px;">Pluto</b>
</p>
<p align="center">
  <a href="https://t.me/pluto_xyz/1"><img src="https://img.shields.io/badge/Telegram-Group-8B5CF6?style=flat-square&logo=telegram&logoColor=white&labelColor=24292e&scale=1.5" alt="Telegram"></a>
  <a href="https://docs.pluto.xyz/"><img src="https://img.shields.io/badge/Docs-Pluto-8B5CF6?style=flat-square&logo=readme&logoColor=white&labelColor=24292e&scale=1.5" alt="Docs"></a>
  <img src="https://img.shields.io/badge/License-Apache%202.0-8B5CF6.svg?label=license&labelColor=2a2f35" alt="License">
</p>

---

# Edge
> Enabling private computation on the edge.

## Features
- Supernova NIVC folding scheme implementation
- Support for Noir circuit DSL
- Client-side proving capabilities through native x86, aarch64, and WASM
- End-to-end proof setup, running, and verification

## Project Structure
The repository contains several key components:
- `edge-prover`: Backend implementation of Supernova NIVC folding scheme
- `edge-frontend`: Frontend adapters for Noir to use `edge-prover`
- `demo`: A demo application for the `edge-frontend` and `edge-prover`

### Prerequisites
Before running the demo, ensure you have:
1. Rust, Noir, and their associated tools installed
2. The Noir programs compiled to JSON (located in the `target/` directory). To do so, just run 
```
nargo compile --workspace
```
from the root directory.

### Running the Demo
The demo application has three main commands: setup, prove, and verify. The help command can be used to see the available options.
```
cargo run -p demo -- --help
```
The demo application proves sequences to a fun (and unproven) math called the Collatz conjecture. In short, for any positive integer `n`, the sequence is defined as:
```
if n is 1, stop.
if n is even, repeat this process on n/2.
if n is odd, repeat this process on 3n + 1.
```
So depending on the starting value, you will find a different sequence of circuits is used to prove the sequence. If you happen to find a case where this proof doesn't work, please let us know -- you may have found a counter example to the conjecture! 😁

#### 1. Setup Phase
First, run the offline setup phase:
```
cargo run -p demo -- setup
```
This will create a `setup.bytes` file in the current directory. You can specify an output file name as an argument (see help for more details).

#### 2. Prove Phase
Generate a proof for a specific input value (e.g., 42):
```
cargo run -p demo -- prove --input 42
```
This creates:
- `proof.bytes`: The compressed proof
- `proof.meta.json`: Metadata about the proof, including:
  - The input value
  - Number of steps in the Collatz sequence
  - The complete sequence of even/odd operations
If you'd like, you can run with some logging to see the steps:
```
cargo run -p demo -- prove --input 42 -v
```
and to see more logs, you can use `-vv` or `-vvv`.

#### 3. Verify Phase
To verify a proof, run:
```
cargo run -p demo -- verify --input 42
```
This will verify the proof. Without verbosity, no output implies a valid proof. But if you provided an incorrect input, you will see an error message. For example, if you provide an input of 43, you will see:
```
ERROR demo: ❌ Proof verification failed: NovaError
Error: NovaError(ProofVerifyError)
```


## Usage
This repository and its crates are **not** production ready. Do not use them in production. No audits have been done and none are planned.
 
With that said, work has been done to make the implementation here work with an offline setup phase. Therefore, this can be used run proofs on an edge device which can later be verified by a remote server.

## Contributing

We welcome contributions to our open-source projects. If you want to contribute or follow along with contributor discussions, join our main [Telegram channel](https://t.me/pluto_xyz/1) to chat about Pluto's development.

Our contributor guidelines can be found in our [CONTRIBUTING.md](https://github.com/pluto/.github/blob/main/profile/CONTRIBUTING.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.

## License

This project is licensed under the Apache V2 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements
> [!NOTE]
> This repository is a fork of the original hosted at [https://github.com/microsoft/nova](https://github.com/microsoft/nova) and also forked from [https://github.com/argumentcomputer/arecibo](https://github.com/argumentcomputer/arecibo).
