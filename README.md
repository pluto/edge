# Client Side Prover

> [!NOTE]
> This repository is a fork of the original hosted at [https://github.com/microsoft/nova](https://github.com/microsoft/nova) and also forked from [https://github.com/argumentcomputer/arecibo](https://github.com/argumentcomputer/arecibo).

## Project Structure
The repository contains several key components:
- `client-side-prover-frontend`: Frontend adapters for both Noir and Circom
- `client-side-prover`: Backend implementation of the client side prover

## Features
- Supernova NIVC folding scheme implementation
- Support for both Noir and Circom circuit frameworks
- Client-side proving capabilities through WebAssembly
- Recursive proof generation and verification

## Usage
This repository and its crates are **not** production ready. Do not use them in production. No audits have been done and none are planned.
 
With that said, work has been done to make the implementation here work with an offline setup phase. Therefore, this can be used run proofs on an edge device which can later be verified by a remote server.