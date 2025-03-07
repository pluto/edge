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
- Support for both Noir and Circom circuit frameworks
- Client-side proving capabilities through WebAssembly
- Recursive proof generation and verification

## Project Structure
The repository contains several key components:
- `edge-frontend`: Frontend adapters for both Noir and Circom
- `edge-prover`: Backend implementation of the client side prover

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