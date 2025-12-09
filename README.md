# Evice Blockchain (Evice-Blockchain-Tendermint-19s)

A robust Layer 1 blockchain built in Rust, designed for security and extensibility. It features a native ZK-Rollup (L2) for high throughput, WASM smart contracts, and next-generation post-quantum (Dilithium2) signatures.

This project is an advanced, full-featured blockchain node implementing a custom BFT consensus, a complete Layer 2 rollup solution, and next-generation cryptography.

## 🚀 Core Features

* **Hybrid L1/L2 Architecture:** A sovereign Layer 1 chain that also serves as the settlement and data availability layer for its own native ZK-Rollup.
* **ZK-Rollup Sequencer & Prover:** Includes a dedicated Sequencer (`sequencer.rs`) to batch L2 transactions and a `prover.rs` binary to generate ZK-SNARK proofs (`ark-groth16`) for state transitions.
* **Post-Quantum Cryptography:** Uses **Dilithium2** (`pqcrypto-dilithium`) for all on-chain signatures, making the L1 chain resistant to attacks from quantum computers.
* **WASM Smart Contracts:** The L1 chain supports turing-complete smart contracts compiled to WASM, executed securely via the `wasmer` runtime (`wasm_runtime.rs`).
* **BFT Consensus:** Implements a Tendermint-style BFT consensus engine (`consensus.rs`) for L1 finality, complete with `Prevote` and `Precommit` steps.
* **Cross-Layer Bridge:** Features a built-in L1/L2 bridge (`contracts/bridge_contract`) for seamless asset deposits and withdrawals (`tests/full_flow.rs`).
* **Proof-of-Authority (PoA) & Slashing:** L1 consensus is secured by a set of known validators, with on-chain slashing for misbehavior like double-signing (`slashing_test.rs`).
* **On-Chain Governance:** Includes a module for submitting proposals and casting votes, allowing the protocol to be upgraded by its stakeholders (`governance.rs`).
* **Modern P2P & RPC:** Uses `libp2p` for a robust peer-to-peer network (Gossipsub, Kademlia) and `tonic` (gRPC) for a high-performance RPC API.

## 🏛️ Architectural Overview

This repository contains the code for a complete blockchain ecosystem, structured as a Rust workspace.

### 1. Layer 1 (Settlement Layer)

The main `evice_blockchain` binary is the L1 node. Its responsibilities include:
* Running the BFT consensus state machine (`main.rs`) to finalize blocks.
* Broadcasting and validating L1 transactions (`TransactionData`).
* Verifying and committing `SubmitRollupBatch` transactions, which involves:
    * Checking VRF-based sequencer leadership.
    * Verifying Data Availability (DAC) signatures.
    * **Verifying the ZK-SNARK proof** (`Groth16::verify`) against the L2 state transition.
* Executing L1 WASM smart contracts (`DeployContract`, `CallContract`).
* Managing the persistent state in a `parity-db` Merkle-Patricia Trie (`state.rs`).

### 2. Layer 2 (Execution Layer - ZK-Rollup)

The L2 is an off-chain execution environment that posts its results to the L1.
* **`sequencer.rs`:** A separate binary that runs an L2 node. It provides an HTTP endpoint (`l2_sendTransaction`) to receive user transactions, maintains an L2 Merkle tree, and selects transactions for a batch.
* **`prover.rs`:** A binary that takes L2 batch data, executes the `BatchSystemCircuit` (`l2_circuit.rs`), and generates a Groth16 ZK-proof.
* **Workflow:** The Sequencer collects L2 transactions, calls the Prover to get a proof, and then submits this proof and batch data to the L1.

### 3. Post-Quantum Cryptography

Instead of standard ECDSA, this chain uses Dilithium2, a CRYSTALS-Dilithium signature scheme chosen by NIST for standardization.
* **Signatures:** `SIGNATURE_SIZE: 2420` bytes.
* **Public Keys:** `PUBLIC_KEY_SIZE: 1312` bytes.
* This provides robust, forward-looking security against future quantum threats.

## 🛠️ Running the Project (Local Testnet)

This project uses a detailed script to generate all necessary keys and configuration for a local 6-node testnet.

### Prerequisites

* Rust & Cargo: `rustup install stable`
* C++ Compiler (Clang/GCC)
* RocksDB (system-wide installation)
* OpenSSL (dev libraries)

### 1. Build the Project

Compile all binaries and contracts in release mode for the best performance.

```bash
cargo build --release

### 2. Generate Testnet Configuration

The start_testnet.sh script will generate all keys (signing keys, VRF keys, TLS certs) and the genesis.json file needed to run a 6-node network.
chmod +x start_testnet.sh
./start_testnet.sh

### 3. Run the Nodes

The script will not run the nodes automatically. Instead, it will print the exact commands needed to run each of the 6 nodes.
    * Open 6 separate terminal windows.
    * Copy and paste one command into each terminal to launch the network.

Example (Terminal 1 - Bootstrap Node):
RUST_LOG=info,evice_blockchain=debug target/debug/evice_blockchain \
    --db-path ./permanent_testnet/node1/database \
    --is-authority \
    --keystore-path './permanent_testnet/node1/keystores/UTC--...' \
    --vrf-private-key '...' \
    --password '1234'

Example (Terminal 2 - Peer Node):
RUST_LOG=info,evice_blockchain=debug target/debug/evice_blockchain \
    --db-path ./permanent_testnet/node2/database \
    --rpc-port 8081 \
    --p2p-port 50001 \
    --is-authority \
    --keystore-path './permanent_testnet/node2/keystores/UTC--...' \
    --vrf-private-key '...' \
    --bootstrap-node "/ip4/127.0.0.1/tcp/50000/p2p/..." \
    --password '1234'

### 4. Interact with the Chain

Once the nodes are running, you can use the create_tx binary to interact with the L1 chain via its gRPC endpoint.
* Check the balance of a validator
* (You must first get the address from the testnet script output)
* Note: This requires a gRPC client, as the CLI is designed for sending transactions.

* Send a transaction (example from the script)
target/debug/create_tx --l1-rpc-url [http://127.0.0.1:8080](http://127.0.0.1:8080) transfer \
    --keystore-path './permanent_testnet/node1/keystores/UTC--...' \
    --recipient '0x...' \
    --amount 100 \
    --nonce 0
```

## 💻 Technology Stack
   * Core Logic: Rust, Tokio
   * Consensus: Custom BFT (Tendermint-style) + VRF Proposer Election
   * L2 / ZK-SNARKs: arkworks (ark-groth16, ark-bls12-381)
   * Cryptography:
     * pqcrypto-dilithium (Post-Quantum Signatures)
     * schnorrkel (VRF)
     * scrypt, XChaCha20Poly1305 (Keystore Encryption)
   * Smart Contracts: wasmer (WASM Runtime)
   * Peer-to-Peer: libp2p (Gossipsub, Kademlia)
   * RPC: tonic (gRPC) & prost
   * Database: parity-db & trie-db (Merkle-Patricia Trie)



