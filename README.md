# Semaphore Implementation In Go

## Description
Welcome! This repository is a simple implementation of [Semaphore](https://github.com/semaphore-protocol/semaphore) in ***Go***. Instead of using [circom](https://docs.circom.io/), this project uses [gnark](https://github.com/Consensys/gnark) to write circuits. So, there are some differences; for example, `gnark` doesn't support the *Poseidon Hash function*, so I implemented the *MiMC Hash function* instead.

There are two main circuits:
- [BinaryMerkleRoot](./circuits/binary_merkle_root.go) computes the root value of the Merkle tree based on a list of siblings and indices.
- [Semaphore](./circuits/semaphore.go) is used for anonymous signaling, ensures the provided secret is a member of a Merkle tree, and prevents double signaling.

For the backend, the **lean incremental Merkle tree** is implemented as in the (current) latest version of [Semaphore](https://github.com/semaphore-protocol/semaphore).

The program flow, which includes **setting up the circuit**, **generating the proof**, and **verifying the proof**, is set up in the `TestSemaphoreCircuit()` function in the [`semaphore_test.go`](./semaphore/semaphore_test.go) file.