package circuits

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Semaphore struct {
	Secret              frontend.Variable
	MerkleProofLength   frontend.Variable
	MerkleProofIndices  [MAX_DEPTH]frontend.Variable
	MerkleProofSiblings [MAX_DEPTH]frontend.Variable
	Message             frontend.Variable `gnark:",public"`
	Scope               frontend.Variable `gnark:",public"`
	DummySquare         frontend.Variable `gnark:",public"`
	MerkleRoot          frontend.Variable `gnark:",public"`
	Nullifier           frontend.Variable `gnark:",public"`
}

func (circuit *Semaphore) Define(api frontend.API) error {
	// The secret scalar must be in the prime subgroup order l + 1
	l := new(big.Int)
	l.SetString("2736030358979909402780800718157159386076813972158567259200215660948447373040", 10)
	api.AssertIsLessOrEqual(circuit.Secret, l)

	// Calculate Identity Commitment
	// Calculate public key from the secret
	// TODO: Use Public Key
	m, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	m.Reset()
	m.Write(circuit.Secret)
	idc := m.Sum()

	// Calculate Merkle Root
	merkleRoot := BinaryMerkleRoot{
		Leaf:     idc,
		Depth:    circuit.MerkleProofLength,
		Indices:  circuit.MerkleProofIndices,
		Siblings: circuit.MerkleProofSiblings,
	}
	if err := merkleRoot.Define(api); err != nil {
		return err
	}
	calculatedMerkleRoot := merkleRoot.Out
	api.AssertIsEqual(circuit.MerkleRoot, calculatedMerkleRoot)

	// Calculate Nullifier
	m.Reset()
	m.Write(circuit.Scope)
	m.Write(circuit.Secret)
	calculatedNullifier := m.Sum()
	api.AssertIsEqual(circuit.Nullifier, calculatedNullifier)

	// Calculate Dummy Square
	calculatedDummySquare := api.Mul(circuit.Message, circuit.Message)
	api.AssertIsEqual(circuit.DummySquare, calculatedDummySquare)

	return nil
}
