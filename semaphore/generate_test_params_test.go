package semaphore

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

func MimcHash(inpBI []*big.Int) (*big.Int, error) {
	hasher := mimc.NewMiMC()
	hasher.Reset()
	for i := 0; i < len(inpBI); i++ {
		if _, err := hasher.Write(inpBI[i].Bytes()); err != nil {
			return nil, err
		}
	}
	res := new(big.Int)
	res.SetBytes(hasher.Sum(nil))
	return res, nil
}

// TestGenerateSemaphoreInputsForGnark prints out an input instance of semaphore circuit for testing
func TestGenerateSemaphoreInputsForGnark(t *testing.T) {
	secret := new(big.Int)
	secret.SetString("2736030358979909402780800718157159386076813972158567259200215660948447373040", 10)

	commitment, err := MimcHash([]*big.Int{secret})
	require.NoError(t, err)

	fmt.Println(">> commitment:", commitment)

	group, err := NewLeanIMT(MimcHash, []*big.Int{commitment, big.NewInt(2), big.NewInt(3), big.NewInt(4)})
	require.NoError(t, err)

	merkleProof, err := group.GenerateProof(0)
	require.NoError(t, err)

	printNodes(group)

	// Get indices
	merkleProofIndices := []int{}
	for i := 0; i < len(merkleProof.Path); i++ {
		merkleProofIndices = append(merkleProofIndices, merkleProof.Path[i])
	}
	for len(merkleProofIndices) != MAX_DEPTH {
		merkleProofIndices = append(merkleProofIndices, 0)
	}

	// Get Siblings
	merkleProofSiblings := []string{}
	for i := 0; i < len(merkleProof.Siblings); i++ {
		merkleProofSiblings = append(merkleProofSiblings, merkleProof.Siblings[i].String())
	}
	for len(merkleProofSiblings) != MAX_DEPTH {
		merkleProofSiblings = append(merkleProofSiblings, "0")
	}

	input := struct {
		Secret              string   `json:"secret"`
		MerkleProofLength   int      `json:"merkleProofLength"`
		MerkleProofIndices  []int    `json:"merkleProofIndices"`
		MerkleProofSiblings []string `json:"merkleProofSiblings"`
		Message             string   `json:"message"`
		Scope               string   `json:"scope"`
	}{
		Secret:              secret.String(),
		MerkleProofLength:   group.Depth(),
		MerkleProofIndices:  merkleProofIndices,
		MerkleProofSiblings: merkleProofSiblings,
		Message:             "1412",
		Scope:               "123",
	}

	jsonData, err := json.MarshalIndent(input, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(jsonData))

	// Prints out the merkle root to compare with public output of the circuit
	fmt.Println(">> merkle root:", merkleProof.Root)
}

// TestGenerateSemaphoreInputsForCircom prints out an input instance of semaphore circuit for testing
// FOR CIRCOM ONLY BECAUSE IT'S USING POSEIDON HASH FUNCTION
func TestGenerateSemaphoreInputsForCircom(t *testing.T) {
	secret := new(big.Int)
	secret.SetString("2736030358979909402780800718157159386076813972158567259200215660948447373040", 10)

	secretPoint := babyjub.NewPoint().Mul(secret, babyjub.B8)
	commitment, err := poseidon.Hash([]*big.Int{secretPoint.X, secretPoint.Y})
	require.NoError(t, err)

	group, err := NewLeanIMT(poseidon.Hash, []*big.Int{commitment, big.NewInt(2), big.NewInt(3), big.NewInt(4)})
	require.NoError(t, err)

	merkleProof, err := group.GenerateProof(0)
	require.NoError(t, err)

	printNodes(group)

	// Get indices
	merkleProofIndices := []int{}
	for i := 0; i < len(merkleProof.Path); i++ {
		merkleProofIndices = append(merkleProofIndices, merkleProof.Path[i])
	}
	for len(merkleProofIndices) != MAX_DEPTH {
		merkleProofIndices = append(merkleProofIndices, 0)
	}

	// Get Siblings
	merkleProofSiblings := []string{}
	for i := 0; i < len(merkleProof.Siblings); i++ {
		merkleProofSiblings = append(merkleProofSiblings, merkleProof.Siblings[i].String())
	}
	for len(merkleProofSiblings) != MAX_DEPTH {
		merkleProofSiblings = append(merkleProofSiblings, "0")
	}

	input := struct {
		Secret              string   `json:"secret"`
		MerkleProofLength   int      `json:"merkleProofLength"`
		MerkleProofIndices  []int    `json:"merkleProofIndices"`
		MerkleProofSiblings []string `json:"merkleProofSiblings"`
		Message             string   `json:"message"`
		Scope               string   `json:"scope"`
	}{
		Secret:              secret.String(),
		MerkleProofLength:   group.Depth(),
		MerkleProofIndices:  merkleProofIndices,
		MerkleProofSiblings: merkleProofSiblings,
		Message:             "1412",
		Scope:               "123",
	}

	jsonData, err := json.MarshalIndent(input, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(jsonData))

	// Prints out the merkle root to compare with public output of the circuit
	fmt.Println(">> merkle root:", merkleProof.Root)
}
