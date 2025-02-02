package circuits

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestSemaphore(t *testing.T) {
	assert := test.NewAssert(t)

	secretStr := "2736030358979909402780800718157159386076813972158567259200215660948447373040"
	secret := new(big.Int)
	secret.SetString(secretStr, 10)

	// Calculate test values
	merkleProofLength := 2
	merkleProofRoot, _ := new(big.Int).SetString("20929041536166227224353180062196682171734823195714040336963397564791155168013", 10)
	merkleProofIndices := [10]frontend.Variable{0, 0}
	for i := merkleProofLength; i < 10; i++ {
		merkleProofIndices[i] = 0
	}
	siblings := []string{
		"2",
		"2190690676082781141873133671079047905725045108867240828170571956736152080833",
	}
	merkleProofSiblings := [10]frontend.Variable{}
	for i := 0; i < 10; i++ {
		if i < len(siblings) {
			merkleProofSiblings[i] = siblings[i]
		} else {
			merkleProofSiblings[i] = "0"
		}
	}
	scope := big.NewInt(8386)
	message := big.NewInt(2)
	dummySquare := new(big.Int).Mul(message, message)
	m := mimc.NewMiMC()
	m.Reset()
	m.Write(scope.Bytes())
	m.Write(secret.Bytes())
	nullifier := new(big.Int).SetBytes(m.Sum(nil))

	var c Semaphore
	assert.ProverSucceeded(&c, &Semaphore{
		Secret:              frontend.Variable(secret),
		MerkleProofLength:   merkleProofLength,
		MerkleProofIndices:  merkleProofIndices,
		MerkleProofSiblings: merkleProofSiblings,
		Message:             message,
		Scope:               scope,
		MerkleRoot:          merkleProofRoot,
		DummySquare:         dummySquare,
		Nullifier:           nullifier,
	}, test.WithCurves(ecc.BN254))
}
