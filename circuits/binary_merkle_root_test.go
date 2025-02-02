package circuits

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/NguyenHiu/semaphore-implementation-in-go/leanIMT"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

// mimcHashFunc returns bn254 mimc hash of an array of big.int variables
func mimcHashFunc(vals []*big.Int) (*big.Int, error) {
	m := mimc.NewMiMC()
	m.Reset()
	for _, val := range vals {
		var x fr.Element
		x.SetBigInt(val)
		b := x.Bytes()
		if _, err := m.Write(b[:]); err != nil {
			fmt.Println("mimc hash err:", err)
			return nil, err
		}
	}

	r := new(big.Int)
	r.SetBytes(m.Sum(nil))
	return r, nil
}

// TestBinaryMerkleRoot checks that the BinaryMerkleRoot circuit is correct
func TestBinaryMerkleRoot(t *testing.T) {
	assert := test.NewAssert(t)

	// Generate Merkle Proof
	leaves := []*big.Int{}
	n := 5
	for i := 0; i < n; i++ {
		leaves = append(leaves, big.NewInt(rand.Int64N(1000)))
	}
	imt, err := leanIMT.NewLeanIMT(mimcHashFunc, leaves)
	assert.NoError(err)
	merkleProof, err := imt.GenerateProof(0)
	assert.NoError(err)

	// Parse indices and siblings arrays
	path := [MAX_DEPTH]frontend.Variable{}
	siblings := [MAX_DEPTH]frontend.Variable{}
	for i := 0; i < MAX_DEPTH; i++ {
		if i >= len(merkleProof.Path) {
			path[i] = 0
			siblings[i] = "0"
		} else {
			path[i] = merkleProof.Path[i]
			siblings[i] = merkleProof.Siblings[i].String()
		}
	}

	// Ensure the current root is correct
	validateIMT(t, imt)

	var c BinaryMerkleRoot
	assert.ProverSucceeded(&c, &BinaryMerkleRoot{
		Leaf:     merkleProof.Node.String(),
		Depth:    imt.Depth(),
		Indices:  path,
		Siblings: siblings,
		Out:      imt.Root().String(), // Set contraints
	}, test.WithCurves(ecc.BN254))
}

// validateIMT validates the integrity of the LeanIMT by ensuring that each parent node
// is correctly computed from its child Nodes using the Poseidon hash function.
func validateIMT(t *testing.T, imt *leanIMT.LeanIMT) {
	for i := 0; i < imt.Depth(); i++ {
		for j := 0; j < len(imt.Nodes[i]); j += 2 {
			parentIdx := j / 2
			var val *big.Int
			if j == len(imt.Nodes[i])-1 {
				val = imt.Nodes[i][j]
			} else {
				var err error
				val, err = mimcHashFunc([]*big.Int{imt.Nodes[i][j], imt.Nodes[i][j+1]})
				require.NoError(t, err)
			}
			require.Equal(t, imt.Nodes[i+1][parentIdx], val)
		}
	}
}
