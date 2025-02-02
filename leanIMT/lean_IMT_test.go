package leanIMT

import (
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

// TestInsert checks the insertion of single elements into the LeanIMT.
func TestInsert(t *testing.T) {
	imt, err := NewLeanIMT(poseidon.Hash, []*big.Int{})
	require.NoError(t, err)
	require.Equal(t, imt.Nodes, [][]*big.Int{})

	err = imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)
}

// TestInsertMany checks the insertion of multiple elements into the LeanIMT at once.
func TestInsertMany(t *testing.T) {
	imt, err := NewLeanIMT(poseidon.Hash, []*big.Int{})
	require.NoError(t, err)

	// Insert some Nodes
	err = imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	err = imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	err = imt.Insert(randomBigInt())
	require.NoError(t, err)
	validateIMT(t, imt)

	n := rand.IntN(10)
	leaves := []*big.Int{}
	for i := 0; i < n; i++ {
		leaves = append(leaves, randomBigInt())
	}

	err = imt.InsertMany(leaves)
	require.NoError(t, err)
	validateIMT(t, imt)
}

// TestUpdate checks the update functionality of the LeanIMT.
func TestUpdate(t *testing.T) {
	imt, err := NewLeanIMT(poseidon.Hash, []*big.Int{})
	require.NoError(t, err)

	// Construct an initial tree
	n := 5
	leaves := randomBigIntArray(n)
	err = imt.InsertMany(leaves)
	require.NoError(t, err)
	validateIMT(t, imt)

	// Update a leaf
	idx := rand.IntN(imt.Size())
	newVal := randomBigInt()
	err = imt.Update(newVal, idx)
	require.NoError(t, err)

	// Check that the updated leaves are correct
	newLeaves := leaves
	newLeaves[idx] = newVal
	require.Equal(t, newLeaves, imt.Nodes[0])

	// Check that the updated tree is valid
	validateIMT(t, imt)
}

// TestUpdateMany checks the batch update functionality of the LeanIMT.
func TestUpdateMany(t *testing.T) {
	imt, err := NewLeanIMT(poseidon.Hash, []*big.Int{})
	require.NoError(t, err)

	// Construct an initial tree
	n := 5
	leaves := randomBigIntArray(5)
	err = imt.InsertMany(leaves)
	require.NoError(t, err)
	// Check if the tree is valid
	validateIMT(t, imt)
	// Store Nodes before update for further checks
	nodesBeforeUpdate := []*big.Int{}
	for i := 0; i < len(imt.Nodes[0]); i++ {
		nodesBeforeUpdate = append(nodesBeforeUpdate, big.NewInt(imt.Nodes[0][i].Int64()))
	}

	// Update batch of leaves
	m := rand.IntN(n)
	newLeaves := randomBigIntArray(m)
	indices := []int{}
	indicesMap := make(map[int]bool) // Ensure changed indices are distinguishable
	for len(indices) != m {
		randomIdx := rand.IntN(n)
		if _, ok := indicesMap[randomIdx]; ok {
			continue
		} else {
			indicesMap[randomIdx] = true
		}
		indices = append(indices, randomIdx)
	}

	// Update Many
	err = imt.UpdateMany(newLeaves, indices)
	require.NoError(t, err)

	// Store Nodes after update for futher checks
	nodesAfterUpdate := imt.Nodes[0]

	// Check that changed leaves are correct
	require.Equal(t, len(nodesBeforeUpdate), len(nodesAfterUpdate))
	noDifferentNodes := 0
	for i := 0; i < len(nodesBeforeUpdate); i++ {
		if nodesBeforeUpdate[i].Cmp(nodesAfterUpdate[i]) != 0 {
			noDifferentNodes++
		}
	}
	require.Equal(t, m, noDifferentNodes)

	// Check that the tree after being updated is valid
	validateIMT(t, imt)
}

// TestGenerateProof checks that the tree generates a correct proof
func TestGenerateProof(t *testing.T) {
	imt, err := NewLeanIMT(poseidon.Hash, []*big.Int{})
	require.NoError(t, err)

	// Construct the tree
	n := 11
	leaves := randomBigIntArray(n)
	err = imt.InsertMany(leaves)
	require.NoError(t, err)
	validateIMT(t, imt)

	// Generate proof for a random index
	m := rand.IntN(n)
	merkleProof, err := imt.GenerateProof(m)
	require.NoError(t, err)
	verifyMerkleProof(t, &merkleProof)
}

func TestVerifyProof(t *testing.T) {
	imt, err := NewLeanIMT(poseidon.Hash, []*big.Int{})
	require.NoError(t, err)

	// Construct the tree
	n := 11
	leaves := randomBigIntArray(n)
	err = imt.InsertMany(leaves)
	require.NoError(t, err)
	validateIMT(t, imt)

	// Generate proof for a random index
	m := rand.IntN(n)
	merkleProof, err := imt.GenerateProof(m)
	require.NoError(t, err)
	verifyMerkleProof(t, &merkleProof)

	// Verify proof
	require.True(t, imt.VerifyProof(&merkleProof))
}

// validateIMT validates the integrity of the LeanIMT by ensuring that each parent node
// is correctly computed from its child Nodes using the Poseidon hash function.
func validateIMT(t *testing.T, imt *LeanIMT) {
	for i := 0; i < imt.Depth(); i++ {
		for j := 0; j < len(imt.Nodes[i]); j += 2 {
			parentIdx := j / 2
			var val *big.Int
			if j == len(imt.Nodes[i])-1 {
				val = imt.Nodes[i][j]
			} else {
				var err error
				val, err = poseidon.Hash([]*big.Int{imt.Nodes[i][j], imt.Nodes[i][j+1]})
				require.NoError(t, err)
			}
			require.Equal(t, imt.Nodes[i+1][parentIdx], val)
		}
	}
}

// verifyMerkleProof checks that the merkle proof is valid
func verifyMerkleProof(t *testing.T, proof *MerkleProof) {
	root := proof.Node
	var err error
	for i := 0; i < len(proof.Path); i++ {
		if proof.Path[i] == 1 {
			root, err = poseidon.Hash([]*big.Int{proof.Siblings[i], root})
		} else {
			root, err = poseidon.Hash([]*big.Int{root, proof.Siblings[i]})
		}
		require.NoError(t, err)
	}
	require.Equal(t, proof.Root, root)
}

// randomBigInt generates a random big integer
func randomBigInt() *big.Int {
	return big.NewInt(rand.Int64N(1000))
}

// randomBigIntArray generates an array of random big int
func randomBigIntArray(n int) []*big.Int {
	res := []*big.Int{}
	for i := 0; i < n; i++ {
		res = append(res, randomBigInt())
	}
	return res
}
