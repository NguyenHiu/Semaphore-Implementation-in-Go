package semaphore

import (
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

const MAX_INT64 = 1000

// randomBigInt generates a random big integer
func randomBigInt() *big.Int {
	return big.NewInt(rand.Int64N(MAX_INT64))
}

// randomBigIntArray generates an array of random big int
func randomBigIntArray(n int) []*big.Int {
	res := []*big.Int{}
	for i := 0; i < n; i++ {
		res = append(res, randomBigInt())
	}
	return res
}

// randomSemaphoreProof returns a semaphore proof with random values based of the
// provided `root` and `secret`
func randomSemaphoreProof(root *big.Int, secret *big.Int, t *testing.T) SemaphoreProof {
	message := randomBigInt()
	scope := randomBigInt()
	nullifier, err := MimcHash([]*big.Int{scope, secret})
	require.NoError(t, err)
	sProof := SemaphoreProof{
		MerkleRoot: root,
		Message:    message,
		Scope:      scope,
		Nullifier:  nullifier,
	}
	return sProof
}

func TestSemaphoreCircuit(t *testing.T) {
	// Init semaphore group
	s, err := NewSemaphore()
	require.NoError(t, err)

	n := 5
	// Random `n` secrets
	secrets := randomBigIntArray(n)

	// Compute identity commitmnets for these secrets
	idcs := []*big.Int{}
	for i := 0; i < n; i++ {
		idc, err := MimcHash([]*big.Int{secrets[i]})
		require.NoError(t, err)
		idcs = append(idcs, idc)
	}

	// Add these identity commitments as members of the group
	for i := 0; i < n; i++ {
		err := s.AddMember(idcs[i])
		require.NoError(t, err)
	}

	// Random user at idx
	idx := rand.IntN(n)
	secret := secrets[idx]

	// Prepare circuit inputs for user at idx
	sProof := randomSemaphoreProof(s.group.Root(), secret, t)
	merkleProof, err := s.GenerateMerkleProof(idx)
	require.NoError(t, err)

	// Generate proof for user at idx
	proof, err := GenerateSemaphoreProof(
		s.GetCss(),
		s.GetProvingKey(),
		secret,
		merkleProof,
		sProof,
	)
	require.NoError(t, err)
	require.NotEmpty(t, proof)

	// Error Message
	errSProof := SemaphoreProof{
		MerkleRoot: sProof.MerkleRoot,
		Nullifier:  sProof.Nullifier,
		Scope:      sProof.Scope,
		Message:    big.NewInt(MAX_INT64 + 1), // invalid message
	}
	err = s.VerifyProof(proof, errSProof)
	require.Error(t, err)

	// Error Scope
	errSProof = SemaphoreProof{
		MerkleRoot: sProof.MerkleRoot,
		Nullifier:  sProof.Nullifier,
		Scope:      big.NewInt(MAX_INT64 + 1), // invalid message,
		Message:    sProof.Message,
	}
	err = s.VerifyProof(proof, errSProof)
	require.Error(t, err)

	// Error Root
	errSProof = SemaphoreProof{
		MerkleRoot: new(big.Int),
		Nullifier:  sProof.Nullifier,
		Scope:      sProof.Scope,
		Message:    sProof.Message,
	}
	err = s.VerifyProof(proof, errSProof)
	require.Error(t, err)

	// Verify proof
	err = s.VerifyProof(proof, sProof)
	require.NoError(t, err)

	// Error when double signaling
	err = s.VerifyProof(proof, sProof)
	require.Error(t, err)
	require.ErrorContains(t, err, "the provided nullifier is already used")
}
