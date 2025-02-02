package semaphore

import (
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupSemaphoreCircuit(t *testing.T) {
	s, err := NewSemaphore()
	require.NoError(t, err)
	require.NotEmpty(t, s)
	require.NotEmpty(t, s.ccs)
	require.NotEmpty(t, s.pk)
	require.NotEmpty(t, s.vk)
}

// DummyIDC, Dummy Identity Commitment -
func DummyIDC(secret *big.Int, t *testing.T) *big.Int {
	res, err := MimcHash([]*big.Int{secret})
	require.NoError(t, err)
	return res
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

	// Verify proof
	err = s.VerifyProof(proof, sProof)
	require.NoError(t, err)

	// Use the same proof to verify again
	// ==> Try to double signaling
	err = s.VerifyProof(proof, sProof)
	require.Error(t, err)
	require.ErrorContains(t, err, "the provided nullifier is already used")
}
