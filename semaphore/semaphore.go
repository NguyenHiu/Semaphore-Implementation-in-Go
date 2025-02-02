package semaphore

import (
	"fmt"
	"math/big"

	"github.com/NguyenHiu/semaphore-implementation-in-go/leanIMT"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
)

const (
	MIN_DEPTH = 1
	MAX_DEPTH = 10
)

// Semaphore represents
type Semaphore struct {
	group      *leanIMT.LeanIMT
	nullifiers map[*big.Int]bool
	ccs        constraint.ConstraintSystem
	vk         groth16.VerifyingKey
	pk         groth16.ProvingKey
}

type SemaphoreProof struct {
	MerkleRoot *big.Int
	Nullifier  *big.Int
	Message    *big.Int
	Scope      *big.Int
}

// NewSemaphore returns a new instance of semaphore and setup the Semaphore circuit
func NewSemaphore() (*Semaphore, error) {
	// Init lean IMT using Mimc Hash
	imt, _ := leanIMT.NewLeanIMT(MimcHash, []*big.Int{})
	s := &Semaphore{
		group:      imt,
		nullifiers: make(map[*big.Int]bool),
	}

	// Setup semaphore circuit
	var err error
	s.ccs, s.pk, s.vk, err = SetupCircuit()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// AddMember inserts an identity commitment into the group
func (s *Semaphore) AddMember(idc *big.Int) error {
	return s.group.Insert(idc)
}

// UpdateMember updates an identity commitment to a new one in the group
func (s *Semaphore) UpdateMember(oldIdc, newIdc *big.Int) error {
	idx := s.group.IndexOf(oldIdc)
	if idx != -1 {
		return s.group.Update(newIdc, idx)
	} else {
		return fmt.Errorf("the provided identity commitment doesn't exist")
	}
}

// RemoveMember deletes an identity commitment from the group
func (s *Semaphore) RemoveMember(idc *big.Int, path []*big.Int) error {
	idx := s.group.IndexOf(idc)
	if idx != -1 {
		return s.group.Update(big.NewInt(0), idx)
	} else {
		return fmt.Errorf("the provided identity commitment doesn't exist")
	}
}

// GenerateMerkleProof returns merkle proof at `idx` leaf of the group tree
func (s *Semaphore) GenerateMerkleProof(idx int) (leanIMT.MerkleProof, error) {
	return s.group.GenerateProof(idx)
}

// VerifyProof returns true if the provided proof is correct
// and also prevents double signaling via the nullifier
func (s *Semaphore) VerifyProof(proof *groth16_bn254.Proof, sProof SemaphoreProof) error {
	// Check Message and Scope
	if !s.CheckMessage(sProof.Message) {
		return fmt.Errorf("invalid message")
	}
	if !s.CheckScope(sProof.Scope) {
		return fmt.Errorf("invalid scope")
	}

	// Check if merkle root is correct
	if sProof.MerkleRoot.Cmp(s.group.Root()) != 0 {
		return fmt.Errorf("invalid merkle root")
	}

	// Check if the provided nullifer is unused
	if s.nullifiers[sProof.Nullifier] {
		return fmt.Errorf("the provided nullifier is already used")
	}

	// Verify Proof
	err := VerifySemaphoreProof(s.vk, proof, sProof)
	if err != nil {
		return fmt.Errorf("failed to verify semaphore proof: %v", err)
	}

	// Set the nullifier as used
	s.nullifiers[sProof.Nullifier] = true

	return nil
}

// TODO Implement CheckMessage logic
// In real applications such as Voting, a valid message is one of the candidates
func (s *Semaphore) CheckMessage(message *big.Int) bool {
	return true
}

// TODO implement CheckScope logic
// In real applications such as Voting, the scope may be the identity of
// the current round, or the big integer format of the title string "Town President Election", etc.
func (s *Semaphore) CheckScope(scope *big.Int) bool {
	return true
}

// GetCss returns the constraint system of the semaphore circuit
func (s *Semaphore) GetCss() constraint.ConstraintSystem {
	return s.ccs
}

// GetProvingKey returns the groth16 proving key of the initialized semaphore circuit
func (s *Semaphore) GetProvingKey() groth16.ProvingKey {
	return s.pk
}

// GetVerifyingKey returns the groth16 verifying key of the initialized semaphore circuit
func (s *Semaphore) GetVerifyingKey() groth16.VerifyingKey {
	return s.vk
}
