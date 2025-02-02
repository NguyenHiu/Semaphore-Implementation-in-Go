package semaphore

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

const (
	MIN_DEPTH = 1
	MAX_DEPTH = 10
)

// TODO: Add zkSNARK Verifier
type Semaphore struct {
	group      *LeanIMT
	nullifiers map[*big.Int]bool
}

type SemaphoreProof struct {
	merkleTreeDepth int
	merkleTreeRoot  *big.Int
	nullifier       *big.Int
	message         *big.Int
	scope           *big.Int
	points          [8]*big.Int
}

func NewSemaphore() *Semaphore {
	imt, _ := NewLeanIMT(poseidon.Hash, []*big.Int{})
	return &Semaphore{
		group: imt,
	}
}

func (s *Semaphore) AddMember(idc *big.Int) error {
	return s.group.Insert(idc)
}

func (s *Semaphore) UpdateMember(oldIdc, newIdc *big.Int) error {
	idx := s.group.IndexOf(oldIdc)
	if idx != -1 {
		return s.group.Update(newIdc, idx)
	} else {
		return fmt.Errorf("the provided identity commitment doesn't exist")
	}
}

func (s *Semaphore) RemoveMember(idc *big.Int, path []*big.Int) error {
	idx := s.group.IndexOf(idc)
	if idx != -1 {
		return s.group.Update(big.NewInt(0), idx)
	} else {
		return fmt.Errorf("the provided identity commitment doesn't exist")
	}
}

// TODO: Implement Generate Proof and Verify Proof methods
