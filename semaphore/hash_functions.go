package semaphore

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// MimcHash extends the `func([]*big.Int) ([]*big.Int, error)` function interface
// to be used in the semaphore hash function
// (currently, gnark doesn't support poseidon hash function)
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
