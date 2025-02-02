package leanIMT

import (
	"fmt"
	"math"
	"math/big"
)

type LeanIMT struct {
	Nodes    [][]*big.Int
	HashFunc func([]*big.Int) (*big.Int, error)
}

// NewLeanIMT generates an instance of LeanIMT with provided leaves
func NewLeanIMT(hashFunc func([]*big.Int) (*big.Int, error), leaves []*big.Int) (*LeanIMT, error) {
	imt := &LeanIMT{
		Nodes:    [][]*big.Int{},
		HashFunc: hashFunc,
	}

	// Insert leaves
	if len(leaves) != 0 {
		err := imt.InsertMany(leaves)
		if err != nil {
			return nil, err
		}
	}

	return imt, nil
}

// Size returns the number of leaves in the tree
func (imt *LeanIMT) Size() int {
	if len(imt.Nodes) != 0 {
		return len(imt.Nodes[0])
	}
	return 0
}

// Depth returns the depth of the tree
func (imt *LeanIMT) Depth() int {
	return len(imt.Nodes) - 1
}

// Root returns the root of the tree
func (imt *LeanIMT) Root() *big.Int {
	return imt.Nodes[imt.Depth()][0]
}

// IndexOf returns index value of a leaf in the tree if it exists,
// else return -1
func (imt *LeanIMT) IndexOf(leaf *big.Int) int {
	for i := 0; i < len(imt.Nodes[0]); i++ {
		if imt.Nodes[0][i].Cmp(leaf) == 0 {
			return i
		}
	}
	return -1
}

// Insert adds a new leaf to the LeanIMT tree
func (imt *LeanIMT) Insert(leaf *big.Int) error {
	// If full --> add one more level
	if int(math.Ceil(math.Log2(float64(imt.Size()+1)))) > imt.Depth() {
		imt.Nodes = append(imt.Nodes, []*big.Int{})
	}

	node := leaf
	index := imt.Size()

	// Update tree
	for lv := 0; lv < imt.Depth(); lv++ {
		// Insert the node into the current level
		if index >= len(imt.Nodes[lv]) {
			imt.Nodes[lv] = append(imt.Nodes[lv], node)
		} else {
			imt.Nodes[lv][index] = node
		}

		// If the current node is left --> independent branch --> parents have the same value
		if index%2 != 0 {
			sibling := imt.Nodes[lv][index-1]

			var err error
			node, err = imt.HashFunc([]*big.Int{sibling, node})
			if err != nil {
				fmt.Println("hash err:", err)
				return err
			}
		}

		// Parent index
		index /= 2
	}

	// Update merkle root
	imt.Nodes[imt.Depth()] = []*big.Int{node}

	return nil
}

// InsertMany adds a batch of leaves to the tree
func (imt *LeanIMT) InsertMany(leaves []*big.Int) error {
	if len(leaves) == 0 {
		return fmt.Errorf("invalid leaves")
	}

	// Add more levels to accommodate all the leaves
	for int(math.Ceil(math.Log2(float64(imt.Size()+len(leaves))))) > imt.Depth() {
		imt.Nodes = append(imt.Nodes, []*big.Int{})
	}

	// Add all the leaves
	imt.Nodes[0] = append(imt.Nodes[0], leaves...)

	// Update parents hash
	for i := 0; i < imt.Depth(); i++ {
		for j := 0; j < len(imt.Nodes[i]); j += 2 {
			parentIdx := j / 2

			// Calculate parents hash
			var val *big.Int
			if j == len(imt.Nodes[i])-1 {
				val = imt.Nodes[i][j]
			} else {
				var err error
				val, err = imt.HashFunc([]*big.Int{imt.Nodes[i][j], imt.Nodes[i][j+1]})
				if err != nil {
					fmt.Println("hash err:", err)
					return err
				}
			}

			// Update or Insert new node
			if parentIdx >= len(imt.Nodes[i+1]) {
				imt.Nodes[i+1] = append(imt.Nodes[i+1], val)
			} else {
				imt.Nodes[i+1][parentIdx] = val
			}
		}
	}

	return nil
}

// Update helps to change value of a specific leaf in the tree
func (imt *LeanIMT) Update(newVal *big.Int, idx int) error {

	// Check if the updated node is valid
	if idx > imt.Size() {
		return fmt.Errorf("the updated node doesn't exist")
	}

	node := newVal
	index := idx

	for lv := 0; lv < imt.Depth(); lv++ {
		// Assign new value
		imt.Nodes[lv][index] = node

		// Re-hashing
		if index%2 != 0 || index != len(imt.Nodes[lv])-1 {
			var err error
			if index%2 == 0 {
				sibling := imt.Nodes[lv][index+1]
				node, err = imt.HashFunc([]*big.Int{node, sibling})
			} else {
				sibling := imt.Nodes[lv][index-1]
				node, err = imt.HashFunc([]*big.Int{sibling, node})
			}
			if err != nil {
				fmt.Println("hash err:", err)
				return err
			}
		}

		index /= 2
	}

	imt.Nodes[imt.Depth()] = []*big.Int{node}
	return nil
}

// UpdateMany helps to update values of a batch of leaves according indices
func (imt *LeanIMT) UpdateMany(leaves []*big.Int, indices []int) error {

	// Check that the updated params are valid
	if len(leaves) != len(indices) {
		return fmt.Errorf("len(leaves) != len(indices)")
	}

	// Check that the updated indices aren't duplicated
	modifiedIndicesMap := make(map[int]bool)
	for i := 0; i < len(indices); i++ {
		if _, ok := modifiedIndicesMap[indices[i]]; ok {
			return fmt.Errorf("duplicated indices")
		}
		modifiedIndicesMap[indices[i]] = true
	}

	// Update leaves
	modifiedIndicesMap = make(map[int]bool)
	for i := 0; i < len(indices); i++ {
		imt.Nodes[0][indices[i]] = leaves[i]
		modifiedIndicesMap[indices[i]/2] = true
	}

	// Update inner Nodes
	for i := 1; i <= imt.Depth(); i++ {
		newModifiedIndicesMap := make(map[int]bool)
		for key := range modifiedIndicesMap {
			leftNode := imt.Nodes[i-1][key*2]
			var val *big.Int
			if key*2 == len(imt.Nodes[i-1])-1 {
				val = leftNode
			} else {
				var err error
				rightNode := imt.Nodes[i-1][key*2+1]
				val, err = imt.HashFunc([]*big.Int{leftNode, rightNode})
				if err != nil {
					fmt.Println("hash err:", err)
					return err
				}
			}
			imt.Nodes[i][key] = val
			newModifiedIndicesMap[key/2] = true
		}
		modifiedIndicesMap = newModifiedIndicesMap
	}

	return nil
}

type MerkleProof struct {
	Node     *big.Int
	Root     *big.Int
	Path     []int // 0: left, 1: right
	Siblings []*big.Int
}

func (imt *LeanIMT) GenerateProof(idx int) (MerkleProof, error) {
	var proof MerkleProof

	if idx < 0 || idx > imt.Size() {
		return proof, fmt.Errorf("invalid index")
	}

	index := idx
	proof.Node = imt.Nodes[0][index]

	for i := 0; i < imt.Depth(); i++ {
		// Right
		if index%2 != 0 {
			proof.Path = append(proof.Path, 1)
			proof.Siblings = append(proof.Siblings, imt.Nodes[i][index-1])
		} else {
			// Left
			if index != len(imt.Nodes[i])-1 {
				proof.Path = append(proof.Path, 0)
				proof.Siblings = append(proof.Siblings, imt.Nodes[i][index+1])
			}
		}
		index /= 2
	}

	proof.Root = imt.Nodes[imt.Depth()][0]

	return proof, nil
}

// VerifyProof checks that a merkle proof belongs to a tree and is valid
func (imt *LeanIMT) VerifyProof(proof *MerkleProof) bool {
	if imt.Root().Cmp(proof.Root) != 0 {
		return false
	}

	root := proof.Node
	var err error
	for i := 0; i < len(proof.Path); i++ {
		if proof.Path[i] == 1 {
			root, err = imt.HashFunc([]*big.Int{proof.Siblings[i], root})
		} else {
			root, err = imt.HashFunc([]*big.Int{root, proof.Siblings[i]})
		}
		if err != nil {
			fmt.Println("hash err:", err)
			return false
		}
	}

	return root.Cmp(proof.Root) == 0
}
