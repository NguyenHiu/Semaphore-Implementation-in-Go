package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const MAX_DEPTH = 10

type BinaryMerkleRoot struct {
	Leaf     frontend.Variable
	Depth    frontend.Variable
	Indices  [MAX_DEPTH]frontend.Variable
	Siblings [MAX_DEPTH]frontend.Variable
	Out      frontend.Variable `gnark:",public"`
}

func (circuit *BinaryMerkleRoot) Define(api frontend.API) error {
	nodes := [MAX_DEPTH + 1]frontend.Variable{circuit.Leaf}
	roots := [MAX_DEPTH]frontend.Variable{}
	root := frontend.Variable(0)
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	for i := 0; i < MAX_DEPTH; i++ {
		isDepth := api.IsZero(api.Sub(circuit.Depth, i))
		roots[i] = api.Mul(isDepth, nodes[i])
		root = api.Add(root, roots[i])
		leftChild := api.Select(circuit.Indices[i], circuit.Siblings[i], nodes[i])
		rightChild := api.Select(circuit.Indices[i], nodes[i], circuit.Siblings[i])
		hFunc.Reset()
		hFunc.Write(leftChild)
		hFunc.Write(rightChild)
		nodes[i+1] = hFunc.Sum()
	}

	isDepth := api.IsZero(api.Sub(circuit.Depth, MAX_DEPTH))
	circuit.Out = api.Add(root, api.Mul(isDepth, nodes[MAX_DEPTH]))
	return nil
}
