package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"sort"
)

type merkleTree struct {
	leaves   []*node
	rootNode *node
	opts     *Options
}

func New(leaves [][]byte, opts *Options) (*merkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("no leaves to build the tree")
	}

	node, leafNodes, err := constructTree(leaves, opts)
	if err != nil {
		return nil, err
	}

	tree := &merkleTree{
		leaves:   leafNodes,
		rootNode: node,
		opts:     opts,
	}
	return tree, err
}

func constructTree(leaves [][]byte, opts *Options) (root *node, leafNodes []*node, err error) {
	for _, leaf := range leaves {
		leafNodes = append(leafNodes, &node{Hash: leaf})
	}

	if opts.SortLeaves {
		sort.Slice(leafNodes, func(i, j int) bool {
			return bytes.Compare(leafNodes[i].Hash, leafNodes[j].Hash) < 0
		})
	}

	nodesInLayer := append([]*node(nil), leafNodes...)

	for len(nodesInLayer) > 1 {
		layerSize := len(nodesInLayer)
		newLayerSize := 0

		for i := 0; i < layerSize; i += 2 {
			var newNode *node

			if i+1 == layerSize {
				newNode = nodesInLayer[i]
			} else {
				newNode = &node{
					Left:  nodesInLayer[i],
					Right: nodesInLayer[i+1],
				}

				if opts.SortPairs && bytes.Compare(newNode.Left.Hash, newNode.Right.Hash) > 0 {
					newNode.Hash, err = calculateHashOfTwoBytes(
						opts.HashObj,
						newNode.Right.Hash,
						newNode.Left.Hash)
				} else {
					newNode.Hash, err = calculateHashOfTwoBytes(
						opts.HashObj,
						newNode.Left.Hash,
						newNode.Right.Hash)
				}

				if err != nil {
					return nil, nil, err
				}

				newNode.Left.Parent = newNode
				newNode.Right.Parent = newNode
			}

			nodesInLayer[newLayerSize] = newNode
			newLayerSize++
		}

		nodesInLayer = nodesInLayer[:newLayerSize]
	}

	return nodesInLayer[0], leafNodes, nil
}

func (m *merkleTree) GetLeaves() [][]byte {
	// Copy the leaves recursively
	result := make([][]byte, 0, len(m.leaves))

	for _, leaf := range m.leaves {
		result = append(result, append([]byte(nil), leaf.Hash...))
	}

	return result
}

func (m *merkleTree) Root() []byte {
	return append([]byte(nil), m.rootNode.Hash...)
}

func (m *merkleTree) HexRoot() string {
	return hexEncode(m.rootNode.Hash)
}

func (m *merkleTree) GetProof(leaf []byte) [][]byte {
	index := -1
	var leafNode *node
	for i, leafNode_ := range m.leaves {
		if bytes.Equal(leaf, leafNode_.Hash) {
			index = i
			leafNode = leafNode_
			break
		}
	}

	if index == -1 {
		return nil
	}

	var proof [][]byte

	for leafNode.Parent != nil {
		parent := leafNode.Parent

		if leafNode == parent.Left {
			proof = append(proof, parent.Right.Hash)
		} else {
			proof = append(proof, parent.Left.Hash)
		}

		leafNode = parent
	}

	return proof
}

func (m *merkleTree) GetHexProof(leaf []byte) []string {
	data := m.GetProof(leaf)
	if data == nil {
		return nil
	}

	result := make([]string, len(data))
	for i, h := range data {
		result[i] = hexEncode(h)
	}

	return result
}

func (m *merkleTree) String() string {
	return fmt.Sprintf("merkleTree(%s)", m.Root())
}

func (m *merkleTree) Inspect(indent string) string {
	return inspect(m.rootNode, indent, "")
}

func inspect(root *node, indent string, inspection string) string {
	inspection += fmt.Sprintf("%s%s\n", indent, hexEncode(root.Hash))
	if root.Left != nil {
		inspection = inspect(root.Left, indent+"  ", inspection)
	}

	if root.Right != nil {
		inspection = inspect(root.Right, indent+"  ", inspection)
	}

	return inspection
}

func VerifySorted(root []byte, leaf []byte, proof [][]byte, hashObj hash.Hash) bool {
	if root == nil || leaf == nil || proof == nil || hashObj == nil {
		return false
	}

	var err error
	calculatedRoot := leaf

	for _, hash := range proof {
		left := calculatedRoot
		right := hash

		if bytes.Compare(left, right) > 0 {
			tmp := left
			left = right
			right = tmp
		}

		calculatedRoot, err = calculateHashOfTwoBytes(hashObj, left, right)
		if err != nil {
			return false
		}
	}

	return bytes.Equal(calculatedRoot, root)
}
