package merkletree

import "bytes"

type node struct {
	Left   *node
	Right  *node
	Parent *node
	Hash   []byte
}

func (n *node) Equals(obj interface{}) bool {
	anotherNode, ok := obj.(node)
	if !ok {
		return false
	}

	return bytes.Equal(anotherNode.Hash, n.Hash)
}
