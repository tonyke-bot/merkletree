package merkletree

import "hash"

type Options struct {
	SortLeaves bool
	SortPairs  bool
	HashObj    hash.Hash
}
