package merkletree_test

import (
	"encoding/hex"
	"testing"

	"github.com/THaGKi9/merkletree"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func sha3Hash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func hexToByte(hexString string) []byte {
	data, _ := hex.DecodeString(hexString[2:])
	return data
}

func TestNewMerkleTree_CompleteTree(t *testing.T) {
	leaves := [][]byte{
		sha3Hash([]byte("a")),
		sha3Hash([]byte("b")),
		sha3Hash([]byte("c")),
		sha3Hash([]byte("d")),
	}

	tree, err := merkletree.New(leaves, &merkletree.Options{
		HashObj: sha3.NewLegacyKeccak256(),
	})

	require.NoError(t, err)
	require.NotNil(t, tree)
	require.Equal(t, tree.HexRoot(), "0x68203f90e9d07dc5859259d7536e87a6ba9d345f2552b5b9de2999ddce9ce1bf")

	require.ElementsMatch(t, tree.GetProof(leaves[0]), [][]byte{
		hexToByte("0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510"),
		hexToByte("0xd253a52d4cb00de2895e85f2529e2976e6aaaa5c18106b68ab66813e14415669"),
	})
	require.ElementsMatch(t, tree.GetProof(leaves[1]), [][]byte{
		hexToByte("0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"),
		hexToByte("0xd253a52d4cb00de2895e85f2529e2976e6aaaa5c18106b68ab66813e14415669"),
	})
	require.ElementsMatch(t, tree.GetProof(leaves[2]), [][]byte{
		hexToByte("0xf1918e8562236eb17adc8502332f4c9c82bc14e19bfc0aa10ab674ff75b3d2f3"),
		hexToByte("0x805b21d846b189efaeb0377d6bb0d201b3872a363e607c25088f025b0c6ae1f8"),
	})
	require.ElementsMatch(t, tree.GetProof(leaves[3]), [][]byte{
		hexToByte("0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2"),
		hexToByte("0x805b21d846b189efaeb0377d6bb0d201b3872a363e607c25088f025b0c6ae1f8"),
	})
}

func TestNewMerkleTree_OddNodes(t *testing.T) {
	leaves := [][]byte{
		sha3Hash([]byte("a")),
		sha3Hash([]byte("b")),
		sha3Hash([]byte("c")),
	}

	tree, err := merkletree.New(leaves, &merkletree.Options{
		HashObj:   sha3.NewLegacyKeccak256(),
		SortPairs: true,
	})

	require.ElementsMatch(t, tree.GetProof(leaves[0]), [][]byte{
		hexToByte("0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510"),
		hexToByte("0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2"),
	})
	require.ElementsMatch(t, tree.GetProof(leaves[1]), [][]byte{
		hexToByte("0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb"),
		hexToByte("0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2"),
	})
	require.ElementsMatch(t, tree.GetProof(leaves[2]), [][]byte{
		hexToByte("0x805b21d846b189efaeb0377d6bb0d201b3872a363e607c25088f025b0c6ae1f8"),
	})

	require.NoError(t, err)
	require.NotNil(t, tree)
	require.Equal(t, tree.HexRoot(), "0x5842148bc6ebeb52af882a317c765fccd3ae80589b21a9b8cbf21abb630e46a7")
}
