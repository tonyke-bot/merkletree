package merkletree

import (
	"encoding/hex"
	"hash"
)

func calculateHashOfTwoBytes(hashObj hash.Hash, a, b []byte) ([]byte, error) {
	hashObj.Reset()

	_, err := hashObj.Write(a)
	if err != nil {
		return nil, err
	}

	_, err = hashObj.Write(b)
	if err != nil {
		return nil, err
	}

	return hashObj.Sum(nil), nil
}

func hexEncode(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}
