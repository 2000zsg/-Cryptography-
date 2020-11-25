package DES

import (
	"CryptoHashCode/Utils"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func DesEnCrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	originalBytes := Utils.PKCS5Padding(data, block.BlockSize())
	Mode := cipher.NewCBCEncrypter(block, key)
	dst := make([]byte, len(originalBytes))
	Mode.CryptBlocks(dst, originalBytes)
	fmt.Println("DES加密后：",string(dst))
	return dst, err
}
func DesDecrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	Mode := cipher.NewCBCDecrypter(block, key)
	dst := make([]byte, len(data))
	Mode.CryptBlocks(dst, data)
	dst = Utils.ClearPkcs5Padding(dst)
	return dst, nil
}
