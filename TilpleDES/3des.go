package TilpleDES

import (
	"CryptoHashCode/Utils"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func SDesEnCrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	originBytes := Utils.PKCS5Padding(data, block.BlockSize())
	Mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	dst := make([]byte, len(originBytes))
	Mode.CryptBlocks(dst, originBytes)
	fmt.Println("3DES加密后：", string(dst))
	return dst, nil
}
func SDesDeCrypt(data, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	Mode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	dst := make([]byte, len(data))
	Mode.CryptBlocks(dst, data)
	dst = Utils.ClearPkcs5Padding(dst)
	return dst, nil
}
