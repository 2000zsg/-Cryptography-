package AES

import (
	"CryptoHashCode/Utils"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func AesEncrypt(data, key []byte) ([]byte, error) {
	//拿到key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//填充后的数据
	originalBytes := Utils.PKCS5Padding(data, block.BlockSize())
	//fmt.Println(originalBytes)
	//实例化加密模式
	mode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])
	//加密
	dst := make([]byte, len(originalBytes))
	mode.CryptBlocks(dst, originalBytes)
	//fmt.Println(dst)
	fmt.Println("AES加密后：", string(dst))
	return dst, nil
}
func AesDecrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	dst := make([]byte, len(data))
	blockMode.CryptBlocks(dst, data)
	//fmt.Println("解密后：",string(dst))
	dst = Utils.ClearPkcs5Padding(dst)
	return dst, nil
}
