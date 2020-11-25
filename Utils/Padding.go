package Utils

import (
	"bytes"
)

//PKCS5尾部填充
func PKCS5Padding(data []byte, blockSize int) []byte {
	//if len(data)%blockSize==0 {
	//	return data
	//}
	padding := blockSize - len(data)%blockSize
	//fmt.Println(padding)
	//fmt.Println(byte(padding))
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}
func ClearPkcs5Padding(data []byte)[]byte  {
	clearsize:=int(data[len(data)-1])
	return data[:len(data)-clearsize]
}
//Zeros尾部填充
func ZerosPadding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, padding)
	return append(data, padText...)
}
func ClearZerosPadding(data []byte,blockSize int) []byte {
	size:= blockSize - len(data)%blockSize
	return data[:len(data)-size]
}
