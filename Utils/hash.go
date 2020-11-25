package Utils

import (
	"crypto/md5"
	"crypto/sha256"
)

/*
*md5hash计算
 */
func MD5Hash(data []byte) []byte {
	MD5Hash := md5.New()
	MD5Hash.Write(data)
	return MD5Hash.Sum(nil)
}

/*
*sha256hash计算
 */
func SHA256Hash(data []byte) []byte {
	SHA256Hash := sha256.New()
	SHA256Hash.Write(data)
	return SHA256Hash.Sum(nil)
}
