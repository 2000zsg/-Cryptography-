package ECC

import (
	"CryptoHashCode/Utils"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

//================椭圆曲线数字签名算法私钥数字生成=================//
/*
*调用go语言的api生成一个ecdsa算法的私钥
 */
func GenerateKey() (*ecdsa.PrivateKey, error) {
	curve := elliptic.P256() //p256规则生成的一个曲线，Curve
	return ecdsa.GenerateKey(curve, rand.Reader)
}

//=========私钥签名，公钥验签================//
func ECDSASing(pri *ecdsa.PrivateKey, data []byte) (*big.Int, *big.Int, error) {
	hash := Utils.SHA256Hash(data)
	return ecdsa.Sign(rand.Reader, pri, hash)
}
func ECDSAVerify(pub ecdsa.PublicKey, data []byte, r *big.Int, s *big.Int) bool {
	hash := Utils.SHA256Hash(data)
	return ecdsa.Verify(&pub, hash, r, s)
}

