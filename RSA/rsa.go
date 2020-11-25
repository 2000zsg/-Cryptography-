package RSA

import (
	"CryptoHashCode/Utils"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

const PSA_PRIVATE_KEY = "PSA_PrivateKey"
const RSA_PUBLIS_KEY = "RSA_PublicKey"

/*
*该函数用于生成一对RSA密钥对，并返回密钥对
 */
func createRSAKeys() (*rsa.PrivateKey, error) {
	//bit:位，二进制位，比特，rsa密钥的长度
	//byte:字节
	var bits int
	flag.IntVar(&bits, "b", 2048, "rsa密钥的长度")
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	//公钥：privateKey.PublicKey,
	//将私钥进行返回
	return privateKey, nil
}

/*
*生成一对密钥对，并以pem文件格式进行保存，及生成两个证书文件
 */
func GenerateKeysPem(file_name string)(*rsa.PrivateKey, error){
	//1、先生成私钥
	pri,err:= createRSAKeys()
	if err != nil {
		return nil,err
	}
	//2、生成私钥证书
	err = generatePriPem(pri, file_name)
	if err != nil {
		return nil,err
	}
	//3、生成公钥证书
	err=generatePubPem(pri.PublicKey,file_name)
	if err != nil {
		return nil,err
	}
	return pri,nil
}

/*  ==========将密钥储存到文件中，进行永久化存储============== */
//用于根据私钥生成一个私钥证书文件
func generatePriPem(pri *rsa.PrivateKey, file_name string) error {
	pirbytes := x509.MarshalPKCS1PrivateKey(pri)
	file, err := os.Create("rsa_pri" + file_name + ".pem")
	if err != nil {
		fmt.Println("出错了：", err.Error())
		return err
	}
	block := pem.Block{
		Type:    PSA_PRIVATE_KEY,
		Headers: nil,
		Bytes:   pirbytes,
	}
	return pem.Encode(file, &block)
}
// 用于根据公钥生成一个公钥证书文件
func generatePubPem(pub rsa.PublicKey, file_name string) error {
	pubBytees := x509.MarshalPKCS1PublicKey(&pub)
	file, err := os.Create("rsa_pub" + file_name + ".pem")
	if err != nil {
		//fmt.Println("出错了：",err.Error())
		return err
	}
	block := pem.Block{
		Type:    RSA_PUBLIS_KEY,
		Headers: nil,
		Bytes:   pubBytees,
	}
	return pem.Encode(file, &block)
}

//========①：公钥加密，私钥解密=============//
/*
*使用RSA算法进行加密,并返回加密后密文
 */
func RSAEncrypt(pub rsa.PublicKey, data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &pub, data)
}

//使用RSA算法对密文数据进行解密，返回解密后的明文
func RSADecrypt(pri *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pri, cipher)
}

//==============②私钥签名，公钥验签=========//
//signature:签名
func RSASign(pri *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := Utils.MD5Hash(data)
	return rsa.SignPKCS1v15(rand.Reader, pri, crypto.MD5, hashed)
}

//verify:验证
func RSAVerify(pub rsa.PublicKey, data []byte, sign []byte) (bool, error) {
	hashed := Utils.MD5Hash(data)
	verifyResult := rsa.VerifyPKCS1v15(&pub, crypto.MD5, hashed, sign)
	return verifyResult == nil, verifyResult
}
