package main

import (
	"CryptoHashCode/AES"
	"CryptoHashCode/Base64"
	"CryptoHashCode/DES"
	"CryptoHashCode/ECC"
	"CryptoHashCode/RSA"
	"CryptoHashCode/TilpleDES"
	"fmt"
)

func main() {
	/*
	*DES三元素：key,data,mode
	*
	 */
	key := "C1906032" //密钥//8位
	data := "只应多看了你一眼，好喜欢"
	ar, _ := DES.DesEnCrypt([]byte(data), []byte(key))
	ar1, _ := DES.DesDecrypt([]byte(ar), []byte(key))
	fmt.Println("DES解密后：", string(ar1))
	key1 := "19191918191919181919191819191918" //32位
	data1 := "只应多看了你一眼，好喜欢,好喜欢"
	br, _ := AES.AesEncrypt([]byte(data1), []byte(key1))
	br1, _ := AES.AesDecrypt(br, []byte(key1))
	fmt.Println("AES解密后：", string(br1))
	key2 := "202011122020111220201112" //24位
	data2 := "热爱山海，山海皆可平！"
	cr, _ := TilpleDES.SDesEnCrypt([]byte(data2), []byte(key2))
	cr1, _ := TilpleDES.SDesDeCrypt(cr, []byte(key2))
	fmt.Println("3DES解密后：", string(cr1))
	fmt.Println("============rsa算法============")
	data4 := "真心虽免费,但绝不廉价!"
	pri, err := RSA.GenerateKeysPem("小张")
	if err != nil {
		fmt.Println(err.Error())
	}

	//pri, err = RSA.CreateRSAKeys()
	//if err != nil {
	//	fmt.Println("rsa算法密钥生成失败！", err.Error())
	//}
	//err = RSA.GeneratePriPem(pri,"老张")
	//if err != nil {
	//	fmt.Println("失败1",err.Error())
	//	return
	//}
	//err = RSA.GeneratePubPem(pri.PublicKey,"小张")
	//if err != nil {
	//	fmt.Println("失败2",err.Error())
	//	return
	//}
	cipherText, err := RSA.RSAEncrypt(pri.PublicKey, []byte(data4))
	if err != nil {
		fmt.Println("rsa算法加密失败！", err.Error())
	}
	originalText, err := RSA.RSADecrypt(pri, []byte(cipherText))
	if err != nil {
		fmt.Println("rsa算法解密失败！", err.Error())
	}
	fmt.Println("rsa算法解密成功：", string(originalText))

	SignText, err := RSA.RSASign(pri, []byte(data4))
	if err != nil {
		fmt.Println("ras算法签名失败", err.Error())
	}
	data4 = "真心虽免费,但绝不廉价!"
	verifyResult, err := RSA.RSAVerify(pri.PublicKey, []byte(data4), SignText)
	if err != nil {
		fmt.Println("rsa签名验证失败!", err.Error())
	}
	if verifyResult {
		fmt.Println("恭喜！rsa签名验证成功！")
	} else {
		fmt.Println("抱歉，rsa签名验证失败!")
	}
	fmt.Println("========椭圆曲线数字签名算法私钥数字生成========")
	data5 := "快点好快点好！"
	prikey, err := ECC.GenerateKey()
	if err != nil {
		fmt.Println(err.Error)
	}
	r, s, err := ECC.ECDSASing(prikey, []byte(data5))
	if err != nil {
		fmt.Println(err.Error)
	}
	verify := ECC.ECDSAVerify(prikey.PublicKey, []byte(data5), r, s)
	if verify {
		fmt.Println("签名验证成功！")
	} else {
		fmt.Println("签名验证失败！")
	}
	fmt.Println("=========BASE64编解码=========")
	data6:="回眸一瞬间，及天下无敌！"
	encodeBytes :=Base64.Base64Encode([]byte(data6))
	decodeBytes :=Base64.Base64Decode(encodeBytes)
	fmt.Println(string(decodeBytes))
}
