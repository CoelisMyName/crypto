package main

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/coel/x/crypto/utils"
)

func main() {
	secretKey := utils.GetAESSecretKey()
	data := make([]byte, 64)
	rand.Read(data)
	encryptedData, _ := utils.EncryptWithAESSecretKey(secretKey, data)
	decryptedData, _ := utils.DecryptWithAESSecretKey(secretKey, encryptedData)
	println(hex.EncodeToString(data))
	println(hex.EncodeToString(encryptedData))
	println(hex.EncodeToString(decryptedData))

	privateKey := utils.GetECPrivateKey()
	publicKey := privateKey.GetECPublicKey()

	encryptedData, _ = utils.EncryptWithECPublicKey(publicKey, data)
	decryptedData, _ = utils.DecryptWithECPrivateKey(privateKey, encryptedData)
	println(hex.EncodeToString(encryptedData))
	println(hex.EncodeToString(decryptedData))
}
