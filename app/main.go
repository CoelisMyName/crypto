package main

import (
	"crypto/rand"
	"encoding/hex"

	crypto "github.com/coel/x/crypto"
)

func main() {
	secretKey := crypto.GetAESSecretKey()
	data := make([]byte, 64)
	rand.Read(data)
	encryptedData, _ := crypto.EncryptWithAESSecretKey(secretKey, data)
	decryptedData, _ := crypto.DecryptWithAESSecretKey(secretKey, encryptedData)
	println(hex.EncodeToString(data))
	println(hex.EncodeToString(encryptedData))
	println(hex.EncodeToString(decryptedData))

	privateKey := crypto.GetECPrivateKey()
	publicKey := privateKey.GetECPublicKey()

	encryptedData, _ = crypto.EncryptWithECPublicKey(publicKey, data)
	decryptedData, _ = crypto.DecryptWithECPrivateKey(privateKey, encryptedData)
	println(hex.EncodeToString(encryptedData))
	println(hex.EncodeToString(decryptedData))
}
