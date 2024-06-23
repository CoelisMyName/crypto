package utils_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/coel/x/crypto/utils"
)

func GetTestData() []byte {
	data := make([]byte, 4096)
	rand.Read(data)
	return data
}

func TestAESEncryptionAndDecryption(t *testing.T) {
	data := GetTestData()
	secretKey := utils.GetAESSecretKey()
	utils.EncryptWithAESSecretKey(secretKey, data)
	encryptedData, err := utils.EncryptWithAESSecretKey(secretKey, data)
	if err != nil {
		t.Fatal(err)
	}
	decryptedData, err := utils.DecryptWithAESSecretKey(secretKey, encryptedData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decryptedData) {
		t.Fatalf("data and decryptedData are not the same\n\t%s\n\t%s\n", hex.EncodeToString(data), hex.EncodeToString(decryptedData))
	}
	if bytes.Equal(data, encryptedData) {
		t.Fatalf("data and encryptedData should not the same\n\t%s\n\t%s\n", hex.EncodeToString(data), hex.EncodeToString(encryptedData))
	}
	t.Logf("data %s\n", hex.EncodeToString(data))
	t.Logf("encryptedData %s\n", hex.EncodeToString(encryptedData))
	t.Logf("decryptedData %s\n", hex.EncodeToString(decryptedData))
}

func BenchmarkAESEncryption(b *testing.B) {
	b.StopTimer()
	data := GetTestData()
	secretKey := utils.GetAESSecretKey()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		utils.EncryptWithAESSecretKey(secretKey, data)
	}
}

func BenchmarkAESDecryption(b *testing.B) {
	b.StopTimer()
	data := GetTestData()
	secretKey := utils.GetAESSecretKey()
	encryptedData, _ := utils.EncryptWithAESSecretKey(secretKey, data)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		utils.DecryptWithAESSecretKey(secretKey, encryptedData)
	}
}

func TestECEncryptionAndDecryption(t *testing.T) {
	data := GetTestData()
	privateKey := utils.GetECPrivateKey()
	publicKey := privateKey.GetECPublicKey()
	encryptedData, err := utils.EncryptWithECPublicKey(publicKey, data)
	if err != nil {
		t.Fatal(err)
	}
	decryptedData, err := utils.DecryptWithECPrivateKey(privateKey, encryptedData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decryptedData) {
		t.Fatalf("data and decryptedData are not the same\n\t%s\n\t%s\n", hex.EncodeToString(data), hex.EncodeToString(decryptedData))
	}
	if bytes.Equal(data, encryptedData) {
		t.Fatalf("data and encryptedData should not the same\n\t%s\n\t%s\n", hex.EncodeToString(data), hex.EncodeToString(encryptedData))
	}
	t.Logf("data %s\n", hex.EncodeToString(data))
	t.Logf("encryptedData %s\n", hex.EncodeToString(encryptedData))
	t.Logf("decryptedData %s\n", hex.EncodeToString(decryptedData))
}

func BenchmarkECEncryption(b *testing.B) {
	b.StopTimer()
	data := GetTestData()
	privateKey := utils.GetECPrivateKey()
	publicKey := privateKey.GetECPublicKey()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		utils.EncryptWithECPublicKey(publicKey, data)
	}
}

func BenchmarkECDecryption(b *testing.B) {
	b.StopTimer()
	data := GetTestData()
	privateKey := utils.GetECPrivateKey()
	publicKey := privateKey.GetECPublicKey()
	encryptedData, _ := utils.EncryptWithECPublicKey(publicKey, data)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		utils.DecryptWithECPrivateKey(privateKey, encryptedData)
	}
}
