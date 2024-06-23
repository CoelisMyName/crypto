package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

type Test struct {
	*ecdh.PrivateKey
}

type AESSecretKey []byte

type ECPrivateKey struct {
	*ecdh.PrivateKey
}

type ECPublicKey struct {
	*ecdh.PublicKey
}

func GetDataWithPadding(data []byte, blockSize int) []byte {
	var paddingValue byte = 0xFF
	var lastByte byte = 0x00
	if len(data) > 0 {
		lastByte = data[len(data)-1]
		paddingValue = ^lastByte
	}

	dataWithPaddingSize := len(data) + (blockSize - (len(data) % blockSize))
	dataWithPadding := make([]byte, dataWithPaddingSize)
	copy(dataWithPadding, data)
	for i := len(data); i < dataWithPaddingSize; i++ {
		dataWithPadding[i] = paddingValue
	}
	return dataWithPadding
}

func GetDataWithoutPadding(dataWithPadding []byte, blockSize int) []byte {
	if len(dataWithPadding) == 0 {
		return make([]byte, 0)
	}
	lastByte := dataWithPadding[len(dataWithPadding)-1]
	for i := len(dataWithPadding) - 2; i >= 0; i-- {
		if dataWithPadding[i] == lastByte {
			continue
		}
		data := make([]byte, i+1)
		copy(data, dataWithPadding)
		return data
	}
	return make([]byte, 0)
}

func GetECPrivateKey() ECPrivateKey {
	curve := ecdh.P256()
	privateKey, _ := curve.GenerateKey(rand.Reader)
	return ECPrivateKey{privateKey}
}

func (key *ECPrivateKey) GetECPublicKey() ECPublicKey {
	publicKey := key.PublicKey()
	return ECPublicKey{publicKey}
}

func GetAESSecretKey() AESSecretKey {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func EncryptWithAESSecretKey(secretKeys AESSecretKey, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKeys)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	cipher := cipher.NewCBCEncrypter(block, iv)
	dataWithPadding := GetDataWithPadding(data, aes.BlockSize)
	encryptedData := make([]byte, len(iv)+len(dataWithPadding))
	copy(encryptedData, iv)
	cipher.CryptBlocks(encryptedData[len(iv):], dataWithPadding)
	return encryptedData, nil
}

func DecryptWithAESSecretKey(secretKeys AESSecretKey, encryptedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(secretKeys)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	copy(iv, encryptedData[0:aes.BlockSize])
	dataWithPadding := make([]byte, len(encryptedData)-aes.BlockSize)
	cipher := cipher.NewCBCDecrypter(block, iv)
	cipher.CryptBlocks(dataWithPadding, encryptedData[aes.BlockSize:])
	data := GetDataWithoutPadding(dataWithPadding, aes.BlockSize)
	return data, nil
}

func EncryptWithECPublicKey(publicKey ECPublicKey, data []byte) ([]byte, error) {
	encryptPrivateKey := GetECPrivateKey()
	encryptPublicKey := encryptPrivateKey.PublicKey()
	shared, err := encryptPrivateKey.ECDH(publicKey.PublicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(shared)
	var secretKey AESSecretKey = digest[:]
	aesEncryptedData, err := EncryptWithAESSecretKey(secretKey, data)
	if err != nil {
		return nil, err
	}
	encryptPublicKeyBytes := encryptPublicKey.Bytes()
	publicKeySize := len(encryptPublicKeyBytes)
	ecEncryptedData := make([]byte, 4+publicKeySize+len(aesEncryptedData))
	binary.LittleEndian.PutUint32(ecEncryptedData, uint32(publicKeySize))
	copy(ecEncryptedData[4:], encryptPublicKeyBytes)
	copy(ecEncryptedData[4+publicKeySize:], aesEncryptedData)
	return ecEncryptedData, nil
}

func DecryptWithECPrivateKey(privateKey ECPrivateKey, encryptedData []byte) ([]byte, error) {
	publicKeySize := binary.LittleEndian.Uint32(encryptedData[:4])
	encryptPublicKey, err := ecdh.P256().NewPublicKey(encryptedData[4 : 4+publicKeySize])
	if err != nil {
		return nil, err
	}
	shared, _ := privateKey.ECDH(encryptPublicKey)
	digest := sha256.Sum256(shared)
	var secretKey AESSecretKey = digest[:]
	decryptedData, err := DecryptWithAESSecretKey(secretKey, encryptedData[4+publicKeySize:])
	if err != nil {
		return nil, err
	}
	return decryptedData, nil
}
