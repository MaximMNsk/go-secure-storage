package ccrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

func GetHash(text string, length int) (string, error) {
	if len(text) == 0 {
		return "", errors.New("text too short")
	}
	h := md5.New()
	h.Write([]byte(text))
	w := hex.EncodeToString(h.Sum(nil))
	if len(w) < length {
		return "", errors.New("result text too short")
	}
	return w[:length], nil
}

func Encrypt(key []byte, text []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, text, nil), nil
}

func Decrypt(key []byte, text []byte) ([]byte, error) {
	k := sha256.Sum256(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(text) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		text[:gcm.NonceSize()],
		text[gcm.NonceSize():],
		nil,
	)
}

func GlueKeys(key1, key2 []byte) ([]byte, error) {
	if len(key1) == 0 || len(key2) == 0 {
		return nil, errors.New("invalid keys")
	}
	maxLen := func(x int, y int) int {
		if x < y {
			return y
		}
		return x
	}(len(key1), len(key2))
	result := make([]byte, maxLen)
	for i := 0; i < maxLen; i++ {
		result[i] = key1[i] ^ key2[i]
	}
	return result, nil
}
