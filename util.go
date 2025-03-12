package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func removeMagic(data []byte) []byte {
	cut := data[7]
	data = data[10+2:]           // Removes token + four byte magic
	data = data[0 : len(data)-4] // Removes four byte magic at the end
	data = data[cut:]
	return data
}

func removeHeaderForParse(data []byte) []byte {
	cut := data[8]
	data = removeMagic(data)
	return data[cut:]
}

func xorDecrypt(data []byte, key []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
}

func reformData(data []byte) []byte {
	i := 0
	tokenSizeTotal := 0
	var messages [][]byte
	for i < len(data) {
		convId := data[i : i+4]
		remainingHeader := data[i+8 : i+28]
		contentLen := int(binary.LittleEndian.Uint32(data[i+24 : i+28]))
		content := data[i+28 : (i + 28 + contentLen)]

		formattedMessage := make([]byte, 24+contentLen)
		copy(formattedMessage, convId)
		copy(formattedMessage[4:], remainingHeader)
		copy(formattedMessage[24:], content)
		i += 28 + contentLen
		tokenSizeTotal += 4
		messages = append(messages, formattedMessage)
	}

	return bytes.Join(messages, []byte{})
}

func createXorPad(seed uint64) []byte {
	first := New()
	first.Seed(int64(seed))
	xorPad := make([]byte, 4096)

	for i := 0; i < 4096; i += 8 {
		value := first.Generate()
		binary.BigEndian.PutUint64(xorPad[i:i+8], uint64(value))
	}
	return xorPad
}

func decrypt(keypath string, ciphertext []byte) ([]byte, error) {
	rest, _ := os.ReadFile(keypath)
	// var ok bool
	var block *pem.Block
	var priv *rsa.PrivateKey
	for {
		block, rest = pem.Decode(rest)
		if block.Type == "RSA PRIVATE KEY" {
			k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				log.Println(err)
			} //else if priv, ok = k.(*rsa.PrivateKey); !ok {
			//	log.Println(fmt.Errorf("failed to parse private key"))
			//}
			priv = k
			break
		}
		if len(rest) == 0 {
			if priv == nil {
				log.Println(fmt.Errorf("failed to parse private key"))
			}
			break
		}
	}
	out := make([]byte, 0, 1024)
	for len(ciphertext) > 0 {
		chunkSize := 128
		if chunkSize > len(ciphertext) {
			chunkSize = len(ciphertext)
		}
		chunk := ciphertext[:chunkSize]
		ciphertext = ciphertext[chunkSize:]
		b, err := rsa.DecryptPKCS1v15(rand.Reader, priv, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
