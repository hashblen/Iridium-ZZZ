package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"log"
	"math/big"
)

func removeMagic(data []byte) []byte {
	cut := data[7]
	data = data[10+2:]           // Removes token + four byte magic
	data = data[0 : len(data)-4] // Removes four byte magic at the end
	data = data[cut:]
	return data
}

func getHeaderAndBody(data []byte) ([]byte, []byte) {
	cut := data[7]
	data = data[10+2:]           // Removes token + two byte magic
	data = data[0 : len(data)-4] // Removes two byte magic at the end
	if len(data) < int(cut) {
		return data, nil
	}
	header := data[:cut]
	data = data[cut:]
	return header, data
}

func removeHeaderForParse(data []byte) []byte {
	//cut := data[8]
	//data = removeMagic(data)
	//return data[cut:]
	if binary.BigEndian.Uint32(data[0:4]) != 0x01234567 || binary.BigEndian.Uint32(data[len(data)-4:]) != 0x89ABCDEF {
		log.Println("ERROR MAGIC IS WRONG")
		return nil
	}
	data = data[4+2 : len(data)-4] // Magic + cmdid
	head_len := binary.BigEndian.Uint16(data[0:2])
	body_len := binary.BigEndian.Uint32(data[2:6])
	data = data[6:]
	return data[head_len : uint32(head_len)+body_len]
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

func newKey(seed uint64) []byte {
	generator := MT19937_64_new()
	generator.Seed(seed)

	// Generate the key.
	btes := make([]byte, 0, 4096)
	for i := 0; i < 4096; i += 8 {
		btes = binary.BigEndian.AppendUint64(btes, generator.NextULong())
	}

	return btes
}

func guess(filetime uint64, serverSeed uint64, depth int, data []byte, packetId uint16) (uint64, []byte) {
	//filetime = 0x1dcbf98a0159de2
	mixed := new(big.Int).SetUint64(0x701ce1722770000 + filetime)
	mask := new(big.Int).SetUint64(0x3fffffffffffffff)
	mixed.And(mixed, mask)
	M := new(big.Int).SetUint64(0x1AD7F29ABCAF48)
	product := new(big.Int).Mul(mixed, M)
	product.Rsh(product, 76)
	computed_seed := int32(product.Uint64())
	generator := NewRandom(computed_seed)
	for i := 0; i < depth; i++ {
		clientSeedHigh := generator.NextInt()
		clientSeed := uint64(uint32(computed_seed)) | (uint64(clientSeedHigh) << 32)

		aSeed := clientSeed ^ serverSeed
		key := newKey(aSeed)

		clone := make([]byte, len(data))
		copy(clone, data)
		xorDecrypt(clone, key)
		_, err := parseProto(packetId, clone)
		if err != nil {
			continue
		}
		log.Println("Found encryption key seed:", aSeed, "at depth", i)
		return aSeed, key
	}
	return 0, nil
}

func bruteforce(ms uint64, serverSeed uint64, data []byte, packetId uint16) (uint64, []byte) {
	filetime := int64(ms*10_000 + 116444736000000000)
	for i := int64(0); i < 30000; i++ {
		offset := func() int64 {
			if i%2 == 0 {
				return i / 2
			}
			return -(i - 1) / 2
		}()
		time := uint64(filetime + offset)
		seed, key := guess(time, serverSeed, 1, data, packetId)
		if key != nil {
			log.Println("Found for time", time)
			return seed, key
		}
	}
	log.Println("Unable to find the encryption key seed.")
	return 0, nil
}

func decrypt(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	b, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	return b, nil
}
