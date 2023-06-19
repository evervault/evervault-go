package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"strings"

	"github.com/evervault/evervault-go/internal/datatypes"
)

const (
	nonceSize      = 12
	p256ANS1Prefix = "3082014b3082010306072a8648ce3d02013081f7020101302c06072a8648ce3d0101022100ffffffff000000010000" +
		"00000000000000000000ffffffffffffffffffffffff305b0420ffffffff00000001000000000000000000000000fffffffffffffffff" +
		"ffffffc04205ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b031500c49d360886e704936a6678e1139d" +
		"26b7819f7e900441046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0" +
		"f9e162bce33576b315ececbb6406837bf51f5022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63255102" +
		"0101034200"
)

func DeriveKDFAESKey(publicKey []byte, sharedECDHSecret []byte) []byte {
	padding := []byte{0x00, 0x00, 0x00, 0x01}
	hash := sha256.New()
	hexEncodedEphemeralPublicKey := hex.EncodeToString(publicKey)
	ANS1EncodedPublicKey := p256ANS1Prefix + hexEncodedEphemeralPublicKey

	encodedANS1EncodedPublicKey, err := hex.DecodeString(ANS1EncodedPublicKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	concatenatedArray := append(append(sharedECDHSecret, padding...), encodedANS1EncodedPublicKey...)
	hash.Write(concatenatedArray)

	return hash.Sum(nil)
}

func CompressPublicKey(keyToCompress []byte) []byte {
	var prefix byte
	if keyToCompress[64]%2 == 0 {
		prefix = 0x02
	} else {
		prefix = 0x03
	}

	return append([]byte{prefix}, keyToCompress[1:33]...)
}

func EncryptValue(
	aesKey []byte,
	ephemeralPublicKey []byte,
	appPublicKey []byte,
	value string,
	datatype datatypes.Datatype,
) string {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(value), appPublicKey)

	return evFormat(ciphertext, nonce, ephemeralPublicKey, datatype)
}

func evFormat(cipherText []byte, iv []byte, publicKey []byte, datatype datatypes.Datatype) string {
	formattedString := "ev:" + base64EncodeStripped([]byte("NOC")) + ":"

	if datatype != datatypes.String {
		if datatype == datatypes.Number {
			formattedString += "number:"
		} else {
			formattedString += "boolean:"
		}
	}

	formattedString += base64EncodeStripped(iv) +
		":" + base64EncodeStripped(publicKey) +
		":" + base64EncodeStripped(cipherText) + ":$"

	return formattedString
}

func base64EncodeStripped(s []byte) string {
	encoded := base64.StdEncoding.EncodeToString(s)

	return strings.TrimRight(encoded, "=")
}
