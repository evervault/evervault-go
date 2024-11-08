package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

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
	metadataOffsetLength                          = 0x02
	lengthOfTwoMetadataItems                      = 0x82
	lengthOfThreeMetadataItems                    = 0x83
	lengthOfFixedLengthStringWith2Bytes           = 0xa2
	encryptionOrigin                              = 0x09
	defaultRoleNameLength                         = 0xa0
	binaryRepresentationOfFourByteUnsignedInteger = 0xce
)

// DeriveKDFAESKey derives an AES key using the given public key and shared ECDH secret.
func DeriveKDFAESKey(publicKey, sharedECDHSecret []byte) ([]byte, error) {
	padding := []byte{0x00, 0x00, 0x00, 0x01}
	hash := sha256.New()
	hexEncodedEphemeralPublicKey := hex.EncodeToString(publicKey)
	ANS1EncodedPublicKey := p256ANS1Prefix + hexEncodedEphemeralPublicKey

	encodedANS1EncodedPublicKey, err := hex.DecodeString(ANS1EncodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error decoding public key %w", err)
	}

	concatenatedArray := append(append(sharedECDHSecret, padding...), encodedANS1EncodedPublicKey...)
	hash.Write(concatenatedArray)

	return hash.Sum(nil), nil
}

// CompressPublicKey compresses the given public key.
func CompressPublicKey(keyToCompress []byte) []byte {
	var prefix byte
	if keyToCompress[64]%2 == 0 {
		prefix = 0x02
	} else {
		prefix = 0x03
	}

	return append([]byte{prefix}, keyToCompress[1:33]...)
}

func CreateV2Aad(datatype datatypes.Datatype, ephemeralPublicKey, appPublicKey []byte) (bytes.Buffer, error) {
	const (
		shiftAmount = 4
	)

	dataTypeNumber := 0
	if datatype == datatypes.Number {
		dataTypeNumber = 1
	} else if datatype == datatypes.Boolean {
		dataTypeNumber = 2
	}

	versionNumber := 1

	var buffer bytes.Buffer

	b := byte(0x00 | (dataTypeNumber << shiftAmount) | versionNumber)

	err := binary.Write(&buffer, binary.LittleEndian, b)
	if err != nil {
		return buffer, fmt.Errorf("error writing buffer %w", err)
	}

	buffer.Write(ephemeralPublicKey)
	buffer.Write(appPublicKey)

	return buffer, nil
}

// EncryptValue encrypts the given value using AES encryption.
func EncryptValue(
	aesKey, ephemeralPublicKey, appPublicKey []byte, value, role string, datatype datatypes.Datatype,
) (string, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", fmt.Errorf("unable to create cipher %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("unable seed rand values %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("unable to encrypt block %w", err)
	}

	metadata, err := buildEncodedMetadata(role)
	if err != nil {
		return "", fmt.Errorf("unable to build metadata %w", err)
	}

	// Get the concatenated result as a byte slice
	metadataOffset := make([]byte, metadataOffsetLength)
	//nolint:gosec
	binary.LittleEndian.PutUint16(metadataOffset, uint16(len(metadata)))

	var buffer bytes.Buffer

	buffer.Write(metadataOffset)
	buffer.Write(metadata)
	buffer.WriteString(value)
	valueWithMetadata := buffer.Bytes()

	v2Aad, err := CreateV2Aad(datatype, ephemeralPublicKey, appPublicKey)
	if err != nil {
		return "", fmt.Errorf("unable to create v2 aad %w", err)
	}

	ciphertext := aesgcm.Seal(nil, nonce, valueWithMetadata, v2Aad.Bytes())

	return evFormat(ciphertext, nonce, ephemeralPublicKey, datatype), nil
}

func buildEncodedMetadata(role string) ([]byte, error) {
	var buffer bytes.Buffer

	// Binary representation of a fixed map with 2 or 3 items, followed by the key-value pairs.
	if role == "" {
		err := binary.Write(&buffer, binary.BigEndian, byte(lengthOfTwoMetadataItems))
		if err != nil {
			return nil, fmt.Errorf("error building metadata %w", err)
		}
	} else {
		err := binary.Write(&buffer, binary.BigEndian, byte(lengthOfThreeMetadataItems))
		if err != nil {
			return nil, fmt.Errorf("error building metadata %w", err)
		}

		err = encodeRole(&buffer, role)
		if err != nil {
			return nil, err
		}
	}

	err := encodeEncryptionOrigin(&buffer)
	if err != nil {
		return nil, err
	}

	err = encodeEncryptionTimestamp(&buffer)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func encodeEncryptionTimestamp(buffer *bytes.Buffer) error {
	// "et" (encryption timestamp) => current time
	// Binary representation for a fixed string of length 2, followed by `et`
	err := binary.Write(buffer, binary.BigEndian, byte(lengthOfFixedLengthStringWith2Bytes))
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	_, err = buffer.WriteString("et")
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	// Binary representation for a 4-byte unsigned integer (uint 32), followed by the epoch time
	err = binary.Write(buffer, binary.BigEndian, byte(binaryRepresentationOfFourByteUnsignedInteger))
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	// Get the current time and convert it to Unix timestamp (seconds since Jan 1, 1970)
	//nolint:gosec
	currentTime := uint32(time.Now().Unix())

	err = binary.Write(buffer, binary.BigEndian, currentTime)
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	return nil
}

func encodeEncryptionOrigin(buffer *bytes.Buffer) error {
	// "eo" (encryption origin) => 9 (Go SDK)
	// Binary representation for a fixed string of length 2, followed by `eo`
	err := binary.Write(buffer, binary.BigEndian, byte(lengthOfFixedLengthStringWith2Bytes))
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	_, err = buffer.WriteString("eo")
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	// Binary representation for the integer 9
	err = binary.Write(buffer, binary.BigEndian, byte(encryptionOrigin))
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	return nil
}

func encodeRole(buffer *bytes.Buffer, role string) error {
	// `dr` (data role) => role_name
	// Binary representation for a fixed string of length 2, followed by `dr`
	err := binary.Write(buffer, binary.BigEndian, byte(lengthOfFixedLengthStringWith2Bytes))
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	_, err = buffer.WriteString("dr")
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	// Binary representation for a fixed string of role name length, followed by the role name itself.
	err = binary.Write(buffer, binary.BigEndian, byte(defaultRoleNameLength|len(role)))
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	_, err = buffer.WriteString(role)
	if err != nil {
		return fmt.Errorf("error building metadata %w", err)
	}

	return nil
}

// evFormat formats the cipher text, IV, public key, and datatype into an "ev" formatted string.
func evFormat(cipherText, iv, publicKey []byte, datatype datatypes.Datatype) string {
	formattedString := "ev:QkTC:"

	if datatype != datatypes.String {
		if datatype == datatypes.Number {
			formattedString += "number:"
		} else {
			formattedString += "boolean:"
		}
	}

	formattedString += fmt.Sprintf("%s:%s:%s:$",
		base64EncodeStripped(iv),
		base64EncodeStripped(publicKey),
		base64EncodeStripped(cipherText),
	)

	return formattedString
}

// base64EncodeStripped encodes the given byte slice to base64 and removes padding characters.
func base64EncodeStripped(s []byte) string {
	encoded := base64.StdEncoding.EncodeToString(s)
	return strings.TrimRight(encoded, "=")
}
