package desired

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const EnvelopeVersion = 0x01

const headerLen = 3

const (
	nonceSize = 12
	tagSize   = 16
	dekSize   = 32
)

func DecryptEnvelope(key *rsa.PrivateKey, envelope []byte) ([]byte, error) {
	if len(envelope) < headerLen {
		return nil, fmt.Errorf("decrypt: envelope too short")
	}

	if envelope[0] != EnvelopeVersion {
		return nil, fmt.Errorf("decrypt: unsupported envelope version %d", envelope[0])
	}

	dekLen := int(binary.BigEndian.Uint16(envelope[1:headerLen]))
	if dekLen <= 0 || len(envelope) < headerLen+dekLen+nonceSize+tagSize {
		return nil, fmt.Errorf("decrypt: truncated envelope (dekLen=%d, total=%d)", dekLen, len(envelope))
	}

	wrappedDEK := envelope[headerLen : headerLen+dekLen]
	rest := envelope[headerLen+dekLen:]

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrappedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: unwrap dek: %w", err)
	}

	if len(dek) != dekSize {
		return nil, fmt.Errorf("decrypt: unexpected dek length %d", len(dek))
	}

	nonce := rest[:nonceSize]
	ciphertext := rest[nonceSize:]

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("decrypt: aes: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt: gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: open: %w", err)
	}

	return plaintext, nil
}
