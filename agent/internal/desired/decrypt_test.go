package desired

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// seal повторяет шифратор браузера (ux/src/crypto/seal.ts) и crypto-сервиса:
// версия, длина обёрнутого DEK big-endian, RSA-OAEP-SHA256, AES-256-GCM.
// Тест держит агента на этом формате: разъехавшийся разбор заголовка
// оставлял ноду с undecryptable на каждом поколении.
func seal(t *testing.T, pub *rsa.PublicKey, plain []byte) []byte {
	t.Helper()

	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	out := make([]byte, headerLen)
	out[0] = EnvelopeVersion
	binary.BigEndian.PutUint16(out[1:headerLen], uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, nil)
}

func TestDecryptEnvelope(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	plain := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	got, err := DecryptEnvelope(key, seal(t, &key.PublicKey, plain))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
}

func TestDecryptEnvelopeRejectsVersion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	blob := seal(t, &key.PublicKey, []byte("x"))
	blob[0] = 0x02

	if _, err := DecryptEnvelope(key, blob); err == nil {
		t.Fatal("expected version error")
	}
}

func TestDecryptEnvelopeRejectsTruncated(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	blob := seal(t, &key.PublicKey, []byte("x"))

	if _, err := DecryptEnvelope(key, blob[:headerLen+4]); err == nil {
		t.Fatal("expected truncation error")
	}
}
