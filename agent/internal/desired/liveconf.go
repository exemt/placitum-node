package desired

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
)

const LiveConfName = "nginx.conf"

func LiveConfPath(confDir string) string {
	return filepath.Join(confDir, LiveConfName)
}

func Fingerprint(body []byte) string {
	sum := md5.Sum(body)
	return "md5:" + hex.EncodeToString(sum[:])
}

func FingerprintFile(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return Fingerprint(body)
}
