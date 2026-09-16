package desired

import (
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var storeRefRE = regexp.MustCompile(`store:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)

const PagesToken = "pages:"

const (
	liveDirName    = "live"
	pagesDirName   = "pages"
	stageDirName   = ".staging"
	stagePagesName = ".staging-pages"
	prevDirName    = ".prev"
	prevPagesName  = ".prev-pages"
)

func Apply(
	key *rsa.PrivateKey,
	p *NginxPack,
	blobs map[string][]byte,
	confDir string,
	storeDir string,
	nginxBin string,
) (string, error) {
	configBody, ok := blobs[p.Config]
	if !ok {
		return "", fmt.Errorf("apply: config blob missing")
	}

	refs := extractRefs(string(configBody))
	for _, uuid := range refs {
		if _, exists := p.Store[uuid]; !exists {
			return "", fmt.Errorf("apply: template references store:%s not in manifest", uuid)
		}
	}
	for uuid := range p.Store {
		found := false
		for _, r := range refs {
			if r == uuid {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("apply: manifest store entry %s not referenced in template", uuid)
		}
	}

	decrypted := make(map[string][]byte, len(p.Store))
	for uuid, entry := range p.Store {
		ciphertext, ok := blobs[entry.Hash]
		if !ok {
			return "", fmt.Errorf("apply: store %s blob missing", uuid)
		}
		plain, err := DecryptEnvelope(key, ciphertext)
		if err != nil {
			return "", fmt.Errorf("apply: store %s: %w", uuid, err)
		}
		decrypted[uuid] = plain
	}

	liveStore := filepath.Join(storeDir, liveDirName)
	livePages := filepath.Join(storeDir, pagesDirName)
	staging := filepath.Join(storeDir, stageDirName)
	stagingPages := filepath.Join(storeDir, stagePagesName)
	prevStore := filepath.Join(storeDir, prevDirName)
	prevPages := filepath.Join(storeDir, prevPagesName)

	cleanStaging := func() {
		_ = os.RemoveAll(staging)
		_ = os.RemoveAll(stagingPages)
	}

	if err := os.RemoveAll(staging); err != nil {
		return "", fmt.Errorf("apply: clean staging: %w", err)
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return "", fmt.Errorf("apply: mkdir staging: %w", err)
	}

	for uuid, plain := range decrypted {
		path := filepath.Join(staging, uuid)
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			cleanStaging()
			return "", fmt.Errorf("apply: write store %s: %w", uuid, err)
		}
	}

	if err := os.RemoveAll(stagingPages); err != nil {
		cleanStaging()
		return "", fmt.Errorf("apply: clean staging pages: %w", err)
	}
	if err := os.MkdirAll(stagingPages, 0o755); err != nil {
		cleanStaging()
		return "", fmt.Errorf("apply: mkdir staging pages: %w", err)
	}
	for name, hash := range p.Pages {
		body, ok := blobs[hash]
		if !ok {
			cleanStaging()
			return "", fmt.Errorf("apply: page %s blob missing", name)
		}
		if err := os.WriteFile(filepath.Join(stagingPages, name), body, 0o644); err != nil {
			cleanStaging()
			return "", fmt.Errorf("apply: write page %s: %w", name, err)
		}
	}

	confPath := filepath.Join(confDir, ".staging", "nginx.conf")
	confStaging := filepath.Dir(confPath)
	if err := os.MkdirAll(confStaging, 0o755); err != nil {
		cleanStaging()
		return "", fmt.Errorf("apply: mkdir conf staging: %w", err)
	}
	if err := os.WriteFile(
		confPath,
		[]byte(substitute(string(configBody), p, staging, stagingPages)),
		0o644,
	); err != nil {
		cleanStaging()
		_ = os.RemoveAll(confStaging)
		return "", fmt.Errorf("apply: write conf: %w", err)
	}

	cmd := exec.Command(nginxBin, "-t", "-c", confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanStaging()
		_ = os.RemoveAll(confStaging)
		return "", fmt.Errorf("apply: nginx -t failed: %w\n%s", err, string(out))
	}

	_ = os.RemoveAll(prevStore)
	_ = os.Rename(liveStore, prevStore)
	if err := os.Rename(staging, liveStore); err != nil {
		_ = os.Rename(prevStore, liveStore)
		cleanStaging()
		_ = os.RemoveAll(confStaging)
		return "", fmt.Errorf("apply: swap store: %w", err)
	}

	_ = os.RemoveAll(prevPages)
	_ = os.Rename(livePages, prevPages)
	if err := os.Rename(stagingPages, livePages); err != nil {
		_ = os.Rename(prevPages, livePages)
		_ = os.RemoveAll(liveStore)
		_ = os.Rename(prevStore, liveStore)
		_ = os.RemoveAll(confStaging)
		return "", fmt.Errorf("apply: swap pages: %w", err)
	}

	liveConf := LiveConfPath(confDir)
	prevConf := liveConf + ".prev"
	_ = os.Remove(prevConf)
	_ = os.Rename(liveConf, prevConf)
	if err := os.Rename(confPath, liveConf); err != nil {
		_ = os.Rename(prevConf, liveConf)
		_ = os.RemoveAll(liveStore)
		_ = os.Rename(prevStore, liveStore)
		_ = os.RemoveAll(livePages)
		_ = os.Rename(prevPages, livePages)
		return "", fmt.Errorf("apply: swap conf: %w", err)
	}
	_ = os.RemoveAll(confStaging)

	liveBody := []byte(substitute(string(configBody), p, liveStore, livePages))
	if err := os.WriteFile(liveConf, liveBody, 0o644); err != nil {
		return "", fmt.Errorf("apply: rewrite conf live paths: %w", err)
	}

	reloadCmd := exec.Command(nginxBin, "-s", "reload", "-c", liveConf)
	if out, err := reloadCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("apply: nginx reload failed: %w\n%s", err, string(out))
	}

	_ = os.RemoveAll(prevStore)
	_ = os.RemoveAll(prevPages)
	_ = os.Remove(prevConf)

	return Fingerprint(liveBody), nil
}

func substitute(text string, p *NginxPack, storeDir string, pagesDir string) string {
	for uuid := range p.Store {
		text = strings.ReplaceAll(text, "store:"+uuid, filepath.Join(storeDir, uuid))
	}
	return strings.ReplaceAll(text, PagesToken, pagesDir)
}

func extractRefs(text string) []string {
	matches := storeRefRE.FindAllStringSubmatch(text, -1)
	seen := map[string]struct{}{}
	var out []string
	for _, m := range matches {
		uuid := strings.ToLower(m[1])
		if _, ok := seen[uuid]; !ok {
			seen[uuid] = struct{}{}
			out = append(out, uuid)
		}
	}
	return out
}
