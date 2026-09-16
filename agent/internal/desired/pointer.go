package desired

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	PackKey    = "policy/nginx-pack"
	BlobPrefix = "waf.blob."
)

type StoreEntry struct {
	Hash string `json:"hash"`
	Type string `json:"type"`
}

type NginxPack struct {
	V      int                   `json:"v"`
	Kind   string                `json:"kind"`
	Rev    int                   `json:"rev"`
	SHA256 string                `json:"sha256"`
	Prefix string                `json:"prefix"`
	Config string                `json:"config"`
	Store  map[string]StoreEntry `json:"store"`
	Pages  map[string]string     `json:"pages"`
	Blobs  int                   `json:"blobs"`
	Wrote  int                   `json:"wrote"`
	Reused int                   `json:"reused"`
	Bytes  int                   `json:"bytes"`
}

func ParsePack(raw []byte) (*NginxPack, error) {
	var p NginxPack
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("nginx-pack: %w", err)
	}

	if p.V != 1 || p.Kind != "nginx-pack" {
		return nil, fmt.Errorf("nginx-pack: unsupported v=%d kind=%q", p.V, p.Kind)
	}
	if p.Rev < 1 {
		return nil, fmt.Errorf("nginx-pack: rev must be positive")
	}
	if p.SHA256 == "" || !strings.HasPrefix(p.SHA256, "sha256:") {
		return nil, fmt.Errorf("nginx-pack: sha256 missing")
	}
	if p.Config == "" || !strings.HasPrefix(p.Config, "sha256:") {
		return nil, fmt.Errorf("nginx-pack: config hash missing")
	}
	if p.Prefix == "" {
		p.Prefix = BlobPrefix
	}
	if p.Store == nil {
		p.Store = map[string]StoreEntry{}
	}
	if p.Pages == nil {
		p.Pages = map[string]string{}
	}

	for name, hash := range p.Pages {
		if !safePageName(name) {
			return nil, fmt.Errorf("nginx-pack: unsafe page name %q", name)
		}
		if !strings.HasPrefix(hash, "sha256:") {
			return nil, fmt.Errorf("nginx-pack: page %q hash missing", name)
		}
	}

	return &p, nil
}

func safePageName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	return name != "."
}

func (p *NginxPack) BlobKey(hash string) string {
	return p.Prefix + strings.TrimPrefix(hash, "sha256:")
}

func (p *NginxPack) AllHashes() []string {
	seen := map[string]struct{}{}
	out := []string{p.Config}
	seen[p.Config] = struct{}{}

	for _, entry := range p.Store {
		if _, ok := seen[entry.Hash]; !ok {
			seen[entry.Hash] = struct{}{}
			out = append(out, entry.Hash)
		}
	}
	for _, hash := range p.Pages {
		if _, ok := seen[hash]; !ok {
			seen[hash] = struct{}{}
			out = append(out, hash)
		}
	}
	return out
}

func HashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
