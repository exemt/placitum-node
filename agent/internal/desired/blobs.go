package desired

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/redis/go-redis/v9"
)

const blobTimeout = 15 * time.Second

func RedactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "<unparsable>"
	}
	return u.Redacted()
}

func OpenRedis(url string) (*redis.Client, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	opt.ReadTimeout = blobTimeout
	opt.WriteTimeout = blobTimeout
	opt.DialTimeout = blobTimeout
	return redis.NewClient(opt), nil
}

func FetchBlobs(ctx context.Context, rdb *redis.Client, p *NginxPack) (map[string][]byte, error) {
	hashes := p.AllHashes()
	if len(hashes) == 0 {
		return map[string][]byte{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, blobTimeout)
	defer cancel()

	keys := make([]string, len(hashes))
	for i, h := range hashes {
		keys[i] = p.BlobKey(h)
	}

	vals, err := rdb.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis mget: %w", err)
	}

	out := make(map[string][]byte, len(hashes))
	for i, raw := range vals {
		if raw == nil {
			return nil, fmt.Errorf("redis: missing %s", keys[i])
		}
		body, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("redis: %s: unexpected type %T", keys[i], raw)
		}
		buf := []byte(body)
		if HashOf(buf) != hashes[i] {
			return nil, fmt.Errorf("redis: %s hash mismatch", keys[i])
		}
		out[hashes[i]] = buf
	}

	return out, nil
}
