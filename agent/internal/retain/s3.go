package retain

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	s3Algorithm  = "AWS4-HMAC-SHA256"
	s3Service    = "s3"
	s3TimeFormat = "20060102T150405Z"
	s3DateFormat = "20060102"
)

type s3Client struct {
	endpoint string
	region   string
	access   string
	secret   string
	http     *http.Client
}

type Uploader struct {
	c *s3Client
}

func (c *s3Client) put(ctx context.Context, bucket, key string, body []byte,
	tag string) (int64, error) {

	url := c.endpoint + "/" + bucket + "/" + uriEncode(key, false)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url,
		bytes.NewReader(body))
	if err != nil {
		return 0, err
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UTC()

	req.ContentLength = int64(len(body))
	req.Header.Set("X-Amz-Content-Sha256", hash)
	req.Header.Set("X-Amz-Date", now.Format(s3TimeFormat))

	if tag != "" {
		req.Header.Set("X-Amz-Tagging", tag)
	}

	c.sign(req, hash, now)

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	if resp.StatusCode/100 == 2 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return expiryOf(resp.Header.Get("X-Amz-Expiration")), nil
	}

	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	return 0, fmt.Errorf("retain: s3 %s: %s", resp.Status,
		strings.TrimSpace(string(detail)))
}

func expiryOf(header string) int64 {
	const field = `expiry-date="`

	start := strings.Index(header, field)
	if start < 0 {
		return 0
	}

	rest := header[start+len(field):]

	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return 0
	}

	ts, err := http.ParseTime(rest[:end])
	if err != nil {
		return 0
	}

	return ts.Unix()
}

func (c *s3Client) sign(req *http.Request, hash string, now time.Time) {
	date := now.Format(s3DateFormat)
	stamp := now.Format(s3TimeFormat)

	names := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	values := []string{req.URL.Host, hash, stamp}

	if tag := req.Header.Get("X-Amz-Tagging"); tag != "" {
		names = append(names, "x-amz-tagging")
		values = append(values, tag)
	}

	var canonical strings.Builder

	canonical.WriteString(req.Method)
	canonical.WriteString("\n")
	canonical.WriteString(req.URL.EscapedPath())
	canonical.WriteString("\n\n")

	for i, name := range names {
		canonical.WriteString(name)
		canonical.WriteString(":")
		canonical.WriteString(values[i])
		canonical.WriteString("\n")
	}

	signed := strings.Join(names, ";")

	canonical.WriteString("\n")
	canonical.WriteString(signed)
	canonical.WriteString("\n")
	canonical.WriteString(hash)

	sum := sha256.Sum256([]byte(canonical.String()))
	scope := date + "/" + c.region + "/" + s3Service + "/aws4_request"

	toSign := s3Algorithm + "\n" + stamp + "\n" + scope + "\n" +
		hex.EncodeToString(sum[:])

	key := hmacSHA256([]byte("AWS4"+c.secret), date)
	key = hmacSHA256(key, c.region)
	key = hmacSHA256(key, s3Service)
	key = hmacSHA256(key, "aws4_request")

	signature := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", s3Algorithm+
		" Credential="+c.access+"/"+scope+
		", SignedHeaders="+signed+
		", Signature="+signature)
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))

	return mac.Sum(nil)
}

func uriEncode(s string, encodeSlash bool) string {
	var out strings.Builder

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			out.WriteByte(c)

		case c == '/':
			if encodeSlash {
				out.WriteString("%2F")
			} else {
				out.WriteByte('/')
			}

		default:
			fmt.Fprintf(&out, "%%%02X", c)
		}
	}

	return out.String()
}
