/*
 * Клиент архива: PutObject и подпись SigV4, больше ничего.
 *
 * Своя подпись вместо SDK — решение того же порядка, что и свой RESP выше.
 * Объектов здесь ровно один запрос из сорока с лишним, а SDK приносит
 * разрешение регионов, цепочки реквизитов, ретраи со своим представлением о
 * тайм-аутах и полсотни транзитивных модулей. Из этого нужна одна функция на
 * пять HMAC — она ниже и написана.
 *
 * Path-style адресация (/bucket/key) выбрана как единственная, работающая и с
 * MinIO, и с Ceph RGW, и с AWS. Virtual-host style у первых двух требует
 * DNS-обвязки, которой на краю обычно нет.
 */

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

// Uploader — тот же PutObject, что у воркера архива. Вынесен, чтобы замер
// потолка писать тем же кодом, а не «похожим» клиентом с другими тайм-аутами.
type Uploader struct {
	c *s3Client
}

func NewUploader(cfg Config) *Uploader {
	cfg.normalize()

	return &Uploader{c: &s3Client{
		endpoint: strings.TrimRight(cfg.S3.Endpoint, "/"),
		region:   cfg.S3.Region,
		access:   cfg.S3.Access,
		secret:   cfg.S3.Secret,
		http: &http.Client{
			Timeout: cfg.OpTimeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: cfg.Workers,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}}
}

func (u *Uploader) Put(ctx context.Context, bucket, key string, body []byte, tag string) (int64, error) {
	return u.c.put(ctx, bucket, key, body, tag)
}

/*
 * put кладёт объект и тегирует его сроком хранения. Тег едет тем же запросом:
 * в составе PutObject тегирование бесплатно, отдельным PutObjectTagging — это
 * второй round-trip и окно, в котором объект живёт без правила удаления.
 *
 * Возвращает момент, до которого объект жив: хранилище называет его в
 * x-amz-expiration тем же ответом, по своему же lifecycle-правилу. Спрашивать
 * его всё равно надо -- правило в бакете могло не совпасть с тегом или не
 * существовать вовсе, -- а знать срок нужно тому, кто через месяц откроет
 * карточку инцидента.
 */
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

	// Тело ошибки S3 — XML с кодом и сообщением; разбирать его незачем, а
	// показать в журнале стоит: без него «403» не отличить от «нет бакета».
	detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	return 0, fmt.Errorf("retain: s3 %s: %s", resp.Status,
		strings.TrimSpace(string(detail)))
}

/*
 * expiryOf разбирает x-amz-expiration:
 *
 *     expiry-date="Wed, 21 Oct 2026 00:00:00 GMT", rule-id="waf-retain-30d"
 *
 * Имя правила не берётся: оно из чужой конфигурации и в записи аудита никому
 * ничего не объясняет, а срок хранения там и так есть.
 *
 * Ноль — срока нет: правило удаления в бакете не заведено, либо заголовок в
 * незнакомой форме. Соврать о сроке хуже, чем его не знать: карточка на нём
 * решает, идти ли за объектом вообще.
 */
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

	// Дату ставит хранилище, а не мы: у AWS и MinIO это RFC 1123 в GMT, но
	// ParseTime разберёт и две старые формы, которые допускает HTTP.
	ts, err := http.ParseTime(rest[:end])
	if err != nil {
		return 0
	}

	return ts.Unix()
}

// sign — SigV4 над уже собранным запросом. Подписываются только те заголовки,
// которые мы сами и поставили: чем короче список подписанных, тем меньше
// поводов у прокси между нами и хранилищем сломать подпись.
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

// uriEncode — кодирование по правилам SigV4. S3 — единственный сервис, где путь
// в каноническом запросе не кодируется повторно, поэтому кодировать его надо
// ровно один раз и ровно так же, как он уедет в строке запроса.
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
