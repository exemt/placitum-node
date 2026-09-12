package desired

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
)

// LiveConfName -- боевой файл ноды: тот самый, с которым работает мастер
// nginx и который читает воркер, считая своё присутствие.
const LiveConfName = "nginx.conf"

// LiveConfPath -- путь боевого файла в дереве ноды.
func LiveConfPath(confDir string) string {
	return filepath.Join(confDir, LiveConfName)
}

/*
Fingerprint -- отпечаток боевого конфига в том же виде, в каком его кладёт в
присутствие воркер: `md5:<hex>`, см. ngx_http_waf_presence_hash.

Второй хеш рядом с `config_hash` нужен потому, что это разные документы.
В поколении едет шаблон до подстановки, на диске лежит он же с путями ноды --
sha256 пака и md5 файла не совпадут никогда, и сравнение воркера с поколением
показывало бы расхождение на исправном флоте. Сравнивать воркера можно только
с тем, что агент положил на диск, а это -- здесь.
*/
func Fingerprint(body []byte) string {
	sum := md5.Sum(body)
	return "md5:" + hex.EncodeToString(sum[:])
}

/*
FingerprintFile -- то же по файлу, для старта: до первого apply на диске лежит
конфиг прошлого запуска, и воркеры работают именно по нему. Нечитаемый файл --
пустая строка: кадр без отпечатка честнее выдуманного, панель просто не
показывает колонку.
*/
func FingerprintFile(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return Fingerprint(body)
}
