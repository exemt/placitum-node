/*
 * Приёмник итогов фазы вместо агента.
 *
 * Модуль шлёт запись аудита датаграммой на unix-сокет и не ждёт ответа: промах
 * не двигает запрос. Настоящий агент кладёт её в ClickHouse и увозит объекты в
 * S3 -- для стенда это лишнее, а вот увидеть саму запись необходимо: превью,
 * секция archive и число записей на запрос иначе не проверяются ничем.
 *
 * Запускается в образе golang: своих зависимостей нет, только stdlib.
 */

package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	path := os.Getenv("SOCK")

	if path == "" {
		path = "/run/waf/agent.sock"
	}

	_ = os.Remove(path)

	conn, err := net.ListenPacket("unixgram", path)
	if err != nil {
		fmt.Printf("listen: %v\n", err)
		os.Exit(1)
	}

	// Модуль работает под своим пользователем: без прав на запись он молча
	// промахнётся мимо сокета, и стенд увидит пустой лог вместо записей.
	if err := os.Chmod(path, 0o777); err != nil {
		fmt.Printf("chmod: %v\n", err)
	}

	fmt.Printf("agent on %s\n", path)

	buf := make([]byte, 1<<20)

	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		fmt.Printf("REC %s\n", buf[:n])
	}
}
