package main

// Сборка процесса: образ передаёт её в бинарь при сборке
// (-ldflags "-X main.version=… -X main.revision=…"); без этого -- dev/unknown.
// Видна в строке старта и в кадре присутствия.
var (
	version  = "dev"
	revision = "unknown"
)
