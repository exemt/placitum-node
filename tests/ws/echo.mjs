/**
 * Защищаемое приложение стенда: WebSocket-эхо с инициативой.
 *
 * Эхо отвечает на кадры клиента, а по слову push-leak шлёт кадр сам -- без
 * запроса. Оба направления нужны потому, что политика у них разная: сообщения
 * клиента держат (gate), выдачу приложения обычно нет (monitor), и стенд
 * обязан уметь показать оба потока.
 */

import { createServer } from "node:http";

import { OP, accept, decodeFrames, encodeFrame } from "./ws.mjs";

const port = Number(process.env.PORT ?? 9001);

const server = createServer((req, res) => {
  res.writeHead(426, { "content-type": "text/plain" });
  res.end("upgrade required\n");
});

server.on("upgrade", (req, socket) => {
  const key = req.headers["sec-websocket-key"];

  if (!key) {
    socket.destroy();
    return;
  }

  const headers = [
    "HTTP/1.1 101 Switching Protocols",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Accept: ${accept(key)}`,
  ];

  const sub = req.headers["sec-websocket-protocol"];

  if (sub) {
    headers.push(`Sec-WebSocket-Protocol: ${sub.split(",")[0].trim()}`);
  }

  // Расширение "согласуется" на словах: сжимать эхо не умеет, но ответ 101
  // его подтверждает -- ровно так стенд видит, дошло ли предложение клиента
  // до приложения или модуль снял его на рукопожатии.
  const ext = req.headers["sec-websocket-extensions"] ?? "";

  if (/permessage-deflate/.test(ext)) {
    headers.push("Sec-WebSocket-Extensions: permessage-deflate");
  }

  socket.write(headers.join("\r\n") + "\r\n\r\n");

  let buf = Buffer.alloc(0);

  socket.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);

    const { frames, rest } = decodeFrames(buf);
    buf = rest;

    for (const f of frames) {
      if (f.opcode === OP.close) {
        socket.write(encodeFrame({ opcode: OP.close, payload: f.payload }));
        socket.end();
        return;
      }

      if (f.opcode === OP.ping) {
        socket.write(encodeFrame({ opcode: OP.pong, payload: f.payload }));
        continue;
      }

      if (f.opcode === OP.pong) {
        continue;
      }

      const text = f.payload.toString("utf8");

      // Инициатива приложения: ответ, которого клиент не просил, и в нём
      // утечка. Это тот кадр, который однажды должен ловить frame:s2c.
      if (text.includes("push-leak")) {
        socket.write(encodeFrame({
          opcode: OP.text,
          payload: Buffer.from(
            "You have an error in your SQL syntax; check the manual that " +
            "corresponds to your MySQL server version",
          ),
        }));
        continue;
      }

      // Эхо сохраняет опкод и фрагментацию: сообщение, пришедшее двумя
      // кадрами, уходит обратно двумя.
      socket.write(encodeFrame({
        fin: f.fin,
        opcode: f.opcode,
        payload: f.payload,
      }));
    }
  });

  socket.on("error", () => socket.destroy());
});

server.listen(port, () => {
  process.stdout.write(`ws echo on ${port}\n`);
});
