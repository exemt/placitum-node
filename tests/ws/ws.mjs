/**
 * Минимальный RFC 6455: рукопожатие и кадрирование, без зависимостей.
 *
 * Своя реализация, а не библиотека, ровно потому, что стенд проверяет байты:
 * фрагментацию, маскирование, опкоды и порядок. Библиотека собрала бы
 * сообщение за нас и спрятала именно то, что здесь и проверяется.
 */

import { createHash, randomBytes } from "node:crypto";

export const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

export const OP = {
  cont: 0x0,
  text: 0x1,
  binary: 0x2,
  close: 0x8,
  ping: 0x9,
  pong: 0xa,
};

export const opcodeName = Object.fromEntries(
  Object.entries(OP).map(([k, v]) => [v, k]),
);

export function accept(key) {
  return createHash("sha1").update(key + GUID).digest("base64");
}

export function clientKey() {
  return randomBytes(16).toString("base64");
}

/**
 * Кадр в байты. mask=true обязателен для кадров клиента: сервер обязан
 * закрыть соединение на немаскированном кадре, и стенд не должен полагаться
 * на то, что прокси это простит.
 */
export function encodeFrame({ fin = true, opcode, payload = Buffer.alloc(0), mask = false }) {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const head = [];

  head.push((fin ? 0x80 : 0) | opcode);

  const maskBit = mask ? 0x80 : 0;

  if (data.length < 126) {
    head.push(maskBit | data.length);
  } else if (data.length < 65536) {
    head.push(maskBit | 126, (data.length >> 8) & 0xff, data.length & 0xff);
  } else {
    const len = BigInt(data.length);
    head.push(maskBit | 127);
    for (let i = 7n; i >= 0n; i--) {
      head.push(Number((len >> (8n * i)) & 0xffn));
    }
  }

  if (!mask) {
    return Buffer.concat([Buffer.from(head), data]);
  }

  const key = randomBytes(4);
  const masked = Buffer.allocUnsafe(data.length);

  for (let i = 0; i < data.length; i++) {
    masked[i] = data[i] ^ key[i % 4];
  }

  return Buffer.concat([Buffer.from(head), key, masked]);
}

/**
 * Разбор потока в кадры. Возвращает готовые кадры и остаток буфера: TCP
 * границ кадров не хранит, и стенд обязан собирать их сам -- ровно так же,
 * как это придётся делать обработчику апгрейда в модуле.
 */
export function decodeFrames(buf) {
  const frames = [];
  let off = 0;

  for (;;) {
    if (buf.length - off < 2) {
      break;
    }

    const b0 = buf[off];
    const b1 = buf[off + 1];
    const fin = (b0 & 0x80) !== 0;
    const opcode = b0 & 0x0f;
    const masked = (b1 & 0x80) !== 0;

    let len = b1 & 0x7f;
    let pos = off + 2;

    if (len === 126) {
      if (buf.length - pos < 2) break;
      len = buf.readUInt16BE(pos);
      pos += 2;
    } else if (len === 127) {
      if (buf.length - pos < 8) break;
      len = Number(buf.readBigUInt64BE(pos));
      pos += 8;
    }

    let key = null;

    if (masked) {
      if (buf.length - pos < 4) break;
      key = buf.subarray(pos, pos + 4);
      pos += 4;
    }

    if (buf.length - pos < len) {
      break;
    }

    const payload = Buffer.from(buf.subarray(pos, pos + len));

    if (key) {
      for (let i = 0; i < payload.length; i++) {
        payload[i] ^= key[i % 4];
      }
    }

    frames.push({ fin, opcode, masked, payload });
    off = pos + len;
  }

  return { frames, rest: buf.subarray(off) };
}

/** Сборка сообщения из фрагментов: opcode берётся у первого кадра. */
export function assemble(frames) {
  const out = [];
  let opcode = null;
  let parts = [];

  for (const f of frames) {
    if (f.opcode === OP.close || f.opcode === OP.ping || f.opcode === OP.pong) {
      out.push({ opcode: f.opcode, payload: f.payload, control: true });
      continue;
    }

    if (f.opcode !== OP.cont) {
      opcode = f.opcode;
      parts = [];
    }

    parts.push(f.payload);

    if (f.fin) {
      out.push({ opcode, payload: Buffer.concat(parts), control: false });
      parts = [];
    }
  }

  return out;
}
