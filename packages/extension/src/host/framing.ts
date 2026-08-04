import { Buffer } from 'node:buffer';

/**
 * Chrome caps host-to-browser native messages at 1 MB; larger frames kill the
 * host. The prefix is native byte order, which is little-endian on every
 * supported platform (unlike the warrend IPC, which is big-endian).
 */
const MAX_NATIVE_FRAME_BYTES = 1024 * 1024;

/** Encodes one native messaging frame: uint32 LE length + UTF-8 JSON. */
export function encodeNativeFrame(message: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(message), 'utf8');
  if (json.length >= MAX_NATIVE_FRAME_BYTES) {
    throw new RangeError('native messaging frame exceeds the 1 MB cap');
  }
  const frame = Buffer.allocUnsafe(4 + json.length);
  frame.writeUInt32LE(json.length, 0);
  json.copy(frame, 4);
  return frame;
}

/** Stateful decoder turning the stdin byte stream into JSON messages. */
export class NativeFrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): unknown[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const messages: unknown[] = [];
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32LE(0);
      if (length > MAX_NATIVE_FRAME_BYTES) {
        throw new RangeError('native messaging frame exceeds the 1 MB cap');
      }
      if (this.buffer.length < 4 + length) break;
      messages.push(JSON.parse(this.buffer.toString('utf8', 4, 4 + length)));
      this.buffer = this.buffer.subarray(4 + length);
    }
    return messages;
  }
}
