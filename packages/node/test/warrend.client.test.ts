import { Buffer } from 'node:buffer';
import { Duplex } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  FrameDecoder,
  WarrendClient,
  WarrendError,
  type WarrendState,
  encodeFrame,
} from '../src/index.js';

/** An in-memory Duplex standing in for the daemon socket. */
class FakeSocket extends Duplex {
  readonly written: Buffer[] = [];
  _read(): void {}
  _write(chunk: Buffer, _enc: BufferEncoding, cb: (error?: Error | null) => void): void {
    this.written.push(Buffer.from(chunk));
    cb();
  }
  /** Simulates the daemon sending bytes to the client. */
  feed(buffer: Buffer): void {
    this.push(buffer);
  }
  decodeWritten(): unknown[] {
    return new FrameDecoder().push(Buffer.concat(this.written));
  }
}

/** Flushes the event loop so a stream `data` event is delivered. */
const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

function makeClient() {
  const socket = new FakeSocket();
  const states: WarrendState[] = [];
  const errors: Array<{ kind: string; message: string }> = [];
  let closed = false;
  const client = new WarrendClient({
    connectFactory: () => socket,
    onState: (s) => states.push(s),
    onError: (e) => errors.push(e),
    onClose: () => {
      closed = true;
    },
  });
  return { socket, client, states, errors, closed: () => closed };
}

describe('WarrendClient', () => {
  it('writes configure and connect frames in wire shape', () => {
    const { socket, client } = makeClient();
    client.open();
    client.configure({ mnemonic: 'm', apiBase: 'https://a', serverPubkeyPin: 'p' });
    client.connect({ exitPubkeyHex: 'ab12' });

    expect(socket.decodeWritten()).toEqual([
      { type: 'configure', mnemonic: 'm', apiBase: 'https://a', serverPubkeyPin: 'p' },
      { type: 'connect', exitPubkeyHex: 'ab12' },
    ]);
  });

  it('dispatches state and error events from the daemon', async () => {
    const { socket, client, states, errors } = makeClient();
    client.open();
    socket.feed(encodeFrame({ type: 'state', state: 'connected' }));
    socket.feed(encodeFrame({ type: 'error', kind: 'tunnel', message: 'down' }));
    await tick();

    expect(states).toEqual(['connected']);
    expect(errors).toEqual([{ kind: 'tunnel', message: 'down' }]);
  });

  it('handles a state frame split across two reads', async () => {
    const { socket, client, states } = makeClient();
    client.open();
    const frame = encodeFrame({ type: 'state', state: 'reconnecting' });
    socket.feed(frame.subarray(0, 2));
    socket.feed(frame.subarray(2));
    await tick();
    expect(states).toEqual(['reconnecting']);
  });

  it('surfaces a malformed frame as a protocol error, not a throw', async () => {
    const { socket, client, errors } = makeClient();
    client.open();
    socket.feed(Buffer.from([0xff, 0xff, 0xff, 0xff]));
    await tick();
    expect(errors).toEqual([{ kind: 'protocol', message: 'malformed daemon frame' }]);
  });

  it('refuses to send before open and after close with a typed not_open error', () => {
    const { client } = makeClient();
    const before = (() => {
      try {
        client.disconnect();
      } catch (e) {
        return e;
      }
      throw new Error('expected a throw');
    })();
    expect(before).toBeInstanceOf(WarrendError);
    expect((before as WarrendError).code).toBe('not_open');
    client.open();
    client.close();
    expect(() => client.disconnect()).toThrow(WarrendError);
  });

  it('rejects a second open with a typed already_open error', () => {
    const { client } = makeClient();
    client.open();
    const err = (() => {
      try {
        client.open();
      } catch (e) {
        return e;
      }
      throw new Error('expected a throw');
    })();
    expect(err).toBeInstanceOf(WarrendError);
    expect((err as WarrendError).code).toBe('already_open');
  });

  it('a protocol error tears the session down fail-closed', async () => {
    const { socket, client, errors, closed } = makeClient();
    client.open();
    socket.feed(Buffer.from([0xff, 0xff, 0xff, 0xff]));
    await tick();

    expect(errors).toEqual([{ kind: 'protocol', message: 'malformed daemon frame' }]);
    // The decoder cannot resync past a corrupt frame, so keeping the socket
    // up would silently eat every further daemon event (including 'failed');
    // the session must die instead.
    expect(closed()).toBe(true);
    expect(socket.destroyed).toBe(true);
    expect(() => client.disconnect()).toThrow(WarrendError);
  });

  it('fires onClose and detaches when the daemon closes the socket', async () => {
    const { socket, client, closed } = makeClient();
    client.open();
    socket.destroy();
    await tick();

    expect(closed()).toBe(true);
    expect(() => client.disconnect()).toThrow(WarrendError);
  });

  it('redacts the raw socket error', async () => {
    const { socket, client, errors } = makeClient();
    client.open();
    socket.emit('error', new Error('connect ECONNREFUSED /tmp/warren-sdk-daemon.sock'));
    await tick();

    expect(errors[0]).toEqual({ kind: 'transport', message: 'socket error' });
  });

  it('a stale close from the previous session does not detach the new one', async () => {
    const sockets = [new FakeSocket(), new FakeSocket()];
    let next = 0;
    const client = new WarrendClient({ connectFactory: () => sockets[next++]! });
    client.open();
    client.close();
    client.open();
    // The first socket's close event lands only now, after the second session
    // is live; it must not null out the new socket.
    sockets[0]!.emit('close');
    await tick();

    client.disconnect();
    expect(new FrameDecoder().push(Buffer.concat(sockets[1]!.written))).toEqual([
      { type: 'disconnect' },
    ]);
  });

  it('a new session starts with a fresh frame decoder', async () => {
    const sockets = [new FakeSocket(), new FakeSocket()];
    let next = 0;
    const states: WarrendState[] = [];
    const client = new WarrendClient({
      connectFactory: () => sockets[next++]!,
      onState: (s) => states.push(s),
    });
    client.open();
    // Leave half a frame buffered in session 1, then tear it down.
    sockets[0]!.feed(encodeFrame({ type: 'state', state: 'connecting' }).subarray(0, 3));
    await tick();
    client.close();
    client.open();
    sockets[1]!.feed(encodeFrame({ type: 'state', state: 'connected' }));
    await tick();

    expect(states).toEqual(['connected']);
  });
});
