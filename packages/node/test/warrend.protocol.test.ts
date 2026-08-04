import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';
import {
  FrameDecoder,
  configureRequest,
  connectRequest,
  disconnectRequest,
  encodeFrame,
  parseEvent,
} from '../src/index.js';

describe('frame codec', () => {
  it('encodes a 4-byte big-endian length prefix plus UTF-8 JSON', () => {
    const frame = encodeFrame({ type: 'disconnect' });
    const payload = '{"type":"disconnect"}';
    expect(frame.readUInt32BE(0)).toBe(Buffer.byteLength(payload));
    expect(frame.subarray(4).toString('utf8')).toBe(payload);
  });

  it('round-trips through the decoder', () => {
    const decoder = new FrameDecoder();
    const out = decoder.push(encodeFrame({ type: 'disconnect' }));
    expect(out).toEqual([{ type: 'disconnect' }]);
  });

  it('reassembles a frame split across chunks', () => {
    const frame = encodeFrame({ type: 'state', state: 'connected' });
    const decoder = new FrameDecoder();
    expect(decoder.push(frame.subarray(0, 3))).toEqual([]);
    expect(decoder.push(frame.subarray(3))).toEqual([{ type: 'state', state: 'connected' }]);
  });

  it('decodes multiple frames in one chunk', () => {
    const chunk = Buffer.concat([
      encodeFrame({ type: 'state', state: 'connecting' }),
      encodeFrame({ type: 'state', state: 'connected' }),
    ]);
    expect(new FrameDecoder().push(chunk)).toEqual([
      { type: 'state', state: 'connecting' },
      { type: 'state', state: 'connected' },
    ]);
  });

  it('rejects a frame whose declared length is absurd', () => {
    const decoder = new FrameDecoder();
    expect(() => decoder.push(Buffer.from([0xff, 0xff, 0xff, 0xff]))).toThrow(RangeError);
  });

  it('refuses to encode a message above the frame size cap', () => {
    expect(() => encodeFrame({ blob: 'x'.repeat(16 * 1024 * 1024) })).toThrow(RangeError);
  });
});

describe('request builders', () => {
  it('configure omits absent optional fields', () => {
    expect(configureRequest({ mnemonic: 'm', apiBase: 'https://a', serverPubkeyPin: 'p' })).toEqual(
      {
        type: 'configure',
        mnemonic: 'm',
        apiBase: 'https://a',
        serverPubkeyPin: 'p',
      },
    );
  });

  it('configure includes DAITA and IPv6 options when set', () => {
    expect(
      configureRequest({
        mnemonic: 'm',
        apiBase: 'https://a',
        serverPubkeyPin: 'p',
        daita: true,
        daitaMachine: 'tamaraw',
        requestIpv6: false,
      }),
    ).toEqual({
      type: 'configure',
      mnemonic: 'm',
      apiBase: 'https://a',
      serverPubkeyPin: 'p',
      daita: true,
      daitaMachine: 'tamaraw',
      requestIpv6: false,
    });
  });

  it('connect omits dnsOverTunnel by default and includes it when set', () => {
    expect(connectRequest({ exitPubkeyHex: 'ab12' })).toEqual({
      type: 'connect',
      exitPubkeyHex: 'ab12',
    });
    expect(connectRequest({ exitPubkeyHex: 'ab12', dnsOverTunnel: false })).toEqual({
      type: 'connect',
      exitPubkeyHex: 'ab12',
      dnsOverTunnel: false,
    });
  });

  it('disconnect is a bare typed object', () => {
    expect(disconnectRequest()).toEqual({ type: 'disconnect' });
  });
});

describe('parseEvent', () => {
  it('narrows state and error events', () => {
    expect(parseEvent({ type: 'state', state: 'connected' })).toEqual({
      type: 'state',
      state: 'connected',
    });
    expect(parseEvent({ type: 'error', kind: 'tunnel', message: 'down' })).toEqual({
      type: 'error',
      kind: 'tunnel',
      message: 'down',
    });
  });

  it('returns null for unknown or malformed messages', () => {
    expect(parseEvent({ type: 'state', state: 'bogus' })).toBeNull();
    expect(parseEvent({ type: 'other' })).toBeNull();
    expect(parseEvent(42)).toBeNull();
  });

  it('parses the draining teardown state', () => {
    // warrend announces teardown with `draining` before the terminal
    // `disconnected`; a client that drops it would miss every disconnect
    // transition.
    expect(parseEvent({ type: 'state', state: 'draining' })).toEqual({
      type: 'state',
      state: 'draining',
    });
  });
});
