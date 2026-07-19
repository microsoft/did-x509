// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import { describe, it, expect } from 'vitest';
import {
  b64url,
  b64urlDecode,
  pctEncode,
  pctDecode,
  parseNameString,
  oidToLabel,
} from '../src/encoding.js';

describe('b64url', () => {
  it('encodes bytes to base64url without padding', () => {
    const input = new Uint8Array([0x4d, 0x61, 0x6e]); // "Man"
    expect(b64url(input)).toBe('TWFu');
  });

  it('replaces + with - and / with _', () => {
    // 0xFB 0xFF 0xBE produces characters that use + and / in standard base64
    const input = new Uint8Array([0xfb, 0xff, 0xbe]);
    const result = b64url(input);
    expect(result).not.toContain('+');
    expect(result).not.toContain('/');
    expect(result).not.toContain('=');
  });

  it('removes padding', () => {
    // 1 byte -> 2 base64 chars + 2 padding chars
    const oneByte = new Uint8Array([0x61]);
    const encoded = b64url(oneByte);
    expect(encoded).not.toContain('=');
    expect(encoded).toBe('YQ');

    // 2 bytes -> 3 base64 chars + 1 padding char
    const twoBytes = new Uint8Array([0x61, 0x62]);
    const encoded2 = b64url(twoBytes);
    expect(encoded2).not.toContain('=');
    expect(encoded2).toBe('YWI');
  });

  it('encodes empty input', () => {
    expect(b64url(new Uint8Array([]))).toBe('');
  });

  it('round-trips with b64urlDecode', () => {
    const original = new Uint8Array([0x00, 0x01, 0x02, 0x7f, 0x80, 0xff]);
    const encoded = b64url(original);
    const decoded = b64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });
});

describe('b64urlDecode', () => {
  it('decodes base64url string to bytes', () => {
    const decoded = b64urlDecode('TWFu');
    expect(decoded).toEqual(new Uint8Array([0x4d, 0x61, 0x6e]));
  });

  it('handles missing padding', () => {
    // "YQ" is base64url for "a" without padding
    const decoded = b64urlDecode('YQ');
    expect(decoded).toEqual(new Uint8Array([0x61]));
  });

  it('handles - and _ characters', () => {
    const decoded = b64urlDecode('____');
    expect(decoded.length).toBe(3);
  });

  it('decodes empty string', () => {
    const decoded = b64urlDecode('');
    expect(decoded.length).toBe(0);
  });

  it('round-trips with b64url', () => {
    const original = 'Hello, World! 🌍';
    const bytes = new TextEncoder().encode(original);
    const encoded = b64url(bytes);
    const decoded = b64urlDecode(encoded);
    const result = new TextDecoder().decode(decoded);
    expect(result).toBe(original);
  });
});

describe('pctEncode', () => {
  it('leaves unreserved characters unchanged', () => {
    expect(pctEncode('abc123')).toBe('abc123');
    expect(pctEncode('-._~')).toBe('-._~');
  });

  it('encodes spaces as %20', () => {
    expect(pctEncode(' ')).toBe('%20');
    expect(pctEncode('hello world')).toBe('hello%20world');
  });

  it('does NOT encode ~ (unreserved in RFC 3986)', () => {
    expect(pctEncode('~')).toBe('~');
  });

  it('encodes / as %2F', () => {
    expect(pctEncode('/')).toBe('%2F');
  });

  it('encodes special characters', () => {
    expect(pctEncode('@')).toBe('%40');
    expect(pctEncode('#')).toBe('%23');
    expect(pctEncode('&')).toBe('%26');
    expect(pctEncode('=')).toBe('%3D');
    expect(pctEncode('+')).toBe('%2B');
  });

  it('encodes unicode characters', () => {
    expect(pctEncode('é')).toBe('%C3%A9');
    expect(pctEncode('🌍')).toBe('%F0%9F%8C%8D');
  });

  it('round-trips with pctDecode', () => {
    const original = 'https://example.com/path?q=1&a=2#frag';
    const encoded = pctEncode(original);
    const decoded = pctDecode(encoded);
    expect(decoded).toBe(original);
  });
});

describe('pctDecode', () => {
  it('decodes %20 to space', () => {
    expect(pctDecode('hello%20world')).toBe('hello world');
  });

  it('decodes %7E to ~', () => {
    expect(pctDecode('%7E')).toBe('~');
  });

  it('decodes %2F to /', () => {
    expect(pctDecode('a%2Fb')).toBe('a/b');
  });

  it('leaves unreserved characters unchanged', () => {
    expect(pctDecode('abc123-._~')).toBe('abc123-._~');
  });

  it('decodes empty string', () => {
    expect(pctDecode('')).toBe('');
  });

  it('round-trips with pctEncode', () => {
    const original = 'CN=Test Corp, O=Acme Inc, C=US';
    const encoded = pctEncode(original);
    expect(pctDecode(encoded)).toBe(original);
  });
});

describe('parseNameString', () => {
  it('parses standard fields', () => {
    const result = parseNameString('CN=Test Corp, O=Acme Inc, C=US');
    expect(result).toEqual({
      '2.5.4.3': 'Test Corp',
      '2.5.4.10': 'Acme Inc',
      '2.5.4.6': 'US',
    });
  });

  it('parses all known fields', () => {
    const result = parseNameString(
      'CN=cn, O=o, OU=ou, C=c, ST=st, L=l, STREET=street'
    );
    expect(result).toEqual({
      '2.5.4.3': 'cn',
      '2.5.4.10': 'o',
      '2.5.4.11': 'ou',
      '2.5.4.6': 'c',
      '2.5.4.8': 'st',
      '2.5.4.7': 'l',
      '2.5.4.9': 'street',
    });
  });

  it('handles unknown OID as key', () => {
    const result = parseNameString('1.2.3.4.5=somevalue');
    expect(result).toEqual({ '1.2.3.4.5': 'somevalue' });
  });

  it('returns empty object for empty string', () => {
    expect(parseNameString('')).toEqual({});
  });

  it('handles single field', () => {
    const result = parseNameString('CN=Test');
    expect(result).toEqual({ '2.5.4.3': 'Test' });
  });

  it('handles duplicate labels - last wins', () => {
    const result = parseNameString('CN=First, CN=Second');
    expect(result).toEqual({ '2.5.4.3': 'Second' });
  });

  it('trims whitespace around parts', () => {
    const result = parseNameString('CN = Test , O = Acme');
    expect(result).toEqual({
      '2.5.4.3': 'Test',
      '2.5.4.10': 'Acme',
    });
  });

  it('handles values containing equals signs', () => {
    const result = parseNameString('CN=name=with=equals');
    expect(result).toEqual({ '2.5.4.3': 'name=with=equals' });
  });
});

describe('oidToLabel', () => {
  it('maps known OID to label', () => {
    expect(oidToLabel('2.5.4.3')).toBe('CN');
    expect(oidToLabel('2.5.4.10')).toBe('O');
    expect(oidToLabel('2.5.4.11')).toBe('OU');
    expect(oidToLabel('2.5.4.6')).toBe('C');
    expect(oidToLabel('2.5.4.8')).toBe('ST');
    expect(oidToLabel('2.5.4.7')).toBe('L');
    expect(oidToLabel('2.5.4.9')).toBe('STREET');
  });

  it('returns OID string for unknown OID', () => {
    expect(oidToLabel('1.2.3.4.5')).toBe('1.2.3.4.5');
    expect(oidToLabel('2.5.29.17')).toBe('2.5.29.17');
  });
});
