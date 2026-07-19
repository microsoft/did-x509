// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

import type { CertificateName } from './types.js';

/**
 * RFC 4514 OID-to-label mapping.
 * @see https://datatracker.ietf.org/doc/html/rfc4514.html
 */
const NAME_OID_STRINGS: Record<string, string> = {
  '2.5.4.3': 'CN',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.6': 'C',
  '2.5.4.9': 'STREET',
};

/**
 * Reverse mapping: label -> OID dotted string.
 */
const NAME_LABEL_TO_OID: Record<string, string> = Object.fromEntries(
  Object.entries(NAME_OID_STRINGS).map(([oid, label]) => [label, oid])
);

/**
 * Base64url-encode bytes without padding.
 */
export function b64url(data: Uint8Array): string {
  let binary = '';
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64url-decode a string (handles missing padding).
 */
export function b64urlDecode(str: string): Uint8Array {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (base64.length % 4)) % 4;
  base64 += '='.repeat(padding);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Percent-encode a string per RFC 3986.
 * Unlike standard URL encoding, `~` is encoded as `%7E`.
 */
export function pctEncode(data: string): string {
  const allowed = /^[A-Za-z0-9\-._~]$/;
  let result = '';
  for (const char of data) {
    if (allowed.test(char)) {
      result += char;
    } else {
      const bytes = new TextEncoder().encode(char);
      for (const byte of bytes) {
        result += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
      }
    }
  }
  return result;
}

/**
 * Percent-decode a string per RFC 3986.
 */
export function pctDecode(data: string): string {
  return decodeURIComponent(data);
}

/**
 * Convert an X.509 name string (e.g. "CN=Example, O=Org") to a CertificateName object.
 */
export function parseNameString(nameStr: string): CertificateName {
  if (!nameStr) return {};

  const result: CertificateName = {};
  const parts = nameStr.split(',').map(s => s.trim());

  for (const part of parts) {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) continue;

    const key = part.substring(0, eqIndex).trim();
    const value = part.substring(eqIndex + 1).trim();

    const oid = NAME_LABEL_TO_OID[key];
    if (oid) {
      result[oid] = value;
    } else {
      // Could be a dotted OID string or the key itself
      result[key] = value;
    }
  }

  return result;
}

/**
 * Get the RFC 4514 label for an OID, or return the OID dotted string.
 */
export function oidToLabel(oid: string): string {
  return NAME_OID_STRINGS[oid] ?? oid;
}
