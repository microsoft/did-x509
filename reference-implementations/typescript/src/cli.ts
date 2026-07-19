// Copyright (c) AyanWorks. Licensed under the MIT License.
// Original did:x509 specification by Microsoft Corporation.

/**
 * CLI entry point for @didx509/core.
 *
 * Commands:
 *   resolve <did> --chain <path> [--skip-validity-period-check]
 *   convert <chain-path>
 *   encode <string>
 */

import { readFileSync } from 'node:fs';
import { resolveDidFromPem, convertChain } from './didx509.js';
import { pctEncode } from './encoding.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command) {
    printUsage();
    process.exit(1);
  }

  switch (command) {
    case 'resolve':
      await handleResolve(args.slice(1));
      break;
    case 'convert':
      handleConvert(args.slice(1));
      break;
    case 'encode':
      handleEncode(args.slice(1));
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

function printUsage(): void {
  console.log(`
Usage:
  didx509 resolve <did> --chain <path> [--skip-validity-period-check]
  didx509 convert <chain-path>
  didx509 encode <string>
`);
}

async function handleResolve(args: string[]): Promise<void> {
  const did = args[0];
  if (!did) {
    console.error('Error: DID argument is required');
    process.exit(1);
  }

  const chainIndex = args.indexOf('--chain');
  if (chainIndex === -1 || !args[chainIndex + 1]) {
    console.error('Error: --chain <path> is required');
    process.exit(1);
  }

  const chainPath = args[chainIndex + 1]!;
  const skipValidityPeriodCheck = args.includes('--skip-validity-period-check');

  try {
    const pemChain = readFileSync(chainPath, 'utf-8');
    const doc = await resolveDidFromPem(did, pemChain, {
      skipValidityPeriodCheck,
    });
    console.log(JSON.stringify(doc, null, 2));
  } catch (error) {
    console.error(
      `Error: ${error instanceof Error ? error.message : String(error)}`
    );
    process.exit(1);
  }
}

function handleConvert(args: string[]): void {
  const chainPath = args[0];
  if (!chainPath) {
    console.error('Error: chain path argument is required');
    process.exit(1);
  }

  try {
    const pemChain = readFileSync(chainPath, 'utf-8');
    const decoded = convertChain(pemChain);
    console.log(JSON.stringify(decoded, null, 2));
  } catch (error) {
    console.error(
      `Error: ${error instanceof Error ? error.message : String(error)}`
    );
    process.exit(1);
  }
}

function handleEncode(args: string[]): void {
  const str = args[0];
  if (str === undefined) {
    console.error('Error: string argument is required');
    process.exit(1);
  }

  console.log(pctEncode(str));
}

main();
