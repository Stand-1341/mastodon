import { createConnection } from 'node:net';
import { createInterface } from 'node:readline';

import {
  createApplicationMessage,
  decode,
  defaultCapabilities,
  defaultCredentialTypes,
  encode,
  generateKeyPackageWithKey,
  generateSignatureKeyPair,
  joinGroup,
  mlsMessageDecoder,
  mlsMessageEncoder,
  processMessage,
  protocolVersions,
  wireformats,
} from 'ts-mls';
import type { Credential } from 'ts-mls';

import { createDraftPqcMlsCiphersuite } from './draft_ciphersuite';

const INTEROP_URL = process.env.PQC_OPENMLS_INTEROP_URL;
const FROM_TYPESCRIPT = 'TypeScript to OpenMLS hybrid MLS interop';
const FROM_OPENMLS = 'OpenMLS to TypeScript hybrid MLS interop';

const splitAddress = (url: string) => {
  const parsed = new URL(url);
  if (parsed.protocol !== 'tcp:')
    throw new Error('PQC_OPENMLS_INTEROP_URL must use tcp://');
  return { host: parsed.hostname, port: Number(parsed.port) };
};

describe('OpenMLS wire interoperability (opt-in)', () => {
  it.skipIf(!INTEROP_URL)(
    'joins an OpenMLS group and exchanges encrypted MLS application messages both ways',
    async () => {
      if (!INTEROP_URL)
        throw new Error(
          'Set PQC_OPENMLS_INTEROP_URL to run the OpenMLS interop test',
        );

      const socket = createConnection(splitAddress(INTEROP_URL));
      socket.setTimeout(60_000);
      await new Promise<void>((resolve, reject) => {
        socket.once('connect', resolve);
        socket.once('error', reject);
        socket.once('timeout', () => {
          reject(new Error('Timed out connecting to the OpenMLS interop peer'));
        });
      });
      const lines = createInterface({ input: socket });
      const responses = lines[Symbol.asyncIterator]();
      const send = (message: unknown) =>
        new Promise<void>((resolve, reject) => {
          socket.write(`${JSON.stringify(message)}\n`, (error) => {
            if (error) reject(error);
            else resolve();
          });
        });
      const receive = async (): Promise<Record<string, unknown>> => {
        const result = await responses.next();
        if (result.done)
          throw new Error('OpenMLS peer closed the connection unexpectedly');
        return JSON.parse(result.value) as Record<string, unknown>;
      };

      try {
        const cipherSuite = await createDraftPqcMlsCiphersuite();
        const identity =
          'https://example.test/users/typescript\ntypescript-device';
        const credential: Credential = {
          credentialType: defaultCredentialTypes.basic,
          identity: new TextEncoder().encode(identity),
        };
        const signatureKeyPair = await generateSignatureKeyPair(cipherSuite);
        const capabilities = defaultCapabilities();
        const generated = await generateKeyPackageWithKey({
          credential,
          signatureKeyPair,
          cipherSuite,
          extensions: [],
          capabilities: { ...capabilities, ciphersuites: [cipherSuite.id] },
        });
        const keyPackageBytes = encode(mlsMessageEncoder, {
          wireformat: wireformats.mls_key_package,
          keyPackage: generated.publicPackage,
          version: protocolVersions.mls10,
        });

        await send({
          phase: 'start',
          key_package: Buffer.from(keyPackageBytes).toString('base64'),
        });
        const welcomeResponse = await receive();
        expect(welcomeResponse.phase).toBe('welcome');
        const welcomeBytes = Buffer.from(
          String(welcomeResponse.welcome),
          'base64',
        );
        const welcomeMessage = decode(mlsMessageDecoder, welcomeBytes);
        if (
          welcomeMessage?.wireformat !== wireformats.mls_welcome ||
          !('welcome' in welcomeMessage)
        ) {
          throw new Error('OpenMLS peer did not send a valid MLS Welcome');
        }

        const context = {
          cipherSuite,
          authService: {
            validateCredential: () => Promise.resolve(true),
            validateSuccessorCredential: () => Promise.resolve(true),
          },
        };
        const state = await joinGroup({
          context,
          welcome: welcomeMessage.welcome,
          keyPackage: generated.publicPackage,
          privateKeys: generated.privatePackage,
        });
        const sent = await createApplicationMessage({
          context,
          state,
          message: new TextEncoder().encode(FROM_TYPESCRIPT),
        });
        await send({
          phase: 'application',
          message: Buffer.from(
            encode(mlsMessageEncoder, sent.message),
          ).toString('base64'),
        });

        const receivedAck = await receive();
        expect(receivedAck).toMatchObject({ phase: 'received', ok: true });
        const reply = await receive();
        expect(reply.phase).toBe('application');
        const incoming = decode(
          mlsMessageDecoder,
          Buffer.from(String(reply.message), 'base64'),
        );
        if (
          !incoming ||
          (incoming.wireformat !== wireformats.mls_private_message &&
            incoming.wireformat !== wireformats.mls_public_message)
        ) {
          throw new Error(
            'OpenMLS peer did not send a valid MLS framed message',
          );
        }
        const processed = await processMessage({
          context,
          state: sent.newState,
          message: incoming,
        });
        expect(processed.kind).toBe('applicationMessage');
        if (processed.kind !== 'applicationMessage')
          throw new Error('OpenMLS reply was not an application message');
        expect(new TextDecoder().decode(processed.message)).toBe(FROM_OPENMLS);
        await send({ phase: 'done' });
      } finally {
        lines.close();
        socket.destroy();
      }
    },
    90_000,
  );
});
