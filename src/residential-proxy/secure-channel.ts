import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';

/**
 * End-to-end encryption for the residential proxy control channel.
 *
 * TLS only protects the hop to whatever terminates it -- a CDN, a load
 * balancer or a reverse proxy all see plaintext tunnel bytes and a static
 * bearer token. This layer sits inside the WebSocket so that the agent and the
 * browserless process are the only parties holding keys, and it replaces the
 * bearer token with a challenge/response that proves knowledge of the shared
 * secret without ever putting it on the wire.
 */
export const secureChannelInfo = 'browserless-residential-proxy/v2';
export const secureChannelKeyBytes = 32;
export const secureChannelMacBytes = 32;
export const secureChannelNonceBytes = 12;
export const secureChannelPublicKeyBytes = 32;
export const secureChannelTagBytes = 16;
export const handshakeNonceBytes = 32;
const maxPadBytes = 255;
const padUnderBytes = 512;

export interface HandshakeHelloFrame {
  nonce: string;
  pub: string;
  t: 'hello';
  v: number;
}

export interface HandshakeAuthFrame {
  box: string;
  mac: string;
  nonce: string;
  pub: string;
  t: 'auth';
}

export interface HandshakeReadyFrame {
  box: string;
  t: 'ready';
}

interface DerivedKeys {
  agentToServer: Buffer;
  macKey: Buffer;
  serverToAgent: Buffer;
}

const asBuffer = (value: unknown, bytes: number, name: string): Buffer => {
  if (typeof value !== 'string') {
    throw new Error(`Handshake field "${name}" is missing`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== bytes) {
    throw new Error(`Handshake field "${name}" must be ${bytes} bytes`);
  }
  return decoded;
};

export const exportRawPublicKey = (key: KeyObject): Buffer => {
  const { x } = key.export({ format: 'jwk' }) as { x?: string };
  if (!x) throw new Error('Unable to export the X25519 public key');
  return Buffer.from(x, 'base64url');
};

export const importRawPublicKey = (raw: Buffer): KeyObject => {
  if (raw.length !== secureChannelPublicKeyBytes) {
    throw new Error('X25519 public keys must be 32 bytes');
  }
  return createPublicKey({
    format: 'jwk',
    key: { crv: 'X25519', kty: 'OKP', x: raw.toString('base64url') },
  });
};

const deriveKeys = (
  psk: string,
  serverPub: Buffer,
  agentPub: Buffer,
  serverNonce: Buffer,
  agentNonce: Buffer,
  shared: Buffer,
): DerivedKeys => {
  // A peer that does not hold the pre-shared token cannot derive these keys
  // even if it completes the X25519 exchange, so an on-path proxy that strips
  // TLS still sees nothing but authenticated ciphertext.
  if (shared.every((byte) => byte === 0)) {
    throw new Error('Rejected a degenerate X25519 shared secret');
  }
  const ikm = Buffer.concat([
    shared,
    createHash('sha256').update(psk, 'utf8').digest(),
  ]);
  const okm = Buffer.from(
    hkdfSync(
      'sha256',
      ikm,
      Buffer.concat([serverNonce, agentNonce]),
      Buffer.concat([
        Buffer.from(secureChannelInfo, 'utf8'),
        serverPub,
        agentPub,
      ]),
      secureChannelKeyBytes * 2 + secureChannelMacBytes,
    ),
  );
  return {
    agentToServer: okm.subarray(0, 32),
    macKey: okm.subarray(64, 96),
    serverToAgent: okm.subarray(32, 64),
  };
};

const authMac = (
  keys: DerivedKeys,
  serverPub: Buffer,
  agentPub: Buffer,
  serverNonce: Buffer,
  agentNonce: Buffer,
): Buffer =>
  createHmac('sha256', keys.macKey)
    .update('agent-auth')
    .update(serverPub)
    .update(agentPub)
    .update(serverNonce)
    .update(agentNonce)
    .digest();

/**
 * Authenticated, ordered, padded framing over an already-established key pair.
 * Each direction owns a key, so a plain counter is a safe nonce, and the
 * receiver requires strictly increasing counters -- replayed or reordered
 * frames are dropped rather than decrypted.
 */
export class SecureChannel {
  protected receiveCounter = 0n;
  protected sendCounter = 0n;

  constructor(
    protected readonly sendKey: Buffer,
    protected readonly receiveKey: Buffer,
    sendCounter = 0n,
    receiveCounter = 0n,
  ) {
    this.sendCounter = sendCounter;
    this.receiveCounter = receiveCounter;
  }

  protected nonce(counter: bigint): Buffer {
    const nonce = Buffer.alloc(secureChannelNonceBytes);
    nonce.writeBigUInt64BE(counter, 4);
    return nonce;
  }

  protected sealWith(key: Buffer, counter: bigint, plaintext: Buffer): Buffer {
    const nonce = this.nonce(counter);
    const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: secureChannelTagBytes,
    });
    cipher.setAAD(nonce, { plaintextLength: plaintext.length });
    return Buffer.concat([
      nonce,
      cipher.update(plaintext),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
  }

  protected openWith(key: Buffer, expected: bigint, frame: Buffer): Buffer {
    const minimum = secureChannelNonceBytes + secureChannelTagBytes;
    if (frame.length < minimum) {
      throw new Error('Encrypted frame is too short');
    }
    const nonce = frame.subarray(0, secureChannelNonceBytes);
    if (nonce.readBigUInt64BE(4) !== expected) {
      throw new Error('Encrypted frame arrived out of order');
    }
    const tag = frame.subarray(frame.length - secureChannelTagBytes);
    const body = frame.subarray(
      secureChannelNonceBytes,
      frame.length - secureChannelTagBytes,
    );
    const decipher = createDecipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: secureChannelTagBytes,
    });
    decipher.setAAD(nonce, { plaintextLength: body.length });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  }

  /** Pads short frames so tunnel byte counts leak less about the payload. */
  protected pad(payload: Buffer): Buffer {
    const padLength =
      payload.length < padUnderBytes
        ? randomBytes(1)[0] % (maxPadBytes + 1)
        : 0;
    const header = Buffer.alloc(2);
    header.writeUInt16BE(padLength);
    return Buffer.concat([header, randomBytes(padLength), payload]);
  }

  protected unpad(plaintext: Buffer): Buffer {
    if (plaintext.length < 2) throw new Error('Malformed padded frame');
    const padLength = plaintext.readUInt16BE(0);
    if (padLength > plaintext.length - 2) {
      throw new Error('Malformed padded frame');
    }
    return plaintext.subarray(2 + padLength);
  }

  public seal(message: unknown): Buffer {
    const frame = this.sealWith(
      this.sendKey,
      this.sendCounter,
      this.pad(Buffer.from(JSON.stringify(message), 'utf8')),
    );
    this.sendCounter += 1n;
    return frame;
  }

  public open<T>(frame: Buffer): T {
    const plaintext = this.openWith(
      this.receiveKey,
      this.receiveCounter,
      frame,
    );
    this.receiveCounter += 1n;
    const value = JSON.parse(this.unpad(plaintext).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error('Encrypted frame did not contain an object');
    }
    return value as T;
  }
}

/** Server half of the handshake: offers a key, then verifies the agent's MAC. */
export class ServerHandshake {
  protected readonly keyPair = generateKeyPairSync('x25519');
  protected readonly nonce = randomBytes(handshakeNonceBytes);
  protected readonly pub = exportRawPublicKey(this.keyPair.publicKey);

  constructor(
    protected readonly psk: string,
    protected readonly version: number,
  ) {}

  public hello(): HandshakeHelloFrame {
    return {
      nonce: this.nonce.toString('base64url'),
      pub: this.pub.toString('base64url'),
      t: 'hello',
      v: this.version,
    };
  }

  public accept<T>(frame: unknown): {
    channel: SecureChannel;
    payload: T;
    ready: HandshakeReadyFrame;
  } {
    const auth = frame as HandshakeAuthFrame;
    if (!auth || auth.t !== 'auth') {
      throw new Error('Expected an "auth" handshake frame');
    }
    const agentPub = asBuffer(auth.pub, secureChannelPublicKeyBytes, 'pub');
    const agentNonce = asBuffer(auth.nonce, handshakeNonceBytes, 'nonce');
    const mac = asBuffer(auth.mac, secureChannelMacBytes, 'mac');
    const keys = deriveKeys(
      this.psk,
      this.pub,
      agentPub,
      this.nonce,
      agentNonce,
      diffieHellman({
        privateKey: this.keyPair.privateKey,
        publicKey: importRawPublicKey(agentPub),
      }),
    );
    const expected = authMac(keys, this.pub, agentPub, this.nonce, agentNonce);
    if (!timingSafeEqual(mac, expected)) {
      throw new Error('Residential proxy agent failed the handshake');
    }
    // Counter 0 in each direction is spent on the handshake payloads, so the
    // first tunnel frame starts at 1 and cannot replay them.
    const channel = new SecureChannel(
      keys.serverToAgent,
      keys.agentToServer,
      0n,
      0n,
    );
    const payload = channel.open<T>(Buffer.from(auth.box, 'base64url'));
    return {
      channel,
      payload,
      ready: {
        box: channel.seal({ ok: true, v: this.version }).toString('base64url'),
        t: 'ready',
      },
    };
  }
}

/** Agent half of the handshake: proves it holds the token, then checks the server does too. */
export class AgentHandshake {
  protected readonly keyPair = generateKeyPairSync('x25519');
  protected readonly nonce = randomBytes(handshakeNonceBytes);
  protected readonly pub = exportRawPublicKey(this.keyPair.publicKey);
  protected channel?: SecureChannel;

  constructor(
    protected readonly psk: string,
    protected readonly version: number,
  ) {}

  public auth(
    frame: unknown,
    payload: unknown,
  ): { auth: HandshakeAuthFrame; channel: SecureChannel } {
    const hello = frame as HandshakeHelloFrame;
    if (!hello || hello.t !== 'hello') {
      throw new Error('Expected a "hello" handshake frame');
    }
    if (hello.v !== this.version) {
      throw new Error(
        `Server offered residential proxy protocol v${hello.v}, expected v${this.version}`,
      );
    }
    const serverPub = asBuffer(hello.pub, secureChannelPublicKeyBytes, 'pub');
    const serverNonce = asBuffer(hello.nonce, handshakeNonceBytes, 'nonce');
    const keys = deriveKeys(
      this.psk,
      serverPub,
      this.pub,
      serverNonce,
      this.nonce,
      diffieHellman({
        privateKey: this.keyPair.privateKey,
        publicKey: importRawPublicKey(serverPub),
      }),
    );
    const channel = new SecureChannel(
      keys.agentToServer,
      keys.serverToAgent,
      0n,
      0n,
    );
    this.channel = channel;
    return {
      auth: {
        box: channel.seal(payload).toString('base64url'),
        mac: authMac(
          keys,
          serverPub,
          this.pub,
          serverNonce,
          this.nonce,
        ).toString('base64url'),
        nonce: this.nonce.toString('base64url'),
        pub: this.pub.toString('base64url'),
        t: 'auth',
      },
      channel,
    };
  }

  /**
   * A server that cannot produce this frame does not hold the token, which
   * stops a hijacked DNS record or a hostile middlebox from collecting
   * tunnels from agents.
   */
  public confirm(frame: unknown): void {
    const ready = frame as HandshakeReadyFrame;
    if (!this.channel) throw new Error('Handshake has not started');
    if (!ready || ready.t !== 'ready' || typeof ready.box !== 'string') {
      throw new Error('Expected a "ready" handshake frame');
    }
    const payload = this.channel.open<{ ok?: boolean }>(
      Buffer.from(ready.box, 'base64url'),
    );
    if (payload.ok !== true) {
      throw new Error('Server rejected the residential proxy handshake');
    }
  }
}
