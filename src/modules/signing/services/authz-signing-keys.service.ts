import { createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { Injectable, OnModuleInit } from '@nestjs/common';
import { calculateJwkThumbprint, exportJWK, SignJWT } from 'jose';
import { AppConfig } from '@config/config.module';

export const AUTHORIZATION_TOKEN_TYP = 'authz+jwt';
const MIN_RSA_BITS = 2048;
const DEV_RSA_BITS = 3072;

export interface PublicSigningJwk {
  kty: 'RSA';
  kid: string;
  use: 'sig';
  alg: 'RS256';
  n: string;
  e: string;
}

/**
 * The Authorization service's own RS256 signing key - separate from Identity Federation's keys.
 *
 *  - Identity (authentication) signs core_assertion / access tokens    -> Identity  /.well-known/jwks.json
 *  - Authorization signs authorization tokens (typ authz+jwt)          -> this service /.well-known/jwks.json
 *
 * Production: the private key comes from AUTHZ_SIGNING_PRIVATE_KEY (injected from a secret store).
 * Development/test: generated once into AUTHZ_SIGNING_KEY_FILE (git-ignored). Only public parameters are published.
 */
@Injectable()
export class AuthzSigningKeys implements OnModuleInit {
  private privateKey?: KeyObject;
  private publicJwk?: PublicSigningJwk;

  constructor(private readonly config: AppConfig) {}

  async onModuleInit(): Promise<void> {
    await this.load();
  }

  async load(): Promise<void> {
    if (this.privateKey) return;
    const key = createPrivateKey(this.readPem());
    if (key.asymmetricKeyType !== 'rsa') throw new Error('authorization signing key must be an RSA private key');
    const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
    if (bits < MIN_RSA_BITS) throw new Error(`authorization signing key is ${bits} bits; minimum is ${MIN_RSA_BITS}`);
    const exported = await exportJWK(createPublicKey(key));
    const kid = `authz-${(await calculateJwkThumbprint(exported)).slice(0, 16)}`;
    this.privateKey = key;
    this.publicJwk = { kty: 'RSA', kid, use: 'sig', alg: 'RS256', n: exported.n as string, e: exported.e as string };
  }

  get issuer(): string {
    return this.config.env.AUTHZ_ISSUER;
  }

  get jwksUri(): string {
    return `${this.issuer}/.well-known/jwks.json`;
  }

  jwks(): { keys: PublicSigningJwk[] } {
    if (!this.publicJwk) throw new Error('authorization signing key not loaded');
    return { keys: [this.publicJwk] };
  }

  /** Signs an authorization token: iss = this service, sub = ITS ID, aud = client_id, short-lived, single jti. */
  async sign(claims: Record<string, unknown>, subject: string, audience: string): Promise<{ token: string; expiresIn: number; kid: string }> {
    await this.load();
    const ttl = this.config.env.AUTHORIZATION_TOKEN_TTL_SECONDS;
    const iat = Math.floor(Date.now() / 1000);
    const kid = this.publicJwk!.kid;
    const token = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', typ: AUTHORIZATION_TOKEN_TYP, kid })
      .setIssuer(this.issuer)
      .setSubject(subject)
      .setAudience(audience)
      .setJti(randomUUID())
      .setIssuedAt(iat)
      .setExpirationTime(iat + ttl)
      .sign(this.privateKey!);
    return { token, expiresIn: ttl, kid };
  }

  private readPem(): string {
    const inline = this.config.env.AUTHZ_SIGNING_PRIVATE_KEY;
    if (inline) return inline.includes('\\n') ? inline.replace(/\\n/g, '\n') : inline;
    if (this.config.isProduction) throw new Error('AUTHZ_SIGNING_PRIVATE_KEY is required in production');
    const file = resolve(this.config.env.AUTHZ_SIGNING_KEY_FILE);
    if (!existsSync(file)) {
      const { privateKey } = generateKeyPairSync('rsa', {
        modulusLength: DEV_RSA_BITS,
        publicExponent: 0x10001,
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
      });
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, privateKey, { mode: 0o600 });
    }
    return readFileSync(file, 'utf8');
  }
}
