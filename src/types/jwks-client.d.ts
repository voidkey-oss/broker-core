declare module 'jwks-client' {
  interface SigningKey {
    getPublicKey(): string;
    kid: string;
  }

  interface JwksClientOptions {
    jwksUri: string;
    requestHeaders?: any;
    timeout?: number;
    cache?: boolean;
    cacheMaxEntries?: number;
    cacheMaxAge?: number;
    jwksRequestsPerMinute?: number;
    rateLimit?: boolean;
  }

  interface JwksClient {
    getSigningKey(kid: string): Promise<SigningKey>;
    getSigningKeys(): Promise<SigningKey[]>;
  }

  function jwksClient(options: JwksClientOptions): JwksClient;
  export = jwksClient;
}