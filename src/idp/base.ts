import { IdpConfiguration, OidcClaims } from '../types';

export abstract class IdpProvider {
  protected config: IdpConfiguration;

  constructor(config: IdpConfiguration) {
    this.config = config;
  }

  abstract validateToken(token: string): Promise<OidcClaims>;
  
  // Optional health check method for providers
  async healthCheck?(): Promise<boolean>;
  
  getName(): string {
    return this.config.name;
  }

  getIssuer(): string {
    return this.config.issuer;
  }

  getAudience(): string | string[] | undefined {
    return this.config.audience;
  }

  getJwksUri(): string {
    return this.config.jwksUri;
  }

  // Note: Identity configuration is now managed centrally by CredentialBroker
  // This method is kept for backward compatibility but will be handled by the broker
}