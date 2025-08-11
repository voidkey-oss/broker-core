import { OidcClaims, IdpConfiguration } from '../types';

export interface JwtValidationOptions {
  issuer: string;
  audience: string;
  algorithms: string[];
  clockTolerance?: number;
}

export class JwksTokenValidator {
  private config: IdpConfiguration;

  constructor(config: IdpConfiguration) {
    this.config = config;
  }

  async validateToken(token: string): Promise<OidcClaims> {
    try {
      // Use runtime import function to avoid TypeScript compilation issues
      const importJose = new Function('return import("jose")');
      const jose = await importJose();
      
      // Create remote JWKS
      const JWKS = jose.createRemoteJWKSet(new URL(this.config.jwksUri));
      
      // Build verification options
      const verifyOptions: any = {
        issuer: this.config.issuer,
        algorithms: this.config.algorithms || ['RS256'],
        clockTolerance: '30s' // Allow 30 seconds clock skew
      };
      
      // Handle flexible audience validation
      const shouldValidateAudience = this.config.validateAudience !== false; // Default to true
      if (shouldValidateAudience && this.config.audience) {
        verifyOptions.audience = this.config.audience;
      }
      
      // Verify JWT using jose library with remote JWKS
      const { payload } = await jose.jwtVerify(token, JWKS, verifyOptions);

      // Convert to our OidcClaims interface
      const claims: OidcClaims = {
        ...payload, // Include all other claims first
        sub: payload.sub!,
        iss: payload.iss!,
        aud: payload.aud ? (Array.isArray(payload.aud) ? payload.aud : [payload.aud]) : [], // Handle missing aud gracefully
        exp: payload.exp!,
        iat: payload.iat!
      };

      // Log audience validation status
      if (!shouldValidateAudience) {
        console.log(`⚠️  Audience validation disabled for ${this.config.name}`);
      } else if (!this.config.audience) {
        console.log(`⚠️  No audience configured for ${this.config.name} - skipping audience validation`);
      } else {
        const expectedAud = Array.isArray(this.config.audience) ? this.config.audience : [this.config.audience];
        console.log(`✅ Audience validated: ${claims.aud} matches expected ${expectedAud.join(' or ')}`);
      }
      
      console.log(`✅ JWT validation successful for subject: ${claims.sub}`);
      return claims;

    } catch (error) {
      // Handle jose errors
      if (error instanceof Error) {
        throw new Error(`JWT validation failed: ${error.message}`);
      } else {
        throw new Error(`OIDC validation error: ${String(error)}`);
      }
    }
  }

  // Utility method to check if we can validate tokens for this issuer
  async healthCheck(): Promise<boolean> {
    try {
      // Try to fetch JWKS directly to verify the endpoint is accessible
      const response = await fetch(this.config.jwksUri);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const jwks = await response.json() as { keys?: unknown[] };
      return !!(jwks.keys && Array.isArray(jwks.keys) && jwks.keys.length > 0);
    } catch (error) {
      console.warn(`JWKS health check failed for ${this.config.issuer}: ${error}`);
      return false;
    }
  }
}