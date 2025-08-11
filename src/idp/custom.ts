import { IdpProvider } from './base';
import { OidcClaims } from '../types';
import { JwksTokenValidator } from '../jwks/jwks-client';

export class CustomIdpProvider extends IdpProvider {
  private jwksValidator: JwksTokenValidator;

  constructor(config: any) {
    super(config);
    this.jwksValidator = new JwksTokenValidator(config);
  }

  async validateToken(token: string): Promise<OidcClaims> {
    console.log(`🔐 Validating custom IdP token for ${this.config.name} (real JWT validation)`);
    
    try {
      const claims = await this.jwksValidator.validateToken(token);
      console.log(`✅ ${this.config.name} token validated for subject: ${claims.sub}`);
      
      // Add provider information to claims
      return {
        ...claims,
        provider: this.config.name
      };
    } catch (error) {
      console.error(`❌ ${this.config.name} token validation failed: ${error}`);
      throw error;
    }
  }

  async healthCheck(): Promise<boolean> {
    return await this.jwksValidator.healthCheck();
  }
}