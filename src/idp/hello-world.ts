import { IdpProvider } from './base';
import { IdpConfiguration, OidcClaims } from '../types';

export class HelloWorldProvider extends IdpProvider {
  constructor() {
    const config: IdpConfiguration = {
      name: 'hello-world',
      issuer: 'hello-world-idp',
      audience: 'hello-world-audience',
      jwksUri: 'dummy://hello-world/jwks',
      algorithms: ['HS256']
    };
    super(config);
  }

  async validateToken(token: string): Promise<OidcClaims> {
    // Hello World provider bypasses all external validation
    // It accepts any token and returns mock claims for testing
    console.log('🎭 Hello World IdP: Bypassing external validation');
    console.log(`📝 Received token: ${token.substring(0, 20)}...`);

    // Check for the specific hello-world token format
    if (token === 'cli-hello-world-token') {
      console.log('✨ Recognized CLI hello-world token');
    } else {
      console.log('✨ Processing custom token in hello-world mode');
    }

    // Return mock claims without any validation
    const mockClaims: OidcClaims = {
      sub: 'hello-world-user',
      iss: 'hello-world-idp',
      aud: 'hello-world-audience',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      iat: Math.floor(Date.now() / 1000),
      email: 'hello@world.dev',
      name: 'Hello World User',
      preferred_username: 'hello-world',
      custom_claim: 'This is a test token from hello-world IdP'
    };

    console.log('🎉 Hello World IdP validation successful');
    return mockClaims;
  }

  async healthCheck(): Promise<boolean> {
    // Hello World provider is always healthy since it doesn't depend on external services
    console.log('💚 Hello World IdP health check: Always healthy');
    return true;
  }
}