import { BrokerAuthProvider } from './broker-auth-provider';
import * as jwt from 'jsonwebtoken';

export interface ClientCredentialsConfig {
  name: string;
  clientId: string;
  clientSecret: string;
  tokenEndpoint: string;
  audience?: string;
  scope?: string;
}

/**
 * Client credentials OAuth2 flow for broker authentication
 */
export class ClientCredentialsProvider implements BrokerAuthProvider {
  constructor(private config: ClientCredentialsConfig) {}

  getType(): string {
    return 'client-credentials';
  }

  getName(): string {
    return this.config.name;
  }

  async acquireToken(): Promise<string> {
    const tokenRequest: any = {
      grant_type: 'client_credentials',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    };

    if (this.config.audience) {
      tokenRequest.audience = this.config.audience;
    }

    if (this.config.scope) {
      tokenRequest.scope = this.config.scope;
    }

    const fetch = (global as any).__TEST_FETCH__ || require('node-fetch');
    const response = await fetch(this.config.tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(tokenRequest).toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to acquire broker token: ${response.status} ${errorText}`);
    }

    const tokenData = await response.json() as any;
    
    if (!tokenData.access_token) {
      throw new Error('No access_token in broker token response');
    }

    return tokenData.access_token;
  }

  async isTokenValid(token: string): Promise<boolean> {
    try {
      const decoded = jwt.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return false;
      }
      
      // Check if token is expired (with 30 second buffer)
      return Date.now() < (decoded.exp * 1000 - 30000);
    } catch {
      return false;
    }
  }

  async getTokenExpiry(token: string): Promise<number | null> {
    try {
      const decoded = jwt.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return null;
      }
      
      return decoded.exp * 1000;
    } catch {
      return null;
    }
  }
}