import { AccessProvider, AccessProviderConfiguration, CredentialRequest, CredentialResponse } from './base';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';

export interface MinIOConfiguration extends AccessProviderConfiguration {
  type: 'minio-sts';
  endpoint: string;
  region?: string;
  roleArn?: string; // MinIO role ARN for AssumeRoleWithWebIdentity
  brokerAuth: {
    tokenSource: 'broker-oidc';
    // Broker OIDC token validation settings
    expectedIssuer: string;
    expectedAudience: string;
    jwksUri?: string; // Optional for now - will be required when signature validation is implemented
  };
}

export interface MinIOKeyConfiguration {
  provider: string;
  policy?: string;
  role?: string;
  duration?: number;
  outputs: { [envVarName: string]: string };
}

export class MinIOProvider extends AccessProvider {
  protected config: MinIOConfiguration;

  constructor(config: MinIOConfiguration) {
    super(config);
    this.config = config;
  }

  getName(): string {
    return this.config.name;
  }

  getType(): string {
    return 'minio-sts';
  }

  async mintCredential(request: CredentialRequest): Promise<CredentialResponse> {
    this.validateKeyConfig(request.keyConfig);
    
    // Broker OIDC token validation is mandatory
    if (!request.brokerToken) {
      throw new Error('Broker OIDC token is required for MinIO credential minting');
    }
    
    await this.validateBrokerToken(request.brokerToken);
    
    const keyConfig = request.keyConfig as MinIOKeyConfiguration;
    const duration = keyConfig.duration || this.getDefaultDuration();
    
    console.log(`🔄 MinIO Provider: Minting credentials for key "${request.keyName}" (subject: ${request.subject})`);
    
    if (!keyConfig.role) {
      throw new Error(`MinIO key configuration must specify a role for key "${request.keyName}"`);
    }
    
    try {
      // Use MinIO STS AssumeRoleWithWebIdentity to get temporary credentials
      const stsResult = await this.createServiceAccount(
        request.brokerToken, // Pass the broker's OIDC token
        '', // Not used anymore
        keyConfig.role,
        duration
      );
      
      console.log(`✅ MinIO Provider: Got STS credentials with role ${keyConfig.role}`);
      
      // Map the STS response to the configured output environment variables
      const credentials: { [envVarName: string]: string } = {};
      
      for (const [envVar, fieldPath] of Object.entries(keyConfig.outputs)) {
        switch (fieldPath) {
          case 'AccessKeyId':
            credentials[envVar] = stsResult.accessKey;
            break;
          case 'SecretAccessKey':
            credentials[envVar] = stsResult.secretKey;
            break;
          case 'SessionToken':
            credentials[envVar] = stsResult.sessionToken || '';
            break;
          case 'Expiration':
            credentials[envVar] = stsResult.expiration || new Date(Date.now() + (duration * 1000)).toISOString();
            break;
          case 'Endpoint':
            credentials[envVar] = this.config.endpoint;
            break;
          default:
            console.warn(`⚠️  MinIO Provider: Unknown field path "${fieldPath}" for env var "${envVar}"`);
        }
      }
      
      return {
        credentials,
        expiresAt: stsResult.expiration || new Date(Date.now() + (duration * 1000)).toISOString(),
        metadata: {
          provider: this.getName(),
          keyName: request.keyName,
          tempAccessKey: stsResult.accessKey,
          role: keyConfig.role
        }
      };
      
    } catch (error) {
      console.error(`❌ MinIO Provider: Failed to mint credentials for key "${request.keyName}":`, error);
      throw new Error(`MinIO credential minting failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      // Simple health check - verify we can reach MinIO endpoint
      const fetch = require('node-fetch');
      const response = await fetch(`${this.config.endpoint}/minio/health/live`);
      return response.ok;
    } catch (error) {
      console.error('MinIO health check failed:', error);
      return false;
    }
  }


  private async createServiceAccount(accessKey: string, secretKey: string, policy: string, duration?: number): Promise<any> {
    try {
      // Use MinIO STS AssumeRoleWithWebIdentity to get temporary credentials using OIDC token
      console.log(`🔧 MinIO Provider: Creating temporary credentials via STS AssumeRoleWithWebIdentity`);
      
      const actualDuration = duration || this.getDefaultDuration();
      
      // MinIO STS endpoint format
      const stsEndpoint = `${this.config.endpoint}`;
      
      // Prepare the STS request parameters
      const params = new URLSearchParams({
        'Action': 'AssumeRoleWithWebIdentity',
        'Version': '2011-06-15',
        'DurationSeconds': actualDuration.toString(),
        'WebIdentityToken': accessKey, // Pass the broker's OIDC token as WebIdentityToken
        // No inline policy - MinIO will use the role/policy configured for the OIDC token
      });
      
      // If MinIO is configured with a role ARN, include it
      if (this.config.roleArn) {
        params.append('RoleArn', this.config.roleArn);
      }
      
      console.log(`🔧 MinIO STS Request URL: ${stsEndpoint}?${params.toString()}`);
      console.log(`🔧 MinIO STS Authorization: Bearer ${accessKey.substring(0, 20)}...`);
      
      const fetch = require('node-fetch');
      const response = await fetch(`${stsEndpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: params.toString() // Send parameters in body for POST request
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`❌ MinIO STS error: ${response.status} - ${errorText}`);
        throw new Error(`MinIO STS request failed: ${response.status} ${response.statusText}`);
      }
      
      const responseText = await response.text();
      console.log(`✅ MinIO Provider: Received STS response`);
      
      // Parse the XML response
      const credentials = await this.parseSTSResponse(responseText);
      
      return {
        accessKey: credentials.AccessKeyId,
        secretKey: credentials.SecretAccessKey,
        sessionToken: credentials.SessionToken,
        expiration: credentials.Expiration,
        policy
      };
    } catch (error) {
      console.error('Failed to create MinIO temporary credentials:', error);
      throw new Error(`Credential creation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private generateAWSSignature(method: string, path: string, body: string): string {
    // Generate AWS Signature V4 for MinIO STS request
    // This method is no longer used with OIDC-only authentication
    // In a full implementation, this would use the broker's OIDC token for MinIO API calls
    throw new Error('Legacy AWS signature generation is not supported with OIDC-only authentication');
  }


  private async parseSTSResponse(responseText: string): Promise<any> {
    // Parse the XML response from MinIO STS
    // MinIO STS returns XML similar to AWS STS
    
    // Simple XML parsing - in production, use a proper XML parser
    const accessKeyMatch = responseText.match(/<AccessKeyId>(.*?)<\/AccessKeyId>/);
    const secretKeyMatch = responseText.match(/<SecretAccessKey>(.*?)<\/SecretAccessKey>/);
    const sessionTokenMatch = responseText.match(/<SessionToken>(.*?)<\/SessionToken>/);
    const expirationMatch = responseText.match(/<Expiration>(.*?)<\/Expiration>/);

    if (!accessKeyMatch || !secretKeyMatch) {
      throw new Error('Invalid STS response: missing credentials');
    }

    return {
      AccessKeyId: accessKeyMatch[1],
      SecretAccessKey: secretKeyMatch[1],
      SessionToken: sessionTokenMatch ? sessionTokenMatch[1] : undefined,
      Expiration: expirationMatch ? expirationMatch[1] : undefined
    };
  }

  // Method to cleanup service account (for proper credential lifecycle)
  async cleanupServiceAccount(accessKey: string): Promise<void> {
    // Note: STS temporary credentials automatically expire and don't need manual cleanup
    // This method is kept for compatibility but no action is needed
    console.log(`🧹 MinIO Provider: STS credentials for ${accessKey} will auto-expire (no cleanup needed)`);
  }

  private async validateBrokerToken(token: string): Promise<void> {
    try {
      console.log('🔐 MinIO Provider: Validating broker OIDC token');
      
      // Decode token to get header and payload
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        throw new Error('Invalid JWT token format');
      }

      const payload = decoded.payload as any;
      
      // Validate basic JWT structure - aud is optional since some IdPs don't include it
      if (!payload.iss || !payload.exp) {
        throw new Error('JWT missing required claims (iss, exp)');
      }

      // Check expiration
      if (Date.now() >= payload.exp * 1000) {
        throw new Error('Broker token has expired');
      }

      // Validate issuer (required)
      if (payload.iss !== this.config.brokerAuth.expectedIssuer) {
        throw new Error(`Invalid issuer: expected ${this.config.brokerAuth.expectedIssuer}, got ${payload.iss}`);
      }

      // Validate audience (optional - only if present in token)
      if (payload.aud) {
        const tokenAudience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!tokenAudience.includes(this.config.brokerAuth.expectedAudience)) {
          throw new Error(`Invalid audience: expected ${this.config.brokerAuth.expectedAudience}, got ${tokenAudience.join(', ')}`);
        }
        console.log(`✅ MinIO Provider: Audience validated: ${tokenAudience.join(', ')}`);
      } else {
        console.log(`⚠️  MinIO Provider: No audience claim in broker token - skipping audience validation`);
      }

      // TODO: Validate signature against JWKS if configured
      // For now, we'll do basic validation and trust the broker
      if (this.config.brokerAuth.jwksUri) {
        console.log('🔍 MinIO Provider: JWKS validation not yet implemented - trusting broker token');
        // In production, implement full JWKS signature validation here
      }

      console.log('✅ MinIO Provider: Broker token validated successfully');
      console.log(`   Subject: ${payload.sub || 'not provided'}`);
      console.log(`   Issuer: ${payload.iss}`);
      console.log(`   Audience: ${payload.aud ? (Array.isArray(payload.aud) ? payload.aud.join(', ') : payload.aud) : 'none'}`);
      
    } catch (error) {
      console.error('❌ MinIO Provider: Broker token validation failed:', error);
      throw new Error(`Broker authentication failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}