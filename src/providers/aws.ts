import { AccessProvider, AccessProviderConfiguration, CredentialRequest, CredentialResponse } from './base';

export interface AWSConfiguration extends AccessProviderConfiguration {
  type: 'aws-sts';
  endpoint: string;
  region: string;
  roleArn?: string; // AWS role ARN for AssumeRoleWithWebIdentity
  brokerAuth: {
    tokenSource: 'broker-oidc';
    // Broker OIDC token validation settings
    expectedIssuer: string;
    expectedAudience: string;
    jwksUri?: string; // Optional for now - will be required when signature validation is implemented
  };
}

export interface AWSKeyConfiguration {
  provider: string;
  roleArn: string;
  roleSessionName?: string;
  policy?: string;
  duration?: number;
  externalId?: string;
  outputs: { [envVarName: string]: string };
}

export class AWSProvider extends AccessProvider {
  protected config: AWSConfiguration;

  constructor(config: AWSConfiguration) {
    super(config);
    this.config = config;
  }

  getName(): string {
    return this.config.name;
  }

  getType(): string {
    return 'aws-sts';
  }

  async mintCredential(request: CredentialRequest): Promise<CredentialResponse> {
    this.validateKeyConfig(request.keyConfig);
    
    // Broker OIDC token validation is mandatory
    if (!request.brokerToken) {
      throw new Error('Broker OIDC token is required for AWS credential minting');
    }
    
    await this.validateBrokerToken(request.brokerToken);
    
    const keyConfig = request.keyConfig as AWSKeyConfiguration;
    const duration = keyConfig.duration || this.getDefaultDuration();
    
    console.log(`🔄 AWS Provider: Minting credentials for key "${request.keyName}" (subject: ${request.subject})`);
    console.log(`📝 AWS Provider: Role ARN: ${keyConfig.roleArn}`);
    
    try {
      // Use AWS STS AssumeRoleWithWebIdentity to get temporary credentials using OIDC token
      const stsResult = await this.assumeRoleWithWebIdentity(
        request.brokerToken,
        keyConfig.roleArn,
        keyConfig.roleSessionName || `voidkey-${request.subject}-${Date.now()}`,
        keyConfig.policy,
        duration
      );
      
      console.log(`✅ AWS Provider: Got STS credentials for role ${keyConfig.roleArn}`);
      
      // Map the STS response to the configured output environment variables
      const credentials: { [envVarName: string]: string } = {};
      
      for (const [envVar, fieldPath] of Object.entries(keyConfig.outputs)) {
        switch (fieldPath) {
          case 'AccessKeyId':
            credentials[envVar] = stsResult.AccessKeyId;
            break;
          case 'SecretAccessKey':
            credentials[envVar] = stsResult.SecretAccessKey;
            break;
          case 'SessionToken':
            credentials[envVar] = stsResult.SessionToken || '';
            break;
          case 'Expiration':
            credentials[envVar] = stsResult.Expiration || new Date(Date.now() + (duration * 1000)).toISOString();
            break;
          default:
            console.warn(`⚠️  AWS Provider: Unknown field path "${fieldPath}" for env var "${envVar}"`);
        }
      }
      
      return {
        credentials,
        expiresAt: stsResult.Expiration || new Date(Date.now() + (duration * 1000)).toISOString(),
        metadata: {
          provider: this.getName(),
          keyName: request.keyName,
          roleArn: keyConfig.roleArn,
          roleSessionName: keyConfig.roleSessionName
        }
      };
      
    } catch (error) {
      console.error(`❌ AWS Provider: Failed to mint credentials for key "${request.keyName}":`, error);
      throw new Error(`AWS credential minting failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      // TODO: Implement AWS STS health check
      // Could call GetCallerIdentity to verify broker credentials work
      console.log('AWS health check not yet implemented');
      return true; // Placeholder
    } catch (error) {
      console.error('AWS health check failed:', error);
      return false;
    }
  }

  private async assumeRoleWithWebIdentity(
    brokerToken: string,
    roleArn: string,
    roleSessionName: string,
    policy?: string,
    duration?: number
  ): Promise<any> {
    try {
      console.log(`🔧 AWS Provider: Assuming role via AssumeRoleWithWebIdentity`);
      
      const actualDuration = duration || this.getDefaultDuration();
      
      // AWS STS endpoint format
      const stsEndpoint = this.config.endpoint;
      
      // Prepare the STS request parameters
      const params = new URLSearchParams({
        'Action': 'AssumeRoleWithWebIdentity',
        'Version': '2011-06-15',
        'RoleArn': roleArn,
        'RoleSessionName': roleSessionName,
        'DurationSeconds': actualDuration.toString(),
        'WebIdentityToken': brokerToken
      });
      
      // Add optional policy
      if (policy) {
        params.append('Policy', policy);
      }
      
      // Add role ARN from config if available
      if (this.config.roleArn) {
        params.append('RoleArn', this.config.roleArn);
      }
      
      const fetch = require('node-fetch');
      const response = await fetch(`${stsEndpoint}?${params.toString()}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`❌ AWS STS error: ${response.status} - ${errorText}`);
        throw new Error(`AWS STS request failed: ${response.status} ${response.statusText}`);
      }
      
      const responseText = await response.text();
      console.log(`✅ AWS Provider: Received STS response`);
      
      // Parse the XML response
      const credentials = await this.parseSTSResponse(responseText);
      
      return credentials;
    } catch (error) {
      console.error('Failed to assume AWS role with web identity:', error);
      throw new Error(`AWS role assumption failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async parseSTSResponse(responseText: string): Promise<any> {
    // Parse the XML response from AWS STS
    // AWS STS returns XML similar to MinIO
    
    // Simple XML parsing - in production, use a proper XML parser
    const accessKeyMatch = responseText.match(/<AccessKeyId>(.*?)<\/AccessKeyId>/);
    const secretKeyMatch = responseText.match(/<SecretAccessKey>(.*?)<\/SecretAccessKey>/);
    const sessionTokenMatch = responseText.match(/<SessionToken>(.*?)<\/SessionToken>/);
    const expirationMatch = responseText.match(/<Expiration>(.*?)<\/Expiration>/);

    if (!accessKeyMatch || !secretKeyMatch) {
      throw new Error('Invalid AWS STS response: missing credentials');
    }

    return {
      AccessKeyId: accessKeyMatch[1],
      SecretAccessKey: secretKeyMatch[1],
      SessionToken: sessionTokenMatch ? sessionTokenMatch[1] : undefined,
      Expiration: expirationMatch ? expirationMatch[1] : undefined
    };
  }

  private async validateBrokerToken(token: string): Promise<void> {
    try {
      console.log('🔐 AWS Provider: Validating broker OIDC token');
      
      const jwt = require('jsonwebtoken');
      
      // Decode token to get header and payload
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        throw new Error('Invalid JWT token format');
      }

      const payload = decoded.payload as any;
      
      // Validate basic JWT structure
      if (!payload.iss || !payload.aud || !payload.exp) {
        throw new Error('JWT missing required claims (iss, aud, exp)');
      }

      // Check expiration
      if (Date.now() >= payload.exp * 1000) {
        throw new Error('Broker token has expired');
      }

      // Validate issuer (required)
      if (payload.iss !== this.config.brokerAuth.expectedIssuer) {
        throw new Error(`Invalid issuer: expected ${this.config.brokerAuth.expectedIssuer}, got ${payload.iss}`);
      }

      // Validate audience (required)
      const tokenAudience = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!tokenAudience.includes(this.config.brokerAuth.expectedAudience)) {
        throw new Error(`Invalid audience: expected ${this.config.brokerAuth.expectedAudience}, got ${tokenAudience.join(', ')}`);
      }

      // TODO: Validate signature against JWKS if configured
      // For now, we'll do basic validation and trust the broker
      if (this.config.brokerAuth.jwksUri) {
        console.log('🔍 AWS Provider: JWKS validation not yet implemented - trusting broker token');
        // In production, implement full JWKS signature validation here
      }

      console.log('✅ AWS Provider: Broker token validated successfully');
      console.log(`   Subject: ${payload.sub || 'not provided'}`);
      console.log(`   Issuer: ${payload.iss}`);
      console.log(`   Audience: ${Array.isArray(payload.aud) ? payload.aud.join(', ') : payload.aud}`);
      
    } catch (error) {
      console.error('❌ AWS Provider: Broker token validation failed:', error);
      throw new Error(`Broker authentication failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}