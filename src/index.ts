import { IdpConfiguration, AccessProviderConfiguration, KeyConfiguration, BrokerIdpConfiguration } from './types';
import { IdpProvider, CustomIdpProvider, HelloWorldProvider } from './idp';
import { IdpConfigLoader, IdpConfigFile } from './config/idp-config';
import { AccessProvider, createProvider, CredentialRequest, CredentialResponse } from './providers';
import { BrokerAuthProvider, ClientCredentialsProvider, ClientCredentialsConfig } from './auth';

export { OidcClaims, IdpConfiguration, Identity, GeneralConfiguration, BrokerIdpConfiguration, ClientIdentity, KeyConfiguration, AccessProviderConfiguration } from './types';
export { IdpProvider } from './idp';
export { IdpConfigLoader, IdpConfigFile } from './config/idp-config';
export { AccessProvider, CredentialRequest, CredentialResponse, CredentialOutput, createProvider } from './providers';
export { BrokerAuthProvider, ClientCredentialsProvider, ClientCredentialsConfig } from './auth';

export class CredentialBroker {
  private idpProviders: Map<string, IdpProvider> = new Map();
  private accessProviders: Map<string, AccessProvider> = new Map();
  private defaultIdpName?: string;
  private clientIdentities: Map<string, { idp: string; keys: { [keyName: string]: KeyConfiguration } }> = new Map();
  private brokerToken?: string;
  private brokerTokenExpiry?: number;
  private brokerIdpConfig?: BrokerIdpConfiguration;
  private brokerAuthProvider?: BrokerAuthProvider;

  constructor(brokerAuthProvider?: BrokerAuthProvider) {
    // Allow injection of auth provider
    this.brokerAuthProvider = brokerAuthProvider;
    
    // Add built-in hello-world provider for testing/demo purposes
    this.addBuiltInProviders();
  }

  private addBuiltInProviders(): void {
    // Add hello-world provider for testing/demo purposes
    const helloWorldProvider = new HelloWorldProvider();
    this.addIdpProvider(helloWorldProvider);
    
    // Set hello-world as default until user configures real IdPs
    this.setDefaultIdp('hello-world');
  }

  /**
   * Set the broker authentication provider
   * This allows the broker-server to inject its own auth logic
   */
  setBrokerAuthProvider(provider: BrokerAuthProvider): void {
    this.brokerAuthProvider = provider;
  }

  addIdpProvider(provider: IdpProvider): void {
    this.idpProviders.set(provider.getName(), provider);
  }

  addAccessProvider(provider: AccessProvider): void {
    this.accessProviders.set(provider.getName(), provider);
  }

  getAccessProvider(name: string): AccessProvider {
    const provider = this.accessProviders.get(name);
    if (!provider) {
      throw new Error(`Access provider '${name}' not found`);
    }
    return provider;
  }

  listAccessProviders(): Array<{ name: string; type: string }> {
    const providers = [];
    for (const [name, provider] of this.accessProviders) {
      providers.push({
        name,
        type: provider.getType()
      });
    }
    return providers.sort((a, b) => a.name.localeCompare(b.name));
  }

  loadIdpConfigFromFile(configPath: string): void {
    const config = IdpConfigLoader.loadFromFile(configPath);
    this.loadIdpConfig(config);
  }

  loadIdpConfigFromString(yamlContent: string): void {
    const config = IdpConfigLoader.loadFromString(yamlContent);
    this.loadIdpConfig(config);
  }

  private loadIdpConfig(config: IdpConfigFile): void {
    // Broker IdP configuration is mandatory for OIDC authentication
    if (!config.brokerIdp) {
      throw new Error('Broker IdP configuration is required. The broker must authenticate with its own IdP to mint credentials.');
    }
    
    console.log(`✅ Loading broker IdP: ${config.brokerIdp.name}`);
    this.brokerIdpConfig = config.brokerIdp;
    
    // If no auth provider is set, create default client credentials provider
    if (!this.brokerAuthProvider && config.brokerIdp.clientId && config.brokerIdp.clientSecret) {
      console.log('🔐 Creating default client credentials auth provider');
      this.brokerAuthProvider = new ClientCredentialsProvider({
        name: config.brokerIdp.name,
        clientId: config.brokerIdp.clientId,
        clientSecret: config.brokerIdp.clientSecret,
        tokenEndpoint: config.brokerIdp.tokenEndpoint,
        audience: config.brokerIdp.audience
      });
    }

    // Handle client IdPs configuration  
    const clientIdps = config.clientIdps || [];
    
    // Add all client IdP providers from config
    clientIdps.forEach((idpConfig: IdpConfiguration) => {
      const provider = new CustomIdpProvider(idpConfig);
      this.addIdpProvider(provider);
    });

    // Load access providers for credential minting
    if (config.accessProviders) {
      console.log(`Loading ${config.accessProviders.length} access providers`);
      config.accessProviders.forEach(providerConfig => {
        try {
          const provider = createProvider(providerConfig);
          this.addAccessProvider(provider);
          console.log(`✅ Loaded access provider: ${provider.getName()} (${provider.getType()})`);
        } catch (error) {
          console.error(`❌ Failed to load access provider ${providerConfig.name}:`, error);
        }
      });
    }

    // Load client identities
    if (config.clientIdentities) {
      console.log(`Loading ${config.clientIdentities.length} client identities`);
      config.clientIdentities.forEach(identity => {
        this.clientIdentities.set(identity.subject, {
          idp: identity.idp,
          keys: identity.keys
        });
      });
    }

    // Set default IdP if specified
    if (config.default) {
      this.setDefaultIdp(config.default);
    }
  }

  setDefaultIdp(name: string): void {
    if (this.idpProviders.has(name)) {
      this.defaultIdpName = name;
    } else {
      throw new Error(`IdP provider '${name}' not found`);
    }
  }

  listIdpProviders(): Array<{ name: string; isDefault: boolean }> {
    const providers = [];
    for (const [name, provider] of this.idpProviders) {
      providers.push({
        name,
        isDefault: name === this.defaultIdpName
      });
    }
    return providers.sort((a, b) => a.name.localeCompare(b.name));
  }

  // Key-based methods
  getAvailableKeys(subject: string): string[] {
    const identityConfig = this.clientIdentities.get(subject);
    if (!identityConfig?.keys) {
      return [];
    }
    return Object.keys(identityConfig.keys);
  }

  getKeyConfiguration(subject: string, keyName: string): KeyConfiguration | null {
    const identityConfig = this.clientIdentities.get(subject);
    if (!identityConfig?.keys) {
      return null;
    }
    return identityConfig.keys[keyName] || null;
  }

  getIdpProvider(name?: string): IdpProvider {
    const providerName = name || this.defaultIdpName;
    if (!providerName) {
      throw new Error('No default IdP provider configured');
    }
    
    const provider = this.idpProviders.get(providerName);
    if (!provider) {
      throw new Error(`IdP provider '${providerName}' not found`);
    }
    
    return provider;
  }

  // Key-based credential minting
  async mintKey(oidcToken: string, keyName: string, idpName?: string, duration?: number): Promise<CredentialResponse> {
    try {
      // Validate the OIDC token first
      const idpProvider = this.getIdpProvider(idpName);
      const claims = await idpProvider.validateToken(oidcToken);
      
      console.log('🎉 Token validated for subject:', claims.sub);
      console.log('🔍 Using IdP:', idpProvider.getName());
      
      // Special handling for hello-world provider (demo/testing)
      if (idpProvider.getName() === 'hello-world') {
        console.log('✅ Using hello-world provider - bypassing key configuration checks');
        // Return mock credentials for hello-world
        return {
          credentials: {
            'HELLO_ACCESS_KEY': 'AKIAIOSFODNN7EXAMPLE',
            'HELLO_SECRET_KEY': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'HELLO_SESSION_TOKEN': 'hello-world-session-token'
          },
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
          metadata: {
            provider: 'hello-world',
            keyName: keyName
          }
        };
      }
      
      // Check if the identity is configured
      const identityConfig = this.clientIdentities.get(claims.sub);
      if (!identityConfig) {
        throw new Error(`Identity '${claims.sub}' is not configured`);
      }
      
      // Verify the identity is configured for the correct IdP
      if (identityConfig.idp !== idpProvider.getName()) {
        throw new Error(`Identity '${claims.sub}' is configured for IdP '${identityConfig.idp}', but token was validated by '${idpProvider.getName()}'`);
      }
      
      console.log('✅ Identity is configured:', claims.sub);
      
      // Get the key configuration
      const keyConfig = identityConfig.keys[keyName];
      if (!keyConfig) {
        const availableKeys = Object.keys(identityConfig.keys);
        throw new Error(`Key "${keyName}" not found for identity "${claims.sub}". Available keys: ${availableKeys.join(', ')}`);
      }
      
      console.log(`🔑 Found key configuration for "${keyName}"`);
      console.log(`🎯 Provider: ${keyConfig.provider}`);
      
      // Override duration if provided
      if (duration) {
        keyConfig.duration = duration;
      }
      
      // Get the access provider
      const accessProvider = this.getAccessProvider(keyConfig.provider);
      
      // Ensure we have a valid broker token for authentication
      const brokerToken = await this.ensureValidBrokerToken();
      
      // Create the credential request
      const request: CredentialRequest = {
        subject: claims.sub,
        keyName: keyName,
        keyConfig: keyConfig,
        brokerToken: brokerToken,
        claims: claims
      };
      
      // Mint the credential using the access provider
      console.log(`🔄 Minting credential via ${accessProvider.getName()} (${accessProvider.getType()})`);
      const response = await accessProvider.mintCredential(request);
      
      console.log(`✅ Successfully minted credential for key "${keyName}"`);
      console.log(`📊 Credential expires at: ${response.expiresAt}`);
      
      return response;
      
    } catch (error) {
      console.error('❌ Key minting failed:', error);
      throw new Error(`Key minting failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Mint multiple keys at once
  async mintKeys(oidcToken: string, keyNames: string[], idpName?: string, duration?: number): Promise<{ [keyName: string]: CredentialResponse }> {
    const results: { [keyName: string]: CredentialResponse } = {};
    const errors: { [keyName: string]: string } = {};
    
    console.log(`🔄 Minting ${keyNames.length} keys: ${keyNames.join(', ')}`);
    
    for (const keyName of keyNames) {
      try {
        results[keyName] = await this.mintKey(oidcToken, keyName, idpName, duration);
      } catch (error) {
        errors[keyName] = error instanceof Error ? error.message : String(error);
        console.error(`❌ Failed to mint key "${keyName}":`, error);
      }
    }
    
    if (Object.keys(errors).length > 0) {
      console.warn(`⚠️  Some keys failed to mint:`, errors);
    }
    
    console.log(`✅ Successfully minted ${Object.keys(results).length}/${keyNames.length} keys`);
    return results;
  }


  async healthCheckIdpProvider(idpName?: string): Promise<{ provider: string; healthy: boolean; error?: string }> {
    try {
      const idpProvider = this.getIdpProvider(idpName);
      const providerName = idpProvider.getName();
      
      if (idpProvider.healthCheck) {
        const healthy = await idpProvider.healthCheck();
        return { provider: providerName, healthy };
      } else {
        // If no health check method, assume healthy
        return { provider: providerName, healthy: true };
      }
    } catch (error) {
      const providerName = idpName || this.defaultIdpName || 'unknown';
      return { 
        provider: providerName, 
        healthy: false, 
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  async healthCheckAllProviders(): Promise<Array<{ provider: string; healthy: boolean; error?: string }>> {
    const results = [];
    
    for (const [name, provider] of this.idpProviders) {
      try {
        if (provider.healthCheck) {
          const healthy = await provider.healthCheck();
          results.push({ provider: name, healthy });
        } else {
          results.push({ provider: name, healthy: true });
        }
      } catch (error) {
        results.push({ 
          provider: name, 
          healthy: false, 
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    
    return results;
  }

  // Broker OIDC token management
  private async acquireBrokerToken(): Promise<string> {
    if (!this.brokerAuthProvider) {
      // Fallback to legacy method if auth provider not set
      if (!this.brokerIdpConfig) {
        throw new Error('No broker authentication provider configured');
      }
      
      console.warn('⚠️  Using legacy broker authentication method. Consider using auth providers.');
      
      const tokenRequest = {
        grant_type: 'client_credentials',
        client_id: this.brokerIdpConfig.clientId,
        client_secret: this.brokerIdpConfig.clientSecret,
        audience: this.brokerIdpConfig.audience
      };

      const fetch = require('node-fetch');
      const response = await fetch(this.brokerIdpConfig.tokenEndpoint, {
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

      // Store token and calculate expiry (with 30 second buffer)
      this.brokerToken = tokenData.access_token;
      const expiresIn = tokenData.expires_in || 3600;
      this.brokerTokenExpiry = Date.now() + (expiresIn - 30) * 1000;

      console.log(`✅ Broker token acquired (legacy), expires in ${expiresIn} seconds`);
      return this.brokerToken!;
    }

    // Use the auth provider
    console.log(`🔐 Acquiring broker token via ${this.brokerAuthProvider.getName()} (${this.brokerAuthProvider.getType()})`);
    
    const token = await this.brokerAuthProvider.acquireToken();
    this.brokerToken = token;
    
    // Get expiry from the token
    const expiry = await this.brokerAuthProvider.getTokenExpiry(token);
    if (expiry) {
      this.brokerTokenExpiry = expiry - 30000; // 30 second buffer
    } else {
      // No expiry info, assume 1 hour
      this.brokerTokenExpiry = Date.now() + 3570000; // 59.5 minutes
    }
    
    console.log(`✅ Broker token acquired via auth provider`);
    return token;
  }

  private async ensureValidBrokerToken(): Promise<string> {
    // If we have an auth provider, use it to validate the token
    if (this.brokerAuthProvider && this.brokerToken) {
      const isValid = await this.brokerAuthProvider.isTokenValid(this.brokerToken);
      if (isValid) {
        return this.brokerToken;
      }
    } else if (this.brokerToken && this.brokerTokenExpiry && Date.now() < this.brokerTokenExpiry) {
      // Legacy check: token exists and not expired
      return this.brokerToken;
    }

    // Token is missing or expired, acquire a new one
    console.log('🔄 Broker token missing or expired, acquiring new token');
    return await this.acquireBrokerToken();
  }

  async getBrokerToken(): Promise<string> {
    return await this.ensureValidBrokerToken();
  }
}