import * as yaml from 'js-yaml';
import * as fs from 'fs';
import * as path from 'path';
import { IdpConfiguration, GeneralConfiguration } from '../types';

export interface IdpConfigFile extends GeneralConfiguration {
}

export class IdpConfigLoader {
  static loadFromFile(configPath: string): IdpConfigFile {
    try {
      const configContent = fs.readFileSync(configPath, 'utf8');
      const config = yaml.load(configContent) as IdpConfigFile;
      
      // Handle empty or null config
      if (!config) {
        return {} as IdpConfigFile;
      }
      
      // Validate client IdP configurations if present
      if (config.clientIdps) {
        if (!Array.isArray(config.clientIdps)) {
          throw new Error('Invalid configuration: "clientIdps" must be an array');
        }
        config.clientIdps.forEach((idp, index) => {
          this.validateIdpConfig(idp, index);
        });
      }

      // Validate broker IdP configuration if present
      if (config.brokerIdp) {
        this.validateBrokerIdpConfig(config.brokerIdp);
      }

      // Validate access providers if present
      if (config.accessProviders) {
        if (!Array.isArray(config.accessProviders)) {
          throw new Error('Invalid configuration: "accessProviders" must be an array');
        }
        config.accessProviders.forEach((provider, index) => {
          this.validateAccessProvider(provider, index);
        });
      }

      // Validate client identities if present
      if (config.clientIdentities) {
        if (!Array.isArray(config.clientIdentities)) {
          throw new Error('Invalid configuration: "clientIdentities" must be an array');
        }
        config.clientIdentities.forEach((identity, index) => {
          this.validateClientIdentity(identity, index, config.clientIdps || [], config.accessProviders || []);
        });
      }

      return config;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to load IdP configuration from ${configPath}: ${error.message}`);
      }
      throw error;
    }
  }

  static loadFromString(yamlContent: string): IdpConfigFile {
    try {
      const config = yaml.load(yamlContent) as IdpConfigFile;
      
      // Handle empty or null config
      if (!config) {
        return {} as IdpConfigFile;
      }
      
      // Validate client IdP configurations if present
      if (config.clientIdps) {
        if (!Array.isArray(config.clientIdps)) {
          throw new Error('Invalid configuration: "clientIdps" must be an array');
        }
        config.clientIdps.forEach((idp, index) => {
          this.validateIdpConfig(idp, index);
        });
      }

      // Validate broker IdP configuration if present
      if (config.brokerIdp) {
        this.validateBrokerIdpConfig(config.brokerIdp);
      }

      // Validate access providers if present
      if (config.accessProviders) {
        if (!Array.isArray(config.accessProviders)) {
          throw new Error('Invalid configuration: "accessProviders" must be an array');
        }
        config.accessProviders.forEach((provider, index) => {
          this.validateAccessProvider(provider, index);
        });
      }

      // Validate client identities if present
      if (config.clientIdentities) {
        if (!Array.isArray(config.clientIdentities)) {
          throw new Error('Invalid configuration: "clientIdentities" must be an array');
        }
        config.clientIdentities.forEach((identity, index) => {
          this.validateClientIdentity(identity, index, config.clientIdps || [], config.accessProviders || []);
        });
      }

      return config;
    } catch (error) {
      if (error instanceof Error) {
        throw new Error(`Failed to parse IdP configuration: ${error.message}`);
      }
      throw error;
    }
  }

  private static validateIdpConfig(idp: any, index: number): void {
    const requiredFields = ['name', 'issuer', 'jwksUri'];
    
    for (const field of requiredFields) {
      if (!idp[field] || typeof idp[field] !== 'string') {
        throw new Error(`Invalid IdP configuration at index ${index}: missing or invalid "${field}" field`);
      }
    }

    // Validate optional audience field - can be string, array of strings, or undefined
    if (idp.audience !== undefined) {
      if (typeof idp.audience === 'string') {
        // Valid single audience
      } else if (Array.isArray(idp.audience)) {
        // Validate each audience in array
        if (idp.audience.length === 0) {
          throw new Error(`Invalid IdP configuration at index ${index}: "audience" array cannot be empty`);
        }
        for (let i = 0; i < idp.audience.length; i++) {
          if (typeof idp.audience[i] !== 'string') {
            throw new Error(`Invalid IdP configuration at index ${index}: "audience" array must contain only strings`);
          }
        }
      } else {
        throw new Error(`Invalid IdP configuration at index ${index}: "audience" must be a string or array of strings`);
      }
    }

    // Validate optional validateAudience field
    if (idp.validateAudience !== undefined && typeof idp.validateAudience !== 'boolean') {
      throw new Error(`Invalid IdP configuration at index ${index}: "validateAudience" must be a boolean`);
    }

    // Validate optional algorithms field
    if (idp.algorithms && !Array.isArray(idp.algorithms)) {
      throw new Error(`Invalid IdP configuration at index ${index}: "algorithms" must be an array`);
    }
  }

  private static validateBrokerIdpConfig(brokerIdp: any): void {
    // For now, broker IdP is a placeholder - no required fields
    if (brokerIdp.name && typeof brokerIdp.name !== 'string') {
      throw new Error('Invalid broker IdP configuration: "name" must be a string');
    }
    if (brokerIdp.issuer && typeof brokerIdp.issuer !== 'string') {
      throw new Error('Invalid broker IdP configuration: "issuer" must be a string');
    }
    // Validate optional audience field - can be string, array of strings, or undefined
    if (brokerIdp.audience !== undefined) {
      if (typeof brokerIdp.audience === 'string') {
        // Valid single audience
      } else if (Array.isArray(brokerIdp.audience)) {
        // Validate each audience in array
        if (brokerIdp.audience.length === 0) {
          throw new Error('Invalid broker IdP configuration: "audience" array cannot be empty');
        }
        for (let i = 0; i < brokerIdp.audience.length; i++) {
          if (typeof brokerIdp.audience[i] !== 'string') {
            throw new Error('Invalid broker IdP configuration: "audience" array must contain only strings');
          }
        }
      } else {
        throw new Error('Invalid broker IdP configuration: "audience" must be a string or array of strings');
      }
    }
    // Validate optional validateAudience field
    if (brokerIdp.validateAudience !== undefined && typeof brokerIdp.validateAudience !== 'boolean') {
      throw new Error('Invalid broker IdP configuration: "validateAudience" must be a boolean');
    }
    if (brokerIdp.jwksUri && typeof brokerIdp.jwksUri !== 'string') {
      throw new Error('Invalid broker IdP configuration: "jwksUri" must be a string');
    }
    if (brokerIdp.algorithms && !Array.isArray(brokerIdp.algorithms)) {
      throw new Error('Invalid broker IdP configuration: "algorithms" must be an array');
    }
  }

  private static validateAccessProvider(provider: any, index: number): void {
    const requiredFields = ['name', 'type', 'endpoint'];
    
    for (const field of requiredFields) {
      if (!provider[field] || typeof provider[field] !== 'string') {
        throw new Error(`Invalid access provider at index ${index}: missing or invalid "${field}" field`);
      }
    }

    // Validate supported provider types
    const supportedTypes = ['minio-sts', 'aws-sts'];
    if (!supportedTypes.includes(provider.type)) {
      throw new Error(`Invalid access provider at index ${index}: unsupported type "${provider.type}". Supported types: ${supportedTypes.join(', ')}`);
    }

    // Validate optional defaultDuration field
    if (provider.defaultDuration !== undefined) {
      if (typeof provider.defaultDuration !== 'number' || provider.defaultDuration <= 0) {
        throw new Error(`Invalid access provider at index ${index}: "defaultDuration" must be a positive number`);
      }
    }

    // Validate optional brokerAuth field
    if (provider.brokerAuth) {
      if (typeof provider.brokerAuth !== 'object' || Array.isArray(provider.brokerAuth)) {
        throw new Error(`Invalid access provider at index ${index}: "brokerAuth" must be an object`);
      }
      if (!provider.brokerAuth.tokenSource || typeof provider.brokerAuth.tokenSource !== 'string') {
        throw new Error(`Invalid access provider at index ${index}: "brokerAuth.tokenSource" is required and must be a string`);
      }
    }
  }

  private static validateClientIdentity(identity: any, index: number, clientIdps: any[], accessProviders: any[] = []): void {
    if (!identity.subject || typeof identity.subject !== 'string') {
      throw new Error(`Invalid client identity at index ${index}: missing or invalid "subject" field`);
    }
    if (!identity.idp || typeof identity.idp !== 'string') {
      throw new Error(`Invalid client identity at index ${index}: missing or invalid "idp" field`);
    }
    // Verify the referenced IdP exists
    const idpNames = clientIdps.map(idp => idp.name);
    if (!idpNames.includes(identity.idp)) {
      throw new Error(`Invalid client identity at index ${index}: IdP "${identity.idp}" not found in clientIdps`);
    }
    // Keys are required and must be an object with key configurations
    if (!identity.keys || typeof identity.keys !== 'object' || Array.isArray(identity.keys)) {
      throw new Error(`Invalid client identity at index ${index}: "keys" is required and must be an object with key configurations`);
    }
    
    if (Object.keys(identity.keys).length === 0) {
      throw new Error(`Invalid client identity at index ${index}: "keys" must define at least one key configuration`);
    }
    
    const providerNames = accessProviders.map(p => p.name);
    
    // Validate each key configuration
    Object.entries(identity.keys).forEach(([keyName, keyConfig]) => {
      if (typeof keyName !== 'string' || keyName.trim() === '') {
        throw new Error(`Invalid client identity at index ${index}: key name must be a non-empty string`);
      }
      
      if (typeof keyConfig !== 'object' || Array.isArray(keyConfig)) {
        throw new Error(`Invalid client identity at index ${index}: key "${keyName}" must be an object with configuration`);
      }
      
      const config = keyConfig as any;
      
      // Validate required provider field
      if (!config.provider || typeof config.provider !== 'string') {
        throw new Error(`Invalid client identity at index ${index}: key "${keyName}" must have a valid "provider" field`);
      }
      
      // Verify the referenced provider exists
      if (!providerNames.includes(config.provider)) {
        throw new Error(`Invalid client identity at index ${index}: key "${keyName}" references provider "${config.provider}" which is not defined in accessProviders`);
      }
      
      // Validate optional duration field
      if (config.duration !== undefined) {
        if (typeof config.duration !== 'number' || config.duration <= 0) {
          throw new Error(`Invalid client identity at index ${index}: key "${keyName}" duration must be a positive number`);
        }
      }
      
      // Validate required outputs field
      if (!config.outputs || typeof config.outputs !== 'object' || Array.isArray(config.outputs)) {
        throw new Error(`Invalid client identity at index ${index}: key "${keyName}" must have an "outputs" object mapping env vars to field paths`);
      }
      
      if (Object.keys(config.outputs).length === 0) {
        throw new Error(`Invalid client identity at index ${index}: key "${keyName}" outputs must define at least one environment variable mapping`);
      }
      
      // Validate each output mapping
      Object.entries(config.outputs).forEach(([envVar, fieldPath]) => {
        if (typeof envVar !== 'string' || envVar.trim() === '') {
          throw new Error(`Invalid client identity at index ${index}: key "${keyName}" output environment variable names must be non-empty strings`);
        }
        if (typeof fieldPath !== 'string' || fieldPath.trim() === '') {
          throw new Error(`Invalid client identity at index ${index}: key "${keyName}" output field paths must be non-empty strings`);
        }
      });
    });
  }
}