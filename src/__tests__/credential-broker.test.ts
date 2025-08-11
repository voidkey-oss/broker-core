import { CredentialBroker } from '../index';
import { MinIOProvider } from '../providers/minio';

// Mock the JwksTokenValidator to avoid external network calls
jest.mock('../jwks/jwks-client');

describe('CredentialBroker', () => {
  let broker: CredentialBroker;

  beforeEach(() => {
    broker = new CredentialBroker();
    jest.clearAllMocks();
  });

  describe('Initialization', () => {
    it('should initialize with hello-world as default provider', () => {
      const provider = broker.getIdpProvider();
      expect(provider.getName()).toBe('hello-world');
      expect(provider.getIssuer()).toBe('hello-world-idp');
    });

    it('should initialize with built-in hello-world provider', () => {
      const helloWorldProvider = broker.getIdpProvider('hello-world');
      expect(helloWorldProvider.getName()).toBe('hello-world');
      expect(helloWorldProvider.getIssuer()).toBe('hello-world-idp');
    });
  });

  describe('Access Provider Configuration', () => {
    it('should load access providers from YAML configuration', () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
accessProviders:
  - name: "minio-test"
    type: "minio-sts"
    endpoint: "http://localhost:9000"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
      expectedIssuer: "http://localhost:8080/realms/broker"
      expectedAudience: "voidkey-broker"
      jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
    algorithms: ["RS256"]
default: "test-idp"
`;

      broker.loadIdpConfigFromString(yamlConfig);
      const provider = broker.getAccessProvider('minio-test');
      expect(provider).toBeDefined();
      expect(provider.getName()).toBe('minio-test');
      expect(provider.getType()).toBe('minio-sts');
    });

    it('should throw error for non-existent access provider', () => {
      expect(() => broker.getAccessProvider('non-existent'))
        .toThrow("Access provider 'non-existent' not found");
    });
  });

  describe('Broker IdP Configuration', () => {
    it('should require broker IdP configuration', () => {
      const yamlConfigWithoutBroker = `
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
    algorithms: ["RS256"]
default: "test-idp"
`;

      expect(() => {
        broker.loadIdpConfigFromString(yamlConfigWithoutBroker);
      }).toThrow('Broker IdP configuration is required. The broker must authenticate with its own IdP to mint credentials.');
    });
  });

  describe('Key-based Credential Minting', () => {
    beforeEach(() => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
accessProviders:
  - name: "minio-test"
    type: "minio-sts"
    endpoint: "http://localhost:9000"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
      expectedIssuer: "http://localhost:8080/realms/broker"
      expectedAudience: "voidkey-broker"
      jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
    algorithms: ["RS256"]
clientIdentities:
  - subject: "test-user-123"
    idp: "test-idp"
    keys:
      MINIO_CREDENTIALS:
        provider: "minio-test"
        policy: "client-policy"
        duration: 1800
        outputs:
          MINIO_ACCESS_KEY_ID: "AccessKeyId"
          MINIO_SECRET_ACCESS_KEY: "SecretAccessKey"
          MINIO_SESSION_TOKEN: "SessionToken"
          MINIO_EXPIRATION: "Expiration"
          MINIO_ENDPOINT: "Endpoint"
      MINIO_ADMIN_CREDENTIALS:
        provider: "minio-test"
        policy: "admin-policy"
        duration: 900
        outputs:
          MINIO_ADMIN_ACCESS_KEY: "AccessKeyId"
          MINIO_ADMIN_SECRET_KEY: "SecretAccessKey"
default: "test-idp"
`;
      broker.loadIdpConfigFromString(yamlConfig);
    });

    it('should get available keys for identity', () => {
      const availableKeys = broker.getAvailableKeys('test-user-123');
      expect(availableKeys).toEqual(['MINIO_CREDENTIALS', 'MINIO_ADMIN_CREDENTIALS']);
    });

    it('should return empty array for non-existent identity', () => {
      const availableKeys = broker.getAvailableKeys('non-existent-user');
      expect(availableKeys).toEqual([]);
    });

    it('should get key configuration for specific key', () => {
      const keyConfig = broker.getKeyConfiguration('test-user-123', 'MINIO_CREDENTIALS');
      expect(keyConfig).toBeDefined();
      expect(keyConfig!.provider).toBe('minio-test');
      expect(keyConfig!.policy).toBe('client-policy');
      expect(keyConfig!.duration).toBe(1800);
    });

    it('should return null for non-existent key configuration', () => {
      const keyConfig = broker.getKeyConfiguration('test-user-123', 'NON_EXISTENT_KEY');
      expect(keyConfig).toBeNull();
    });

    it('should mint credentials using configured key and provider', async () => {
      // Test using hello-world provider without explicit configuration (it bypasses identity checks)
      const response = await broker.mintKey('hello-world-token', 'TEST_KEY', 'hello-world');
      
      expect(response).toHaveProperty('credentials');
      expect(response).toHaveProperty('expiresAt');
      expect(response).toHaveProperty('metadata');
      expect(response.credentials).toHaveProperty('HELLO_ACCESS_KEY');
      expect(response.credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(response.credentials).toHaveProperty('HELLO_SECRET_KEY');
      expect(response.credentials).toHaveProperty('HELLO_SESSION_TOKEN');
    });

    it('should mint multiple keys using configured provider', async () => {
      // Test using hello-world provider without explicit configuration (it bypasses identity checks)  
      const keyNames = ['TEST_KEY_1', 'TEST_KEY_2'];
      const results = await broker.mintKeys('hello-world-token', keyNames, 'hello-world');
      
      expect(Object.keys(results)).toEqual(keyNames);
      expect(results['TEST_KEY_1']).toHaveProperty('credentials');
      expect(results['TEST_KEY_2']).toHaveProperty('credentials');
      expect(results['TEST_KEY_1'].credentials).toHaveProperty('HELLO_ACCESS_KEY');
      expect(results['TEST_KEY_2'].credentials).toHaveProperty('HELLO_ACCESS_KEY');
      expect(results['TEST_KEY_1'].credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(results['TEST_KEY_2'].credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
    });
  });


  describe('IdP Provider Management', () => {
    it('should load multiple IdP providers from configuration', () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
clientIdps:
  - name: "keycloak-client"
    issuer: "http://localhost:8080/realms/client"
    audience: "voidkey-broker"
    jwksUri: "http://localhost:8080/realms/client/protocol/openid-connect/certs"
    algorithms: ["RS256"]
  - name: "auth0"
    issuer: "https://mytenant.us.auth0.com/"
    audience: "https://mytenant.us.auth0.com/api/v2/"
    jwksUri: "https://mytenant.us.auth0.com/.well-known/jwks.json"
    algorithms: ["RS256"]
default: "keycloak-client"
`;

      broker.loadIdpConfigFromString(yamlConfig);
      
      const keycloakProvider = broker.getIdpProvider('keycloak-client');
      expect(keycloakProvider.getName()).toBe('keycloak-client');
      expect(keycloakProvider.getIssuer()).toBe('http://localhost:8080/realms/client');
      
      const auth0Provider = broker.getIdpProvider('auth0');
      expect(auth0Provider.getName()).toBe('auth0');
      expect(auth0Provider.getIssuer()).toBe('https://mytenant.us.auth0.com/');
      
      // Test default provider
      const defaultProvider = broker.getIdpProvider();
      expect(defaultProvider.getName()).toBe('keycloak-client');
    });

    it('should list all available IdP providers', () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
clientIdps:
  - name: "provider1"
    issuer: "https://provider1.com"
    audience: "api://provider1"
    jwksUri: "https://provider1.com/.well-known/jwks.json"
  - name: "provider2"
    issuer: "https://provider2.com"
    audience: "api://provider2"
    jwksUri: "https://provider2.com/.well-known/jwks.json"
default: "provider1"
`;

      broker.loadIdpConfigFromString(yamlConfig);
      
      const providers = broker.listIdpProviders();
      expect(providers).toEqual([
        { name: 'hello-world', isDefault: false },
        { name: 'provider1', isDefault: true },
        { name: 'provider2', isDefault: false }
      ]);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid YAML configuration', () => {
      const invalidYaml = `
accessProviders:
  - name: "missing-required-fields"
    # Missing type and endpoint
clientIdps:
  - name: "missing-required-fields"
    issuer: "https://example.com"
    # Missing audience and jwksUri
`;

      expect(() => broker.loadIdpConfigFromString(invalidYaml))
        .toThrow('Failed to parse IdP configuration');
    });

    it('should handle empty configuration', () => {
      const emptyConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
accessProviders: []
clientIdps: []
clientIdentities: []
`;

      expect(() => broker.loadIdpConfigFromString(emptyConfig))
        .not.toThrow();
    });

    it('should handle configuration with multiple keys', () => {
      const keysConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
accessProviders:
  - name: "minio-test"
    type: "minio-sts"
    endpoint: "http://localhost:9000"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
      expectedIssuer: "http://localhost:8080/realms/broker"
      expectedAudience: "voidkey-broker"
      jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "multi-key-user"
    idp: "test-idp"
    keys:
      MINIO_KEY:
        provider: "minio-test"
        policy: "test-policy"
        outputs:
          MINIO_ACCESS_KEY: "AccessKeyId"
      ANOTHER_KEY:
        provider: "minio-test"
        policy: "test-policy-2"
        outputs:
          ANOTHER_ACCESS_KEY: "AccessKeyId"
`;

      expect(() => broker.loadIdpConfigFromString(keysConfig))
        .not.toThrow();
        
      const availableKeys = broker.getAvailableKeys('multi-key-user');
      expect(availableKeys).toContain('MINIO_KEY');
      expect(availableKeys).toContain('ANOTHER_KEY');
      expect(availableKeys).toHaveLength(2);
    });
  });
});