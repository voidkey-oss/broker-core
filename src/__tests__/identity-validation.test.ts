import { CredentialBroker } from '../index';

// Mock the JwksTokenValidator to avoid external network calls
jest.mock('../jwks/jwks-client');

describe('Identity Validation with Keys', () => {
  let broker: CredentialBroker;

  beforeEach(() => {
    broker = new CredentialBroker();
    jest.clearAllMocks();
  });

  describe('Key Management', () => {
    it('should validate identity with keys', async () => {
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
clientIdentities:
  - subject: "user1"
    idp: "test-idp"
    keys:
      ADMIN_CREDENTIALS:
        provider: "minio-test"
        policy: "admin-policy"
        outputs:
          AWS_ADMIN_ACCESS_KEY: "AccessKeyId"
          AWS_ADMIN_SECRET_KEY: "SecretAccessKey"
      USER_CREDENTIALS:
        provider: "minio-test"
        policy: "user-policy"
        outputs:
          AWS_USER_ACCESS_KEY: "AccessKeyId"
          AWS_USER_SECRET_KEY: "SecretAccessKey"
`;

      broker.loadIdpConfigFromString(yamlConfig);
      
      // Test that the identity has the expected keys
      const availableKeys = broker.getAvailableKeys('user1');
      expect(availableKeys).toContain('ADMIN_CREDENTIALS');
      expect(availableKeys).toContain('USER_CREDENTIALS');
      expect(availableKeys).toHaveLength(2);
      
      // Test that we can get the key configuration
      const adminKeyConfig = broker.getKeyConfiguration('user1', 'ADMIN_CREDENTIALS');
      expect(adminKeyConfig).not.toBeNull();
      expect(adminKeyConfig!.provider).toBe('minio-test');
      expect(adminKeyConfig!.policy).toBe('admin-policy');
    });

    it('should return empty array for non-existent identity', () => {
      const availableKeys = broker.getAvailableKeys('non-existent-user');
      expect(availableKeys).toEqual([]);
    });

    it('should return null for non-existent key configuration', () => {
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
clientIdentities:
  - subject: "user1"
    idp: "test-idp"
    keys:
      EXISTING_KEY:
        provider: "minio-test"
        policy: "test-policy"
        outputs:
          TEST_VAR: "AccessKeyId"
`;

      broker.loadIdpConfigFromString(yamlConfig);
      
      const keyConfig = broker.getKeyConfiguration('user1', 'NON_EXISTENT_KEY');
      expect(keyConfig).toBeNull();
    });
  });

  describe('Hello World Provider Integration', () => {
    it('should work with hello-world provider for testing', async () => {
      // The hello-world provider bypasses normal identity checks
      const response = await broker.mintKey('cli-hello-world-token', 'TEST_KEY', 'hello-world');
      
      expect(response).toHaveProperty('credentials');
      expect(response).toHaveProperty('expiresAt');
      expect(response.credentials).toHaveProperty('HELLO_ACCESS_KEY');
      expect(response.metadata).toHaveProperty('provider', 'hello-world');
    });
  });
});

describe('Configuration Error Handling', () => {
  let broker: CredentialBroker;

  beforeEach(() => {
    broker = new CredentialBroker();
  });

  it('should require keys for client identities', () => {
    const invalidConfig = `
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "invalid-user"
    idp: "test-idp"
`;

    expect(() => broker.loadIdpConfigFromString(invalidConfig))
      .toThrow('keys" is required and must be an object with key configurations');
  });

  it('should require at least one key configuration', () => {
    const invalidConfig = `
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "empty-user"
    idp: "test-idp"
    keys: {}
`;

    expect(() => broker.loadIdpConfigFromString(invalidConfig))
      .toThrow('keys" must define at least one key configuration');
  });
});