import { IdpConfigLoader } from '../config/idp-config';

describe('IdpConfigLoader', () => {
  describe('loadFromString', () => {
    it('should parse valid YAML configuration with clientIdps', () => {
      const yamlContent = `
clientIdps:
  - name: "test-provider"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
    algorithms: ["RS256", "ES256"]
  - name: "another-provider"
    issuer: "https://another.example.com"
    audience: "api://another"
    jwksUri: "https://another.example.com/.well-known/jwks.json"
default: "test-provider"
`;

      const config = IdpConfigLoader.loadFromString(yamlContent);
      
      expect(config.clientIdps).toHaveLength(2);
      expect(config.default).toBe('test-provider');
      
      const firstIdp = config.clientIdps![0];
      expect(firstIdp.name).toBe('test-provider');
      expect(firstIdp.issuer).toBe('https://test.example.com');
      expect(firstIdp.audience).toBe('api://test');
      expect(firstIdp.jwksUri).toBe('https://test.example.com/.well-known/jwks.json');
      expect(firstIdp.algorithms).toEqual(['RS256', 'ES256']);
    });

    it('should handle configuration with brokerIdp', () => {
      const yamlContent = `
brokerIdp:
  name: "broker-keycloak"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  jwksUri: "http://localhost:8080/realms/broker/protocol/openid-connect/certs"
  algorithms: ["RS256"]
clientIdps:
  - name: "client-provider"
    issuer: "https://client.example.com"
    audience: "api://client"
    jwksUri: "https://client.example.com/.well-known/jwks.json"
`;

      const config = IdpConfigLoader.loadFromString(yamlContent);
      
      expect(config.brokerIdp).toBeDefined();
      expect(config.brokerIdp!.name).toBe('broker-keycloak');
      expect(config.brokerIdp!.issuer).toBe('http://localhost:8080/realms/broker');
      expect(config.clientIdps).toHaveLength(1);
    });

    it('should handle configuration with clientIdentities and keys', () => {
      const yamlContent = `
accessProviders:
  - name: "aws-dev"
    type: "aws-sts"
    endpoint: "https://sts.amazonaws.com"
    region: "us-east-1"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
clientIdps:
  - name: "test-provider"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "auth0|507f1f77bcf86cd799439011"
    idp: "test-provider"
    keys:
      DEV_CREDENTIALS:
        provider: "aws-dev"
        roleArn: "arn:aws:iam::123456789012:role/VoidkeyDevRole"
        outputs:
          AWS_ACCESS_KEY_ID: "AccessKeyId"
          AWS_SECRET_ACCESS_KEY: "SecretAccessKey"
      ADMIN_CREDENTIALS:
        provider: "aws-dev"
        roleArn: "arn:aws:iam::123456789012:role/VoidkeyAdminRole"
        outputs:
          AWS_ADMIN_ACCESS_KEY: "AccessKeyId"
          AWS_ADMIN_SECRET_KEY: "SecretAccessKey"
  - subject: "service-account-voidkey-cli"
    idp: "test-provider"
    keys:
      SERVICE_CREDENTIALS:
        provider: "aws-dev"
        roleArn: "arn:aws:iam::123456789012:role/VoidkeyServiceRole"
        outputs:
          AWS_SERVICE_ACCESS_KEY: "AccessKeyId"
          AWS_SERVICE_SECRET_KEY: "SecretAccessKey"
`;

      const config = IdpConfigLoader.loadFromString(yamlContent);
      
      expect(config.clientIdentities).toHaveLength(2);
      expect(config.clientIdentities![0].subject).toBe('auth0|507f1f77bcf86cd799439011');
      expect(config.clientIdentities![0].idp).toBe('test-provider');
      expect(config.clientIdentities![0].keys).toHaveProperty('DEV_CREDENTIALS');
      expect(config.clientIdentities![0].keys.DEV_CREDENTIALS).toEqual({
        provider: 'aws-dev',
        roleArn: 'arn:aws:iam::123456789012:role/VoidkeyDevRole',
        outputs: {
          AWS_ACCESS_KEY_ID: 'AccessKeyId',
          AWS_SECRET_ACCESS_KEY: 'SecretAccessKey'
        }
      });
      expect(config.clientIdentities![0].keys.ADMIN_CREDENTIALS).toEqual({
        provider: 'aws-dev',
        roleArn: 'arn:aws:iam::123456789012:role/VoidkeyAdminRole',
        outputs: {
          AWS_ADMIN_ACCESS_KEY: 'AccessKeyId',
          AWS_ADMIN_SECRET_KEY: 'SecretAccessKey'
        }
      });
      expect(config.clientIdentities![1].subject).toBe('service-account-voidkey-cli');
      expect(config.clientIdentities![1].keys.SERVICE_CREDENTIALS).toEqual({
        provider: 'aws-dev',
        roleArn: 'arn:aws:iam::123456789012:role/VoidkeyServiceRole',
        outputs: {
          AWS_SERVICE_ACCESS_KEY: 'AccessKeyId',
          AWS_SERVICE_SECRET_KEY: 'SecretAccessKey'
        }
      });
    });

    it('should handle configuration without algorithms', () => {
      const yamlContent = `
clientIdps:
  - name: "simple-provider"
    issuer: "https://simple.example.com"
    audience: "api://simple"
    jwksUri: "https://simple.example.com/.well-known/jwks.json"
`;

      const config = IdpConfigLoader.loadFromString(yamlContent);
      
      expect(config.clientIdps).toHaveLength(1);
      expect(config.clientIdps![0].algorithms).toBeUndefined();
    });

    it('should handle configuration without default', () => {
      const yamlContent = `
clientIdps:
  - name: "no-default-provider"
    issuer: "https://no-default.example.com"
    audience: "api://no-default"
    jwksUri: "https://no-default.example.com/.well-known/jwks.json"
`;

      const config = IdpConfigLoader.loadFromString(yamlContent);
      
      expect(config.clientIdps).toHaveLength(1);
      expect(config.default).toBeUndefined();
    });

    it('should handle empty configuration', () => {
      const yamlContent = `
# Empty configuration
`;

      const config = IdpConfigLoader.loadFromString(yamlContent);
      
      expect(config.clientIdps).toBeUndefined();
      expect(config.brokerIdp).toBeUndefined();
      expect(config.clientIdentities).toBeUndefined();
    });

    it('should throw error for missing required fields in clientIdps', () => {
      const invalidYaml = `
clientIdps:
  - name: "incomplete-provider"
    issuer: "https://incomplete.example.com"
    # Missing jwksUri (audience is now optional)
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid IdP configuration at index 0: missing or invalid "jwksUri" field');
    });

    it('should throw error for invalid algorithms field', () => {
      const invalidYaml = `
clientIdps:
  - name: "bad-algorithms"
    issuer: "https://bad.example.com"
    audience: "api://bad"
    jwksUri: "https://bad.example.com/.well-known/jwks.json"
    algorithms: "RS256"  # Should be array, not string
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid IdP configuration at index 0: "algorithms" must be an array');
    });

    it('should throw error for invalid clientIdentities', () => {
      const invalidYaml = `
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "test-subject"
    # Missing idp field
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid client identity at index 0: missing or invalid "idp" field');
    });

    it('should throw error for clientIdentity referencing non-existent IdP', () => {
      const invalidYaml = `
clientIdps:
  - name: "real-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "test-subject"
    idp: "non-existent-idp"
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid client identity at index 0: IdP "non-existent-idp" not found in clientIdps');
    });

    it('should throw error for invalid keys structure', () => {
      const invalidYaml = `
accessProviders:
  - name: "test-provider"
    type: "aws-sts"
    endpoint: "https://sts.amazonaws.com"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "test-subject"
    idp: "test-idp"
    keys:
      - "invalid-array-format"
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid client identity at index 0: "keys" is required and must be an object with key configurations');
    });

    it('should throw error for invalid key configuration', () => {
      const invalidYaml = `
accessProviders:
  - name: "test-provider"
    type: "aws-sts"
    endpoint: "https://sts.amazonaws.com"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"  
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "test-subject"
    idp: "test-idp"
    keys:
      ADMIN_KEY: "not-an-object"
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid client identity at index 0: key "ADMIN_KEY" must be an object with configuration');
    });

    it('should throw error for missing required fields in key configuration', () => {
      const invalidYaml = `
accessProviders:
  - name: "test-provider"
    type: "aws-sts"
    endpoint: "https://sts.amazonaws.com"
    defaultDuration: 3600
    brokerAuth:
      tokenSource: "broker-oidc"
clientIdps:
  - name: "test-idp"
    issuer: "https://test.example.com"
    audience: "api://test"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
clientIdentities:
  - subject: "test-subject"
    idp: "test-idp"
    keys:
      ADMIN_KEY:
        roleArn: "arn:aws:iam::123456789012:role/AdminRole"
        outputs:
          AWS_ACCESS_KEY: "AccessKeyId"
`;

      expect(() => IdpConfigLoader.loadFromString(invalidYaml))
        .toThrow('Invalid client identity at index 0: key "ADMIN_KEY" must have a valid "provider" field');
    });

    it('should throw error for malformed YAML', () => {
      const malformedYaml = `
clientIdps:
  - name: "test
    # Unclosed quote
`;

      expect(() => IdpConfigLoader.loadFromString(malformedYaml))
        .toThrow('Failed to parse IdP configuration');
    });

    // New audience validation tests
    it('should accept IdP configuration without audience field', () => {
      const yamlWithoutAudience = `
clientIdps:
  - name: "no-audience-idp"
    issuer: "https://test.example.com"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      const config = IdpConfigLoader.loadFromString(yamlWithoutAudience);
      expect(config.clientIdps).toHaveLength(1);
      expect(config.clientIdps?.[0].audience).toBeUndefined();
    });

    it('should accept IdP configuration with array audience', () => {
      const yamlWithArrayAudience = `
clientIdps:
  - name: "multi-audience-idp"
    issuer: "https://test.example.com"
    audience: ["aud1", "aud2", "aud3"]
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      const config = IdpConfigLoader.loadFromString(yamlWithArrayAudience);
      expect(config.clientIdps).toHaveLength(1);
      expect(config.clientIdps?.[0].audience).toEqual(["aud1", "aud2", "aud3"]);
    });

    it('should accept IdP configuration with validateAudience flag', () => {
      const yamlWithValidateAudience = `
clientIdps:
  - name: "validate-audience-idp"
    issuer: "https://test.example.com"
    audience: "test-audience"
    validateAudience: false
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      const config = IdpConfigLoader.loadFromString(yamlWithValidateAudience);
      expect(config.clientIdps).toHaveLength(1);
      expect(config.clientIdps?.[0].validateAudience).toBe(false);
    });

    it('should throw error for empty audience array', () => {
      const yamlWithEmptyAudience = `
clientIdps:
  - name: "empty-audience-idp"
    issuer: "https://test.example.com"
    audience: []
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      expect(() => IdpConfigLoader.loadFromString(yamlWithEmptyAudience))
        .toThrow('Invalid IdP configuration at index 0: "audience" array cannot be empty');
    });

    it('should throw error for non-string audience array elements', () => {
      const yamlWithInvalidAudience = `
clientIdps:
  - name: "invalid-audience-idp"
    issuer: "https://test.example.com"
    audience: ["valid", 123, "another"]
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      expect(() => IdpConfigLoader.loadFromString(yamlWithInvalidAudience))
        .toThrow('Invalid IdP configuration at index 0: "audience" array must contain only strings');
    });

    it('should throw error for invalid audience type', () => {
      const yamlWithInvalidAudienceType = `
clientIdps:
  - name: "invalid-audience-type-idp"
    issuer: "https://test.example.com"
    audience: 123
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      expect(() => IdpConfigLoader.loadFromString(yamlWithInvalidAudienceType))
        .toThrow('Invalid IdP configuration at index 0: "audience" must be a string or array of strings');
    });

    it('should throw error for non-boolean validateAudience', () => {
      const yamlWithInvalidValidateAudience = `
clientIdps:
  - name: "invalid-validate-audience-idp"
    issuer: "https://test.example.com"
    validateAudience: "false"
    jwksUri: "https://test.example.com/.well-known/jwks.json"
`;

      expect(() => IdpConfigLoader.loadFromString(yamlWithInvalidValidateAudience))
        .toThrow('Invalid IdP configuration at index 0: "validateAudience" must be a boolean');
    });
  });
});