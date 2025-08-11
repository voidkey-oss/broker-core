// Mock node-fetch via global injection
const mockFetch = jest.fn();
(global as any).__TEST_FETCH__ = mockFetch;

import { CredentialBroker } from '../index';

describe('Broker OIDC Authentication', () => {
  let broker: CredentialBroker;

  beforeEach(() => {
    broker = new CredentialBroker();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  afterAll(() => {
    // Clean up global mock
    delete (global as any).__TEST_FETCH__;
  });

  describe('Broker Token Acquisition', () => {
    it('should acquire broker token using client credentials flow', async () => {
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
`;

      // Mock successful token response
      const mockTokenResponse = {
        access_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJicm9rZXItc2VydmljZSIsImF1ZCI6InZvaWRrZXktYnJva2VyIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9icm9rZXIiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.test-signature',
        expires_in: 3600,
        token_type: 'Bearer'
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockTokenResponse),
        text: () => Promise.resolve(''),
        status: 200
      } as any);

      broker.loadIdpConfigFromString(yamlConfig);
      const token = await broker.getBrokerToken();

      expect(token).toBe(mockTokenResponse.access_token);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/realms/broker/protocol/openid-connect/token',
        expect.objectContaining({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=client_credentials&client_id=broker-service&client_secret=broker-secret-12345&audience=voidkey-broker'
        })
      );
    });

    it('should handle token acquisition failure', async () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  clientId: "broker-service"
  clientSecret: "wrong-secret"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
`;

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        text: () => Promise.resolve('Invalid client credentials')
      } as any);

      broker.loadIdpConfigFromString(yamlConfig);

      await expect(broker.getBrokerToken()).rejects.toThrow(
        'Failed to acquire broker token: 401 Invalid client credentials'
      );
    });

    it('should cache and reuse valid tokens', async () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
`;

      // Create a valid JWT token that expires in the future
      const jwt = require('jsonwebtoken');
      const futureExp = Math.floor(Date.now() / 1000) + 3600; // Expires in 1 hour
      const validToken = jwt.sign(
        {
          sub: 'broker-service',
          aud: 'voidkey-broker',
          iss: 'http://localhost:8080/realms/broker',
          exp: futureExp,
          iat: Math.floor(Date.now() / 1000)
        },
        'test-secret',
        { algorithm: 'HS256' }
      );

      const mockTokenResponse = {
        access_token: validToken,
        expires_in: 3600,
        token_type: 'Bearer'
      };

      // Mock the response before loading config
      mockFetch.mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockTokenResponse),
        text: () => Promise.resolve(''),
        status: 200
      } as any);

      broker.loadIdpConfigFromString(yamlConfig);

      // First call should make network request
      const token1 = await broker.getBrokerToken();
      expect(token1).toBe(validToken);
      expect(mockFetch).toHaveBeenCalledTimes(1);

      // Second call should use cached token
      const token2 = await broker.getBrokerToken();
      expect(token2).toBe(validToken);
      expect(mockFetch).toHaveBeenCalledTimes(1); // Still only 1 call
    });

    it('should refresh expired tokens', async () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
`;

      // First token with short expiry
      const mockTokenResponse1 = {
        access_token: 'token-1',
        expires_in: 1, // 1 second
        token_type: 'Bearer'
      };

      // Second token
      const mockTokenResponse2 = {
        access_token: 'token-2',
        expires_in: 3600,
        token_type: 'Bearer'
      };

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(mockTokenResponse1)
        } as any)
        .mockResolvedValueOnce({
          ok: true,
          json: () => Promise.resolve(mockTokenResponse2)  
        } as any);

      broker.loadIdpConfigFromString(yamlConfig);

      // Get first token
      const token1 = await broker.getBrokerToken();
      expect(token1).toBe('token-1');

      // Wait for token to expire (plus buffer)
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Get second token (should refresh)
      const token2 = await broker.getBrokerToken();
      expect(token2).toBe('token-2');
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe('Error Handling', () => {
    it('should throw error when broker IdP not configured', async () => {
      await expect(broker.getBrokerToken()).rejects.toThrow(
        'No broker authentication provider configured'
      );
    });

    it('should handle malformed token response', async () => {
      const yamlConfig = `
brokerIdp:
  name: "test-broker-idp"
  issuer: "http://localhost:8080/realms/broker"
  audience: "voidkey-broker"
  clientId: "broker-service"
  clientSecret: "broker-secret-12345"
  tokenEndpoint: "http://localhost:8080/realms/broker/protocol/openid-connect/token"
`;

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ token_type: 'Bearer' }) // Missing access_token
      } as any);

      broker.loadIdpConfigFromString(yamlConfig);

      await expect(broker.getBrokerToken()).rejects.toThrow(
        'No access_token in broker token response'
      );
    });
  });
});