import { CredentialBroker } from '../index';

// Mock the JwksTokenValidator to avoid external network calls
jest.mock('../jwks/jwks-client');

describe('CredentialBroker Integration', () => {
  let broker: CredentialBroker;

  beforeEach(() => {
    broker = new CredentialBroker();
    jest.clearAllMocks();
  });

  describe('mintKey with Hello World Provider', () => {
    it('should return valid credential response using hello-world provider', async () => {
      const validToken = 'cli-hello-world-token';
      
      // Explicitly use hello-world provider for demo credentials
      const response = await broker.mintKey(validToken, 'TEST_KEY', 'hello-world');
      
      expect(response).toHaveProperty('credentials');
      expect(response).toHaveProperty('expiresAt');
      expect(response).toHaveProperty('metadata');
      
      expect(typeof response.credentials).toBe('object');
      expect(typeof response.expiresAt).toBe('string');
      expect(response.metadata?.provider).toBe('hello-world');
    });

    it('should return credentials with future expiration date', async () => {
      const validToken = 'cli-hello-world-token';
      
      const response = await broker.mintKey(validToken, 'TEST_KEY', 'hello-world');
      const expirationDate = new Date(response.expiresAt);
      const now = new Date();
      
      expect(expirationDate.getTime()).toBeGreaterThan(now.getTime());
    });

    it('should log successful token validation for hello-world provider', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const validToken = 'cli-hello-world-token';
      
      await broker.mintKey(validToken, 'TEST_KEY', 'hello-world');
      
      expect(consoleSpy).toHaveBeenCalledWith(
        '🎉 Token validated for subject:', 
        'hello-world-user'
      );
      
      consoleSpy.mockRestore();
    });

    it('should return expected hello world credentials', async () => {
      const validToken = 'cli-hello-world-token';
      
      const response = await broker.mintKey(validToken, 'TEST_KEY', 'hello-world');
      
      expect(response.credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(response.credentials.HELLO_SECRET_KEY).toBe('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
      expect(response.credentials.HELLO_SESSION_TOKEN).toBe('hello-world-session-token');
    });

    it('should work with any token when using hello-world provider', async () => {
      const anyToken = 'any-random-token-123';
      
      const response = await broker.mintKey(anyToken, 'TEST_KEY', 'hello-world');
      
      expect(response.credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(response.credentials.HELLO_SECRET_KEY).toBe('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
      expect(response.credentials.HELLO_SESSION_TOKEN).toBe('hello-world-session-token');
    });

    it('should mint multiple keys at once', async () => {
      const validToken = 'cli-hello-world-token';
      const keyNames = ['KEY_1', 'KEY_2'];
      
      const responses = await broker.mintKeys(validToken, keyNames, 'hello-world');
      
      expect(Object.keys(responses)).toEqual(keyNames);
      expect(responses.KEY_1.credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(responses.KEY_2.credentials.HELLO_ACCESS_KEY).toBe('AKIAIOSFODNN7EXAMPLE');
    });
  });

  describe('Health Checks', () => {
    it('should check health of hello-world provider', async () => {
      const result = await broker.healthCheckIdpProvider('hello-world');
      
      expect(result.provider).toBe('hello-world');
      expect(result.healthy).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should check all providers health including built-in ones', async () => {
      const results = await broker.healthCheckAllProviders();
      
      // Should include at least hello-world
      expect(results.length).toBeGreaterThanOrEqual(1);
      
      const helloWorldResult = results.find(r => r.provider === 'hello-world');
      expect(helloWorldResult).toBeDefined();
      expect(helloWorldResult?.healthy).toBe(true);
    });
  });
});