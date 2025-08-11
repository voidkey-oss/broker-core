import { CustomIdpProvider, HelloWorldProvider } from '../idp';
import { IdpConfiguration, OidcClaims } from '../types';
import { JwksTokenValidator } from '../jwks/jwks-client';

// Mock the JwksTokenValidator
jest.mock('../jwks/jwks-client');

describe('IdP Providers', () => {
  const mockConfig: IdpConfiguration = {
    name: 'test-provider',
    issuer: 'https://test.example.com',
    audience: 'api://test',
    jwksUri: 'https://test.example.com/.well-known/jwks.json',
    algorithms: ['RS256']
  };

  const mockClaims: OidcClaims = {
    sub: 'user-123',
    iss: 'https://test.example.com',
    aud: 'api://test',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    email: 'test@example.com'
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('HelloWorldProvider', () => {
    let provider: HelloWorldProvider;

    beforeEach(() => {
      provider = new HelloWorldProvider();
    });

    it('should return correct name and issuer', () => {
      expect(provider.getName()).toBe('hello-world');
      expect(provider.getIssuer()).toBe('hello-world-idp');
      expect(provider.getAudience()).toBe('hello-world-audience');
    });

    it('should validate CLI hello-world token successfully', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const claims = await provider.validateToken('cli-hello-world-token');
      
      expect(claims.sub).toBe('hello-world-user');
      expect(claims.iss).toBe('hello-world-idp');
      expect(claims.aud).toBe('hello-world-audience');
      expect(claims.email).toBe('hello@world.dev');
      expect(claims.name).toBe('Hello World User');
      expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
      
      expect(consoleSpy).toHaveBeenCalledWith('✨ Recognized CLI hello-world token');
      consoleSpy.mockRestore();
    });

    it('should validate any custom token successfully', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const claims = await provider.validateToken('any-custom-token-123');
      
      expect(claims.sub).toBe('hello-world-user');
      expect(claims.custom_claim).toBe('This is a test token from hello-world IdP');
      
      expect(consoleSpy).toHaveBeenCalledWith('✨ Processing custom token in hello-world mode');
      consoleSpy.mockRestore();
    });

    it('should always pass health check', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      const healthy = await provider.healthCheck();
      
      expect(healthy).toBe(true);
      expect(consoleSpy).toHaveBeenCalledWith('💚 Hello World IdP health check: Always healthy');
      consoleSpy.mockRestore();
    });
  });


  describe('CustomIdpProvider', () => {
    let provider: CustomIdpProvider;
    let mockValidateToken: jest.MockedFunction<(token: string) => Promise<OidcClaims>>;
    let mockHealthCheck: jest.MockedFunction<() => Promise<boolean>>;

    beforeEach(() => {
      mockValidateToken = jest.fn();
      mockHealthCheck = jest.fn();
      
      (JwksTokenValidator as jest.MockedClass<typeof JwksTokenValidator>).mockImplementation(() => ({
        validateToken: mockValidateToken,
        healthCheck: mockHealthCheck
      } as any));

      provider = new CustomIdpProvider(mockConfig);
    });

    it('should return correct name and issuer', () => {
      expect(provider.getName()).toBe('test-provider');
      expect(provider.getIssuer()).toBe('https://test.example.com');
    });

    it('should validate valid JWT token and add provider info', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      mockValidateToken.mockResolvedValue(mockClaims);

      const claims = await provider.validateToken('valid.jwt.token');
      
      expect(claims).toEqual({
        ...mockClaims,
        provider: 'test-provider'
      });
      expect(mockValidateToken).toHaveBeenCalledWith('valid.jwt.token');
      expect(consoleSpy).toHaveBeenCalledWith('✅ test-provider token validated for subject: user-123');
      
      consoleSpy.mockRestore();
    });

    it('should handle JWT validation errors', async () => {
      const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
      const validationError = new Error('JWT validation failed');
      mockValidateToken.mockRejectedValue(validationError);

      await expect(provider.validateToken('invalid.jwt.token'))
        .rejects
        .toThrow('JWT validation failed');
      
      expect(consoleErrorSpy).toHaveBeenCalledWith('❌ test-provider token validation failed: Error: JWT validation failed');
      consoleErrorSpy.mockRestore();
    });

    it('should perform health check', async () => {
      mockHealthCheck.mockResolvedValue(false);

      const healthy = await provider.healthCheck();
      
      expect(healthy).toBe(false);
      expect(mockHealthCheck).toHaveBeenCalled();
    });
  });
});