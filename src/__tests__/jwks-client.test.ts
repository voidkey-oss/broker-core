import { JwksTokenValidator } from '../jwks/jwks-client';
import { IdpConfiguration, OidcClaims } from '../types';

// Mock the jose library
const mockJose = {
  createRemoteJWKSet: jest.fn(),
  jwtVerify: jest.fn()
};

// Mock the global fetch function
global.fetch = jest.fn();

// Mock the runtime import function
const originalFunction = global.Function;
beforeAll(() => {
  global.Function = jest.fn().mockImplementation((code: string) => {
    if (code === 'return import("jose")') {
      return () => Promise.resolve(mockJose);
    }
    return originalFunction(code);
  });
});

afterAll(() => {
  global.Function = originalFunction;
});

describe('JwksTokenValidator', () => {
  let validator: JwksTokenValidator;
  const mockConfig: IdpConfiguration = {
    name: 'test-idp',
    issuer: 'https://test.example.com',
    audience: 'api://test',
    jwksUri: 'https://test.example.com/.well-known/jwks.json',
    algorithms: ['RS256']
  };

  const mockPayload = {
    sub: 'user-123',
    iss: 'https://test.example.com',
    aud: 'api://test',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    email: 'test@example.com',
    name: 'Test User'
  };

  beforeEach(() => {
    validator = new JwksTokenValidator(mockConfig);
    jest.clearAllMocks();
  });

  describe('validateToken', () => {
    it('should validate JWT token successfully', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const mockJWKS = jest.fn();
      
      mockJose.createRemoteJWKSet.mockReturnValue(mockJWKS);
      mockJose.jwtVerify.mockResolvedValue({ payload: mockPayload });

      const claims = await validator.validateToken('valid.jwt.token');

      expect(mockJose.createRemoteJWKSet).toHaveBeenCalledWith(new URL(mockConfig.jwksUri));
      expect(mockJose.jwtVerify).toHaveBeenCalledWith('valid.jwt.token', mockJWKS, {
        issuer: mockConfig.issuer,
        audience: mockConfig.audience,
        algorithms: mockConfig.algorithms,
        clockTolerance: '30s'
      });

      expect(claims).toEqual({
        sub: 'user-123',
        iss: 'https://test.example.com',
        aud: ['api://test'], // String audience converted to array
        exp: mockPayload.exp,
        iat: mockPayload.iat,
        email: 'test@example.com',
        name: 'Test User'
      });

      expect(consoleSpy).toHaveBeenCalledWith('✅ JWT validation successful for subject: user-123');
      consoleSpy.mockRestore();
    });

    it('should handle array audience correctly', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const mockJWKS = jest.fn();
      const payloadWithArrayAud = { ...mockPayload, aud: ['api://test', 'api://test2'] };
      
      mockJose.createRemoteJWKSet.mockReturnValue(mockJWKS);
      mockJose.jwtVerify.mockResolvedValue({ payload: payloadWithArrayAud });

      const claims = await validator.validateToken('valid.jwt.token');

      expect(claims.aud).toEqual(['api://test', 'api://test2']);
      consoleSpy.mockRestore();
    });

    it('should handle string audience correctly', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const mockJWKS = jest.fn();
      
      mockJose.createRemoteJWKSet.mockReturnValue(mockJWKS);
      mockJose.jwtVerify.mockResolvedValue({ payload: mockPayload });

      const claims = await validator.validateToken('valid.jwt.token');

      // String audience should be converted to array
      expect(claims.aud).toEqual(['api://test']);
      consoleSpy.mockRestore();
    });

    it('should handle jose validation errors', async () => {
      const mockJWKS = jest.fn();
      const joseError = new Error('JWT expired');
      
      mockJose.createRemoteJWKSet.mockReturnValue(mockJWKS);
      mockJose.jwtVerify.mockRejectedValue(joseError);

      await expect(validator.validateToken('expired.jwt.token'))
        .rejects
        .toThrow('JWT validation failed: JWT expired');
    });

    it('should handle non-Error exceptions', async () => {
      const mockJWKS = jest.fn();
      
      mockJose.createRemoteJWKSet.mockReturnValue(mockJWKS);
      mockJose.jwtVerify.mockRejectedValue('String error');

      await expect(validator.validateToken('invalid.jwt.token'))
        .rejects
        .toThrow('OIDC validation error: String error');
    });

    it('should use default algorithms if not specified', async () => {
      const configWithoutAlgorithms = { ...mockConfig };
      delete configWithoutAlgorithms.algorithms;
      
      const validatorWithoutAlgorithms = new JwksTokenValidator(configWithoutAlgorithms);
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      const mockJWKS = jest.fn();
      
      mockJose.createRemoteJWKSet.mockReturnValue(mockJWKS);
      mockJose.jwtVerify.mockResolvedValue({ payload: mockPayload });

      await validatorWithoutAlgorithms.validateToken('valid.jwt.token');

      expect(mockJose.jwtVerify).toHaveBeenCalledWith('valid.jwt.token', mockJWKS, {
        issuer: configWithoutAlgorithms.issuer,
        audience: configWithoutAlgorithms.audience,
        algorithms: ['RS256'], // Default should be used
        clockTolerance: '30s'
      });

      consoleSpy.mockRestore();
    });
  });

  describe('healthCheck', () => {
    beforeEach(() => {
      (fetch as jest.MockedFunction<typeof fetch>).mockClear();
    });

    it('should return true for healthy JWKS endpoint', async () => {
      const mockJwks = {
        keys: [
          { kty: 'RSA', kid: 'key1' },
          { kty: 'RSA', kid: 'key2' }
        ]
      };

      (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockJwks)
      } as Response);

      const healthy = await validator.healthCheck();

      expect(healthy).toBe(true);
      expect(fetch).toHaveBeenCalledWith(mockConfig.jwksUri);
    });

    it('should return false for HTTP error responses', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found'
      } as Response);

      const healthy = await validator.healthCheck();

      expect(healthy).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('JWKS health check failed for https://test.example.com')
      );

      consoleSpy.mockRestore();
    });

    it('should return false for JWKS without keys', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ keys: [] })
      } as Response);

      const healthy = await validator.healthCheck();

      expect(healthy).toBe(false);
      consoleSpy.mockRestore();
    });

    it('should return false for JWKS with malformed response', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      (fetch as jest.MockedFunction<typeof fetch>).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ invalid: 'format' })
      } as Response);

      const healthy = await validator.healthCheck();

      expect(healthy).toBe(false);
      consoleSpy.mockRestore();
    });

    it('should handle network errors', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      (fetch as jest.MockedFunction<typeof fetch>).mockRejectedValue(new Error('Network error'));

      const healthy = await validator.healthCheck();

      expect(healthy).toBe(false);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('JWKS health check failed for https://test.example.com')
      );

      consoleSpy.mockRestore();
    });
  });
});