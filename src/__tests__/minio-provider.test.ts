import { MinIOProvider, MinIOConfiguration } from '../providers/minio';
import { CredentialRequest } from '../providers/base';
import * as jwt from 'jsonwebtoken';

// Mock node-fetch at the module level
const mockFetch = jest.fn();
jest.mock('node-fetch', () => mockFetch);

describe('MinIOProvider', () => {
  let provider: MinIOProvider;
  let mockConfig: MinIOConfiguration;

  beforeEach(() => {
    mockFetch.mockClear();
    mockConfig = {
      name: 'test-minio',
      type: 'minio-sts',
      endpoint: 'http://localhost:9000',
      region: 'us-east-1',
      defaultDuration: 3600,
      brokerAuth: {
        tokenSource: 'broker-oidc',
        expectedIssuer: 'http://localhost:8080/realms/broker',
        expectedAudience: 'voidkey-broker',
        jwksUri: 'http://localhost:8080/realms/broker/protocol/openid-connect/certs'
      }
    };
    provider = new MinIOProvider(mockConfig);
  });

  describe('Configuration', () => {
    it('should initialize with correct configuration', () => {
      expect(provider.getName()).toBe('test-minio');
      expect(provider.getType()).toBe('minio-sts');
    });

    it('should have correct configuration values', () => {
      // Test configuration values are accessible via provider methods
      expect(provider.getName()).toBe('test-minio');
      expect(provider.getType()).toBe('minio-sts');
      // getDefaultDuration is protected, so we can't test it directly
      // but we can test that duration is used correctly in credential minting
    });
  });

  describe('Credential Minting', () => {
    beforeEach(() => {
      // Mock successful STS response
      const mockSTSResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <AssumedRoleUser>
      <Arn>arn:minio:iam:::role/broker-role</Arn>
      <AssumedRoleId>broker-role:test-session</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
      <Expiration>2025-07-30T12:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`;
      
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => mockSTSResponse
      });
    });

    it('should mint credentials successfully', async () => {
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio',
          role: 'client-role',
          policy: 'client-policy',
          duration: 1800,
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId',
            MINIO_SECRET_ACCESS_KEY: 'SecretAccessKey',
            MINIO_SESSION_TOKEN: 'SessionToken',
            MINIO_EXPIRATION: 'Expiration',
            MINIO_ENDPOINT: 'Endpoint'
          }
        },
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      const response = await provider.mintCredential(request);

      // Verify STS endpoint was called with correct parameters
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('http://localhost:9000'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/x-www-form-urlencoded'
          }),
          body: expect.stringContaining('WebIdentityToken=')
        })
      );

      // Verify the request body contains correct STS parameters
      const requestBody = mockFetch.mock.calls[0][1].body;
      expect(requestBody).toContain('Action=AssumeRoleWithWebIdentity');
      expect(requestBody).toContain('Version=2011-06-15');
      expect(requestBody).toContain('DurationSeconds=1800');

      expect(response).toHaveProperty('credentials');
      expect(response).toHaveProperty('expiresAt');
      expect(response).toHaveProperty('metadata');

      // Check that all output mappings are present with actual STS values
      expect(response.credentials.MINIO_ACCESS_KEY_ID).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(response.credentials.MINIO_SECRET_ACCESS_KEY).toBe('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
      expect(response.credentials.MINIO_SESSION_TOKEN).toBe('AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE');
      expect(response.credentials.MINIO_EXPIRATION).toBe('2025-07-30T12:00:00Z');
      expect(response.credentials.MINIO_ENDPOINT).toBe('http://localhost:9000');

      // Check metadata
      expect(response.metadata).toBeDefined();
      expect(response.metadata?.provider).toBe('test-minio');
      expect(response.metadata?.keyName).toBe('MINIO_CREDENTIALS');
      expect(response.metadata?.role).toBe('client-role');
    });

    it('should call STS endpoint for each credential request', async () => {
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await provider.mintCredential(request);
      await provider.mintCredential(request);

      // Verify STS was called twice
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should respect custom duration from key configuration', async () => {
      const customDuration = 900; // 15 minutes
      
      // Set up mock with dynamic expiration time
      const expectedExpiration = new Date(Date.now() + customDuration * 1000);
      const mockSTSResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
      <Expiration>${expectedExpiration.toISOString()}</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`;
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => mockSTSResponse
      });
      
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio',
          role: 'client-role',
          policy: 'client-policy',
          duration: customDuration,
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      const response = await provider.mintCredential(request);
      
      // Check that the expiration time is reasonable (not exact due to timing variations)
      const now = new Date();
      const expiresAt = new Date(response.expiresAt);
      const timeDiff = expiresAt.getTime() - now.getTime();
      
      // Should be approximately 15 minutes (allow for 1 minute variance)
      expect(timeDiff).toBeGreaterThan((customDuration - 60) * 1000);
      expect(timeDiff).toBeLessThan((customDuration + 60) * 1000);
    });

    it('should use default duration when not specified', async () => {
      // Ensure mock is set up for this test
      const mockSTSResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
      <Expiration>${new Date(Date.now() + 3600000).toISOString()}</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`;
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => mockSTSResponse
      });
      
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio',
          role: 'client-role',
          policy: 'client-policy',
          // No duration specified
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      const response = await provider.mintCredential(request);
      const now = new Date();
      const expiresAt = new Date(response.expiresAt);
      const expectedExpiration = new Date(now.getTime() + (3600 * 1000)); // Default 1 hour

      const timeDiff = Math.abs(expiresAt.getTime() - expectedExpiration.getTime());
      expect(timeDiff).toBeLessThan(5000);
    });

    it('should handle different policy configurations', async () => {
      // Ensure mock is set up for this test
      const mockSTSResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ADMINKEY7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/ADMINEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
      <Expiration>2025-07-30T13:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`;
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => mockSTSResponse
      });
      
      const adminRequest: CredentialRequest = {
        subject: 'admin-user-456',
        keyName: 'MINIO_ADMIN_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio',
          role: 'admin-role',
          policy: 'admin-policy',
          outputs: {
            MINIO_ADMIN_ACCESS_KEY: 'AccessKeyId'
          }
        },
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'admin-user-456', iss: 'test-issuer' }
      };

      const response = await provider.mintCredential(adminRequest);

      expect(response.metadata?.role).toBe('admin-role');
      expect(response.credentials).toHaveProperty('MINIO_ADMIN_ACCESS_KEY');
    });
  });

  describe('Health Check', () => {
    beforeEach(() => {
      // Reset mock before each test
      mockFetch.mockReset();
    });

    it('should perform health check successfully', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200
      });

      const isHealthy = await provider.healthCheck();
      expect(isHealthy).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith('http://localhost:9000/minio/health/live');
    });

    it('should handle health check network failure', async () => {
      mockFetch.mockRejectedValue(new Error('Network error'));

      const isHealthy = await provider.healthCheck();
      expect(isHealthy).toBe(false);
    });

    it('should handle unhealthy service response', async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 503
      });

      const isHealthy = await provider.healthCheck();
      expect(isHealthy).toBe(false);
    });

    it('should handle MinIO endpoint errors gracefully', async () => {
      mockFetch.mockRejectedValue(new Error('ETIMEDOUT'));

      const isHealthy = await provider.healthCheck();
      expect(isHealthy).toBe(false);
    });
  });


  describe('Error Handling', () => {
    it('should handle credential minting errors gracefully', async () => {
      const invalidRequest: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'INVALID_KEY',
        keyConfig: {
          provider: 'test-minio',
          // Missing required role field - this should trigger an error
          outputs: {
            MINIO_ACCESS_KEY: 'AccessKeyId'
          }
        } as any,
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(provider.mintCredential(invalidRequest))
        .rejects
        .toThrow('MinIO key configuration must specify a role for key "INVALID_KEY"');
    });

    it('should handle unknown field mappings with warnings', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Ensure mock is set up for this test
      const mockSTSResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
      <Expiration>2025-07-30T13:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`;
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => mockSTSResponse
      });
      
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            VALID_FIELD: 'AccessKeyId',
            UNKNOWN_FIELD: 'UnknownField'
          }
        },
        brokerToken: jwt.sign({
          sub: 'broker-service',
          iss: 'http://localhost:8080/realms/broker',
          aud: 'voidkey-broker',
          exp: Math.floor(Date.now() / 1000) + 3600,
          iat: Math.floor(Date.now() / 1000)
        }, 'test-secret'),
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      const response = await provider.mintCredential(request);
      
      // Should work for valid fields
      expect(response.credentials).toHaveProperty('VALID_FIELD');
      
      // Should log warning for unknown fields
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Unknown field path "UnknownField" for env var "UNKNOWN_FIELD"')
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('Broker Token Validation', () => {
    let providerWithOIDC: MinIOProvider;
    let oidcConfig: MinIOConfiguration;

    beforeEach(() => {
      oidcConfig = {
        name: 'test-minio-oidc',
        type: 'minio-sts',
        endpoint: 'http://localhost:9000',
        defaultDuration: 3600,
        brokerAuth: {
          tokenSource: 'broker-oidc',
          expectedIssuer: 'http://localhost:8080/realms/broker',
          expectedAudience: 'voidkey-broker',
          jwksUri: 'http://localhost:8080/realms/broker/protocol/openid-connect/certs'
        }
      };
      providerWithOIDC = new MinIOProvider(oidcConfig);
    });

    it('should validate valid broker tokens', async () => {
      // Ensure mock is set up for this test
      const mockSTSResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/LTo6UDdyJwOOvEVPvLXCrrrUtdnniCEXAMPLE/IvU1dYUg2RVAJBanLiHb4IgRmpRV3zrkuWJOgQs8IZZaIv2BXIa2R4OlgkBN9bkUDNCJiBeb/AXlzBBko7b15fjrBs2+cTQtpZ3CYWFXG8C5zqx37wnOE49mRl/+OtkIKGO7fAE</SessionToken>
      <Expiration>2025-07-30T13:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`;
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => mockSTSResponse
      });
      
      // Create a valid JWT token
      const validToken = jwt.sign({
        sub: 'broker-service',
        iss: 'http://localhost:8080/realms/broker',
        aud: 'voidkey-broker',
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
        iat: Math.floor(Date.now() / 1000)
      }, 'test-secret');

      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: validToken,
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      // Should not throw
      const response = await providerWithOIDC.mintCredential(request);
      expect(response).toHaveProperty('credentials');
    });

    it('should reject expired broker tokens', async () => {
      const expiredToken = jwt.sign({
        sub: 'broker-service',
        iss: 'http://localhost:8080/realms/broker',
        aud: 'voidkey-broker',
        exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
        iat: Math.floor(Date.now() / 1000) - 7200  // 2 hours ago
      }, 'test-secret');

      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: expiredToken,
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(providerWithOIDC.mintCredential(request))
        .rejects
        .toThrow('Broker authentication failed: Broker token has expired');
    });

    it('should reject tokens with wrong issuer', async () => {
      const wrongIssuerToken = jwt.sign({
        sub: 'broker-service',
        iss: 'http://evil.com/malicious-issuer',
        aud: 'voidkey-broker',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      }, 'test-secret');

      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: wrongIssuerToken,
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(providerWithOIDC.mintCredential(request))
        .rejects
        .toThrow('Broker authentication failed: Invalid issuer: expected http://localhost:8080/realms/broker, got http://evil.com/malicious-issuer');
    });

    it('should reject tokens with wrong audience', async () => {
      const wrongAudienceToken = jwt.sign({
        sub: 'broker-service',
        iss: 'http://localhost:8080/realms/broker',
        aud: 'wrong-audience',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000)
      }, 'test-secret');

      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: wrongAudienceToken,
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(providerWithOIDC.mintCredential(request))
        .rejects
        .toThrow('Broker authentication failed: Invalid audience: expected voidkey-broker, got wrong-audience');
    });

    it('should handle malformed tokens', async () => {
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: 'not-a-valid-jwt-token',
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(providerWithOIDC.mintCredential(request))
        .rejects
        .toThrow('Broker authentication failed: Invalid JWT token format');
    });

    it('should handle missing required claims', async () => {
      const tokenWithoutRequiredClaims = jwt.sign({
        sub: 'broker-service',
        // Missing iss and exp - aud is present
        aud: 'voidkey-broker',
        iat: Math.floor(Date.now() / 1000)
      }, 'test-secret');

      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        brokerToken: tokenWithoutRequiredClaims,
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(providerWithOIDC.mintCredential(request))
        .rejects
        .toThrow('Broker authentication failed: JWT missing required claims (iss, exp)');
    });

    it('should require broker token for credential minting', async () => {
      const request: CredentialRequest = {
        subject: 'test-user-123',
        keyName: 'MINIO_CREDENTIALS',
        keyConfig: {
          provider: 'test-minio-oidc',
          role: 'client-role',
          policy: 'client-policy',
          outputs: {
            MINIO_ACCESS_KEY_ID: 'AccessKeyId'
          }
        },
        // No brokerToken provided
        claims: { sub: 'test-user-123', iss: 'test-issuer' }
      };

      await expect(providerWithOIDC.mintCredential(request))
        .rejects
        .toThrow('Broker OIDC token is required for MinIO credential minting');
    });
  });
});