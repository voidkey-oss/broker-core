/**
 * Interface for broker authentication providers
 * Allows different authentication methods (client credentials, mTLS, Cloudflare, etc.)
 */
export interface BrokerAuthProvider {
  /**
   * Get the authentication type
   */
  getType(): string;
  
  /**
   * Get the provider name
   */
  getName(): string;
  
  /**
   * Acquire a token for broker authentication
   * @returns The authentication token (e.g., OIDC JWT)
   */
  acquireToken(): Promise<string>;
  
  /**
   * Check if the current token is still valid
   * @param token The token to validate
   * @returns true if valid, false if expired or invalid
   */
  isTokenValid(token: string): Promise<boolean>;
  
  /**
   * Get token expiry time
   * @param token The token to check
   * @returns Expiry time in milliseconds since epoch, or null if no expiry
   */
  getTokenExpiry(token: string): Promise<number | null>;
}

/**
 * Configuration for broker authentication
 */
export interface BrokerAuthConfiguration {
  /**
   * The authentication provider to use
   */
  provider: BrokerAuthProvider;
  
  /**
   * Cache tokens for reuse
   */
  cacheTokens?: boolean;
  
  /**
   * Token refresh buffer in seconds (refresh before expiry)
   */
  refreshBuffer?: number;
}

/**
 * Token cache entry
 */
export interface TokenCacheEntry {
  token: string;
  expiry?: number;
  provider: string;
}