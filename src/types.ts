
export interface OidcClaims {
  sub: string;
  iss: string;
  aud: string | string[]; // Can be empty array when validateAudience is false
  exp: number;
  iat: number;
  [key: string]: any;
}

export interface Identity {
  subject: string;
}

export interface IdpConfiguration {
  name: string;
  issuer: string;
  audience?: string | string[];  // Optional: single audience, multiple audiences, or none
  validateAudience?: boolean;     // Optional: explicitly control audience validation (default: true)
  jwksUri: string;
  algorithms?: string[];
}

export interface BrokerIdpConfiguration {
  name: string;
  issuer: string;
  audience: string;
  jwksUri?: string;
  algorithms?: string[];
  // Service account credentials for broker authentication
  clientId: string;
  clientSecret: string;
  tokenEndpoint: string;
}

export interface KeyConfiguration {
  provider: string;
  duration?: number;
  outputs: { [envVarName: string]: string }; // Maps env var names to response field paths
  [key: string]: any; // Provider-specific configuration (role, policy, etc.)
}

export interface AccessProviderConfiguration {
  name: string;
  type: string;
  endpoint: string;
  defaultDuration?: number;
  brokerAuth?: {
    tokenSource: string;
    [key: string]: any; // Provider-specific auth config
  };
  [key: string]: any; // Provider-specific configuration
}

export interface ClientIdentity {
  subject: string;
  idp: string; // Reference to the IdP name from clientIdps
  keys: { [keyName: string]: KeyConfiguration }; // Key-based configuration
}

export interface GeneralConfiguration {
  brokerIdp: BrokerIdpConfiguration; // Broker's own IdP - required for OIDC authentication
  clientIdps?: IdpConfiguration[]; // Client IdPs that can authenticate with the broker
  accessProviders?: AccessProviderConfiguration[]; // Access providers for credential minting
  clientIdentities?: ClientIdentity[]; // Client identities with their IdP and key mappings
  default?: string;
}