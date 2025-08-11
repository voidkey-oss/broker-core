# Voidkey Broker Core

TypeScript core library that implements the credential minting logic for the Voidkey zero-trust credential broker system.

## Overview

The broker-core package contains the core business logic for validating OIDC tokens, managing identity configurations, and orchestrating credential minting across different cloud providers. It provides a provider-based architecture that supports multiple identity providers and access providers.

## Architecture

The broker-core participates in the zero-trust credential broker workflow:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Client    │──▶│  Client IdP │    │   Voidkey   │──▶│  Broker IdP │──▶│   Access    │
│     CLI     │    │  (Auth0,    │    │   Broker    │    │ (Keycloak,  │    │  Provider   │
│             │    │ GitHub, etc)│    │             │    │  Okta, etc) │    │    (STS)    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │                   │
       │ 1. Get client     │                   │                   │                   │
       │    OIDC token     │                   │                   │                   │
       │◀─────────────────│                   │                   │                   │
       │                                       │                   │                   │
       │ 2. Request credentials with token     │                   │                   │
       │─────────────────────────────────────▶│                   │                   │
       │                                       │                   │                   │
       │                             3. Validate client token      │                   │
       │                                       │                   │                   │
       │                                       │ 4. Get broker     │                   │
       │                                       │    OIDC token     │                   │
       │                                       │◀─────────────────│                   │
       │                                       │                                       │
       │                                       │ 5. Mint credentials with broker token │
       │                                       │─────────────────────────────────────▶│
       │                                       │                                       │
       │                                       │ 6. Return temp credentials            │
       │                                       │◀─────────────────────────────────────│
       │                                       │                                       │
       │ 7. Return temp credentials to client  │                                       │
       │◀─────────────────────────────────────│                                       │
       │                                                                               │
       │ 8. Use credentials for operations                                             │
       │─────────────────────────────────────────────────────────────────────────────▶│
```

## Key Components

### CredentialBroker

The main orchestrator class that handles the complete credential minting workflow:

```typescript
class CredentialBroker {
  async mintCredentials(token: string, keys: string[]): Promise<Credentials[]>
  async listAvailableKeys(token: string): Promise<string[]>
}
```

### Provider Interfaces

#### IdpProvider

Handles identity provider integration and token validation:

```typescript
interface IdpProvider {
  validateToken(token: string): Promise<TokenClaims>
  getJwks(): Promise<JwksResponse>
}
```

Supported identity providers:
- **Auth0Provider**: Auth0 OIDC integration
- **GitHubProvider**: GitHub Actions OIDC tokens
- **KeycloakProvider**: Keycloak/generic OIDC provider
- **OktaProvider**: Okta OIDC integration

#### AccessProvider

Handles cloud provider credential minting:

```typescript
interface AccessProvider {
  mintCredentials(brokerToken: string, config: ProviderConfig): Promise<Credentials>
  getProviderToken(): Promise<string>
}
```

Supported access providers:
- **MinIOProvider**: MinIO/S3-compatible storage
- **AWSProvider**: AWS STS integration
- **GCPProvider**: Google Cloud STS integration
- **AzureProvider**: Azure credential minting

### Identity Configuration

The core uses a flexible identity configuration system that maps subjects to individual keys:

```typescript
interface IdentityConfig {
  idpProviders: {
    [providerId: string]: IdpProviderConfig
  }
  subjects: {
    [subject: string]: {
      keys: {
        [keyName: string]: {
          provider: string
          config: ProviderConfig
        }
      }
    }
  }
}
```

## Installation

```bash
npm install
```

## Development

### Build

```bash
npm run build          # Compile TypeScript
npm run dev            # Watch mode development
npm run clean          # Remove dist directory
```

### Testing

```bash
npm run test           # Run Jest tests
npm run test:watch     # Watch mode testing
npm run test:coverage  # Generate coverage report
```

## Usage Examples

### Basic Credential Minting

```typescript
import { CredentialBroker } from '@voidkey/broker-core'

const broker = new CredentialBroker(identityConfig)

// Mint credentials for specific keys
const credentials = await broker.mintCredentials(
  'eyJhbGciOiJSUzI1NiIs...',
  ['s3-readonly', 's3-readwrite']
)

// List available keys for a subject
const availableKeys = await broker.listAvailableKeys('eyJhbGciOiJSUzI1NiIs...')
```

### Custom Provider Implementation

```typescript
import { AccessProvider } from '@voidkey/broker-core'

class CustomCloudProvider implements AccessProvider {
  async mintCredentials(brokerToken: string, config: ProviderConfig): Promise<Credentials> {
    // Implement custom credential minting logic
    return {
      AccessKeyId: 'AKIA...',
      SecretAccessKey: 'secret...',
      SessionToken: 'token...',
      Expiration: new Date()
    }
  }

  async getProviderToken(): Promise<string> {
    // Get broker's own OIDC token for this provider
    return 'broker-token...'
  }
}
```

### Identity Configuration Setup

```typescript
const identityConfig = {
  idpProviders: {
    'github-actions': {
      type: 'github',
      issuer: 'https://token.actions.githubusercontent.com',
      audience: 'sts.amazonaws.com'
    },
    'auth0': {
      type: 'auth0',
      issuer: 'https://myorg.auth0.com/',
      audience: 'https://myorg.com/api'
    }
  },
  subjects: {
    'repo:myorg/myapp:ref:refs/heads/main': {
      keys: {
        'ci-deployment': {
          provider: 'aws',
          config: {
            roleArn: 'arn:aws:iam::123456789012:role/GitHubActions',
            region: 'us-east-1'
          }
        }
      }
    },
    'user|auth0|12345': {
      keys: {
        's3-readonly': {
          provider: 'minio',
          config: {
            endpoint: 'https://minio.example.com',
            bucket: 'my-bucket',
            permissions: ['s3:GetObject']
          }
        }
      }
    }
  }
}
```

## Key Features

### Token Validation

- **JWKS Validation**: Validates tokens against provider JWKS endpoints
- **Audience Validation**: Configurable audience validation per provider
- **Expiration Checking**: Ensures tokens are not expired
- **Issuer Verification**: Validates token issuer matches configuration

### Provider Architecture

- **Pluggable Providers**: Easy to add new identity and access providers
- **Configuration-Driven**: All provider behavior controlled via configuration
- **Error Handling**: Comprehensive error handling and logging
- **Async/Await**: Modern Promise-based API

### Security Features

- **Zero-Trust Architecture**: No shared secrets between components
- **Token Isolation**: Client and broker tokens are separate
- **Automatic Expiration**: All credentials have automatic expiration
- **Audit Logging**: Comprehensive logging for security auditing

## Configuration Reference

### IdP Provider Configuration

```typescript
interface IdpProviderConfig {
  type: 'auth0' | 'github' | 'keycloak' | 'okta'
  issuer: string
  audience?: string | string[]
  jwksUri?: string
  clientId?: string
  clockTolerance?: number
}
```

### Access Provider Configuration

```typescript
interface AccessProviderConfig {
  type: 'aws' | 'gcp' | 'azure' | 'minio'
  region?: string
  endpoint?: string
  roleArn?: string
  serviceAccount?: string
  permissions?: string[]
  durationSeconds?: number
}
```

## Error Handling

The core library provides structured error handling:

```typescript
try {
  const credentials = await broker.mintCredentials(token, keys)
} catch (error) {
  if (error instanceof TokenValidationError) {
    // Handle invalid token
  } else if (error instanceof ProviderError) {
    // Handle provider-specific errors
  } else if (error instanceof ConfigurationError) {
    // Handle configuration errors
  }
}
```

## Testing

### Unit Tests

```bash
# Run all tests
npm test

# Run specific test file
npm test -- credential-broker.test.ts

# Run tests with coverage
npm run test:coverage
```

### Integration Tests

```bash
# Test with real providers (requires configuration)
npm run test:integration
```

## Performance Considerations

- **Token Caching**: JWKS responses are cached to reduce latency
- **Connection Pooling**: HTTP clients use connection pooling
- **Async Operations**: All I/O operations are asynchronous
- **Memory Management**: Efficient memory usage for high-throughput scenarios

## Security Considerations

- **Token Validation**: Always validate tokens before minting credentials
- **Secure Communication**: Use HTTPS for all external communications
- **Credential Expiration**: Set appropriate expiration times for credentials
- **Audit Logging**: Log all credential minting operations
- **Error Information**: Avoid leaking sensitive information in error messages
