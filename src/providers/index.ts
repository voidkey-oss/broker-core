export { AccessProvider, AccessProviderConfiguration, CredentialRequest, CredentialResponse, KeyConfiguration, CredentialOutput } from './base';
export { MinIOProvider, MinIOConfiguration, MinIOKeyConfiguration } from './minio';
export { AWSProvider, AWSConfiguration, AWSKeyConfiguration } from './aws';

import { AccessProvider, AccessProviderConfiguration } from './base';
import { MinIOProvider, MinIOConfiguration } from './minio';
import { AWSProvider, AWSConfiguration } from './aws';

// Provider factory for creating providers by type
export function createProvider(config: AccessProviderConfiguration): AccessProvider {
  switch (config.type) {
    case 'minio-sts':
      return new MinIOProvider(config as MinIOConfiguration);
    case 'aws-sts':
      return new AWSProvider(config as AWSConfiguration);
    default:
      throw new Error(`Unsupported provider type: ${config.type}`);
  }
}