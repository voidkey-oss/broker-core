export interface CredentialOutput {
  [envVarName: string]: string;
}

export interface KeyConfiguration {
  provider: string;
  duration?: number;
  outputs: { [envVarName: string]: string }; // Maps env var names to response field paths
  [key: string]: any; // Provider-specific configuration
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

export interface CredentialRequest {
  subject: string;
  keyName: string;
  keyConfig: KeyConfiguration;
  brokerToken?: string;
  claims?: any;
}

export interface CredentialResponse {
  credentials: CredentialOutput;
  expiresAt: string;
  metadata?: {
    provider: string;
    keyName: string;
    [key: string]: any;
  };
}

export abstract class AccessProvider {
  protected config: AccessProviderConfiguration;

  constructor(config: AccessProviderConfiguration) {
    this.config = config;
  }

  abstract getName(): string;
  abstract getType(): string;
  abstract mintCredential(request: CredentialRequest): Promise<CredentialResponse>;
  abstract healthCheck?(): Promise<boolean>;

  protected getDefaultDuration(): number {
    return this.config.defaultDuration || 3600; // 1 hour default
  }

  protected validateKeyConfig(keyConfig: KeyConfiguration): void {
    if (!keyConfig.outputs || Object.keys(keyConfig.outputs).length === 0) {
      throw new Error(`Key configuration must specify at least one output mapping`);
    }
  }
}