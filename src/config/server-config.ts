export interface ServerConfig {
  // Tool behavior configuration
  threatIntelligence: {
    // Use structured actor lookup by default for threat actor queries
    useStructuredActorLookup: boolean;
    // Automatically include attributed feeds when getting actor profiles
    includeAttributedFeeds: boolean;
    // Maximum number of threat feeds to return in a single response
    maxFeedsPerResponse: number;
  };
  
  // API behavior configuration
  api: {
    // Default timeout for API requests
    defaultTimeout: number;
    // Maximum retries for failed requests
    maxRetries: number;
    // Rate limiting configuration
    rateLimiting: {
      enabled: boolean;
      requestsPerMinute: number;
    };
  };
  
  // Security configuration
  security: {
    // Validate all input parameters
    strictInputValidation: boolean;
    // Sanitize output data
    sanitizeOutput: boolean;
  };
}

export const DEFAULT_SERVER_CONFIG: ServerConfig = {
  threatIntelligence: {
    useStructuredActorLookup: true, // This makes the better flow the default!
    includeAttributedFeeds: true,
    maxFeedsPerResponse: 50
  },
  
  api: {
    defaultTimeout: 30000,
    maxRetries: 3,
    rateLimiting: {
      enabled: false, // Can be enabled in production
      requestsPerMinute: 60
    }
  },
  
  security: {
    strictInputValidation: true,
    sanitizeOutput: true
  }
};

// Environment-based configuration override
export function getServerConfig(): ServerConfig {
  const config = { ...DEFAULT_SERVER_CONFIG };
  
  // Override from environment variables if needed
  if (process.env.FALCONFEEDS_USE_STRUCTURED_LOOKUP === 'false') {
    config.threatIntelligence.useStructuredActorLookup = false;
  }
  
  if (process.env.FALCONFEEDS_INCLUDE_ATTRIBUTED_FEEDS === 'false') {
    config.threatIntelligence.includeAttributedFeeds = false;
  }
  
  if (process.env.FALCONFEEDS_MAX_FEEDS) {
    config.threatIntelligence.maxFeedsPerResponse = parseInt(process.env.FALCONFEEDS_MAX_FEEDS);
  }
  
  if (process.env.FALCONFEEDS_TIMEOUT) {
    config.api.defaultTimeout = parseInt(process.env.FALCONFEEDS_TIMEOUT);
  }
  
  return config;
} 