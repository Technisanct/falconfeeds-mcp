export const API_CONFIG = {
  BASE_URL: "https://api.falconfeeds.io/merlin",
  ENDPOINTS: {
    CVE: "/cve",
    THREAT_FEED: "/threat/feed",
    THREAT_ACTOR: "/threat/actor",
    IOC: "/ioc",
    IOCV2: "/ioc/v2",
    THREAT_IMAGE: "/threat/image",
    IOC_THREAT_ACTOR: "/ioc/actor",
    IOC_MALWARE: "/ioc/malware"
  },
  LIMITS: {
    MAX_CVE_RESULT_COUNT: 50,
    DEFAULT_RESULT_COUNT: 10
  }
} as const;

export interface EndpointConfig {
  path: string;
  method: "GET" | "POST" | "PUT" | "DELETE";
  description: string;
  requiresAuth: boolean;
}

export const ENDPOINT_REGISTRY: Record<string, EndpointConfig> = {
  GET_CVES: {
    path: API_CONFIG.ENDPOINTS.CVE,
    method: "GET",
    description: "Retrieve Common Vulnerabilities and Exposures (CVEs)",
    requiresAuth: true
  },
  GET_THREAT_FEEDS: {
    path: API_CONFIG.ENDPOINTS.THREAT_FEED,
    method: "GET", 
    description: "Retrieve threat intelligence feeds",
    requiresAuth: true
  },
  GET_THREAT_ACTORS: {
    path: API_CONFIG.ENDPOINTS.THREAT_ACTOR,
    method: "GET",
    description: "Retrieve threat actor information",
    requiresAuth: true
  },

  GET_IOCS: {
    path: API_CONFIG.ENDPOINTS.IOC,
    method: "GET",
    description: "Retrieve Indicators of Compromise (IOCs)",
    requiresAuth: true
  },

  GET_IOCS_V2: {
    path: API_CONFIG.ENDPOINTS.IOCV2,
    method: "GET",
    description: "Retrieve Indicators of Compromise (IOCs) - Version 2",
    requiresAuth: true
  },
  
  GET_THREAT_IMAGE: {
    path: API_CONFIG.ENDPOINTS.THREAT_IMAGE,
    method: "GET",
    description: "Retrieve threat feed images as base64",
    requiresAuth: true
  },
  
  GET_IOC_THREAT_ACTORS: {
    path: API_CONFIG.ENDPOINTS.IOC_THREAT_ACTOR,
    method: "GET",
    description: "Retrieve threat actors related to IOCs",
    requiresAuth: true
  },

   GET_IOC_MALWARE: {
    path: API_CONFIG.ENDPOINTS.IOC_MALWARE,
    method: "GET",
    description: "Retrieve malwares related to IOCs",
    requiresAuth: true
  }

} as const; 