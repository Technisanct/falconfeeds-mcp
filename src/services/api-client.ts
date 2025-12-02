import { API_CONFIG } from "../config/api-endpoints.js";
import type {
  CVEResponse,
  CVEQueryParams,
  ThreatFeedResponse,
  ThreatFeedQueryParams,
  ThreatActorResponse,
  ThreatActorQueryParams,
  IOCResponse,
  IOCQueryParams,
  ThreatImageResponse,
  FalconIOCResponse,
  FalconIOCQueryParams,
  IOCsThreatActorQueryParams
} from "../types/index.js";
import { isValidCountry, isValidIndustry, getIndustryValidationMessage } from "../utils/validation.js";


export interface ApiClientConfig {
  apiKey: string;
  baseUrl?: string;
  timeout?: number;
}

export interface ApiError extends Error {
  status?: number;
  code?: string;
}

export class FalconFeedsApiError extends Error implements ApiError {
  constructor(
    message: string,
    public status?: number,
    public code?: string
  ) {
    super(message);
    this.name = "FalconFeedsApiError";
  }
}

export interface IApiClient {
  getCVEs(params: CVEQueryParams): Promise<CVEResponse>;
  getThreatFeeds(params?: ThreatFeedQueryParams): Promise<ThreatFeedResponse>;
  getThreatActors(params?: ThreatActorQueryParams): Promise<ThreatActorResponse>;
  getIOCs(params?: IOCQueryParams): Promise<IOCResponse>;
  getThreatImage(imageUuid: string): Promise<ThreatImageResponse>;
  getIOC(params?: FalconIOCQueryParams): Promise<FalconIOCResponse>;
  getIOCsThreatActors(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
}

export class FalconFeedsApiClient implements IApiClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: ApiClientConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || API_CONFIG.BASE_URL;
    this.timeout = config.timeout || 30000;
  }

  private async makeRequest<T>(
    endpoint: string,
    params?: Record<string, any>
  ): Promise<T> {
    const url = new URL(this.baseUrl + endpoint);
    
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url.toString(), {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${this.apiKey}`,
          "Content-Type": "application/json"
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new FalconFeedsApiError(
          `API request failed: ${response.statusText}`,
          response.status,
          this.getErrorCode(response.status)
        );
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof FalconFeedsApiError) {
        throw error;
      }
      
      if (error instanceof Error && error.name === "AbortError") {
        throw new FalconFeedsApiError("Request timeout", 408, "timeout");
      }
      
      const errorMessage = error instanceof Error ? error.message : "Unknown error";
      throw new FalconFeedsApiError(
        `Network error: ${errorMessage}`,
        0,
        "network_error"
      );
    }
  }

  private getErrorCode(status: number): string {
    switch (status) {
      case 400: return "bad_request";
      case 401: return "unauthorized";
      case 403: return "forbidden";
      case 404: return "not_found";
      case 429: return "rate_limited";
      case 500: return "internal_error";
      default: return "unknown_error";
    }
  }

  async getCVEs(params: CVEQueryParams): Promise<CVEResponse> {
    this.validateCVEParams(params);
    return this.makeRequest<CVEResponse>(API_CONFIG.ENDPOINTS.CVE, params);
  }

  async getThreatFeeds(params?: ThreatFeedQueryParams): Promise<ThreatFeedResponse> {
    this.validateThreatFeedParams(params);
    return this.makeRequest<ThreatFeedResponse>(API_CONFIG.ENDPOINTS.THREAT_FEED, params);
  }

  async getThreatActors(params?: ThreatActorQueryParams): Promise<ThreatActorResponse> {
    return this.makeRequest<ThreatActorResponse>(API_CONFIG.ENDPOINTS.THREAT_ACTOR, params);
  }

  async getIOCs(params?: IOCQueryParams): Promise<IOCResponse> {
    this.validateIOCParams(params);
    return this.makeRequest<IOCResponse>(API_CONFIG.ENDPOINTS.IOC, params);
  }

  async getIOC(params?: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    this.validateFalconIOCParams(params);
    return this.makeRequest<FalconIOCResponse>(API_CONFIG.ENDPOINTS.IOCV2, params);
  }

  async getIOCsThreatActors(params: IOCsThreatActorQueryParams): Promise<FalconIOCResponse> {
    this.validateFalconIOCParams(params);
    return this.makeRequest<FalconIOCResponse>(API_CONFIG.ENDPOINTS.IOC, params);
  }

  async getThreatImage(imageUuid: string): Promise<ThreatImageResponse> {
    if (!imageUuid) {
      throw new FalconFeedsApiError(
        "Image UUID is required",
        400,
        "invalid_parameter"
      );
    }
    
    return this.makeRequest<ThreatImageResponse>(
      API_CONFIG.ENDPOINTS.THREAT_IMAGE, 
      { uuid: imageUuid }
    );
  }

  private validateCVEParams(params: CVEQueryParams): void {
    if (params.resultCount > API_CONFIG.LIMITS.MAX_CVE_RESULT_COUNT) {
      throw new FalconFeedsApiError(
        `resultCount cannot exceed ${API_CONFIG.LIMITS.MAX_CVE_RESULT_COUNT}`,
        400,
        "invalid_parameter"
      );
    }

    if (params.resultCount < 1) {
      throw new FalconFeedsApiError(
        "resultCount must be at least 1",
        400,
        "invalid_parameter"
      );
    }
  }

  private validateThreatFeedParams(params?: ThreatFeedQueryParams): void {
    if (!params) return;

    if (params.victimKey && !params.victimValue) {
      throw new FalconFeedsApiError(
        "victimValue is required when victimKey is specified",
        400,
        "invalid_parameter"
      );
    }

    if (params.victimValue && !params.victimKey) {
      throw new FalconFeedsApiError(
        "victimKey is required when victimValue is specified",
        400,
        "invalid_parameter"
      );
    }

    // Validate victim value based on victim key
    if (params.victimKey && params.victimValue) {
      this.validateVictimValue(params.victimKey, params.victimValue);
    }
  }

  private validateVictimValue(victimKey: string, victimValue: string): void {
    if (victimKey === "Country") {
      if (!isValidCountry(victimValue)) {
        throw new FalconFeedsApiError(
          `Invalid country name: "${victimValue}". Must be one of the supported countries.`,
          400,
          "invalid_country"
        );
      }
    } else if (victimKey === "Industry") {
      if (!isValidIndustry(victimValue)) {
        throw new FalconFeedsApiError(
          getIndustryValidationMessage(victimValue),
          400,
          "invalid_industry"
        );
      }
    }
  }

  private validateIOCParams(params?: IOCQueryParams): void {
    if (!params) return;

    if (params.page && params.page < 1) {
      throw new FalconFeedsApiError(
        "page must be at least 1",
        400,
        "invalid_parameter"
      );
    }
  }

  private validateFalconIOCParams(params?: FalconIOCQueryParams): void {
    if (!params) return;

    if (params.next !== undefined && params.next === "") {

      throw new FalconFeedsApiError(
        "The 'next' token cannot be an empty string.",
        400,
        "invalid_parameter"
      );
    }
  }
} 
