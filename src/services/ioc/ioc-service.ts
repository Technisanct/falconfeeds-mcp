import type { IApiClient } from "../api-client.js";
import type { 
  IOCResponse, 
  IOCQueryParams,
  FalconIOCResponse,
  FalconIOCQueryParams
} from "../../types/index.js";

export interface IIOCService {
  searchIOCs(params?: IOCQueryParams): Promise<IOCResponse>;
  getIOCsByCountry(country: string): Promise<IOCResponse>;
  getIOCsByThreatType(threatType: string): Promise<IOCResponse>;
  getIOCsPage(params: IOCQueryParams): Promise<IOCResponse>;
  getIOCByType(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
  getIOCsByMalwareUUID(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
  getIOCsByThreatActorUUID(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
  getIOCsByConfidence(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
  getIOCsByKeyword(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
  getIOCsByPage(params: FalconIOCQueryParams): Promise<FalconIOCResponse>;
}

export class IOCService implements IIOCService {
  constructor(private readonly apiClient: IApiClient) {}

  async searchIOCs(params?: IOCQueryParams): Promise<IOCResponse> {
    return this.apiClient.getIOCs(params);
  }

  async getIOCsByCountry(country: string): Promise<IOCResponse> {
    return this.apiClient.getIOCs({ country });
  }

  async getIOCsByThreatType(threatType: string): Promise<IOCResponse> {
    return this.apiClient.getIOCs({ threatType });
  }

  async getIOCsPage(params: IOCQueryParams): Promise<IOCResponse> {
    return this.apiClient.getIOCs(params);
  }

  async getIOCByType(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsByMalwareUUID(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsByThreatActorUUID(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsByConfidence(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsByKeyword(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsByPage(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }
}