import type { IApiClient } from "../api-client.js";
import type { 
  IOCResponse, 
  IOCQueryParams,
  FalconIOCResponse,
  FalconIOCQueryParams,
  IOCsThreatActorQueryParams,
  IOCsMalwaresQueryParams
} from "../../types/index.js";

export interface IIOCService {
  searchIOCs(params?: IOCQueryParams): Promise<IOCResponse>;
  getIOCsByCountry(country: string): Promise<IOCResponse>;
  getIOCsByThreatType(threatType: string): Promise<IOCResponse>;
  getIOCsPage(params: IOCQueryParams): Promise<IOCResponse>;
  getIOCsByFilters(params:FalconIOCQueryParams):Promise<FalconIOCResponse>;
  getIOCsThreatActors(params: IOCsThreatActorQueryParams): Promise<FalconIOCResponse>;
  getIOCsMalwares(params: IOCsMalwaresQueryParams):Promise<FalconIOCResponse>;
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

  async getIOCsByFilters(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsThreatActors(params: IOCsThreatActorQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOCsThreatActors(params);
  }

  async getIOCsMalwares(params: IOCsMalwaresQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOCsMalwares(params);
  }
}