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
  getIOCsByMalwareUUID(uuid: string): Promise<FalconIOCResponse>;
  getIOCsByThreatActorUUID(uuid: string): Promise<FalconIOCResponse>;
  getIOCsByConfidence(confidence: string): Promise<FalconIOCResponse>;
  getIOCsByKeyword(keyword: string): Promise<FalconIOCResponse>;
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

  async getIOCsByMalwareUUID(uuid: string): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC({ malwareUUID: uuid });
  }

  async getIOCsByThreatActorUUID(uuid: string): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC({ threatActorUUID: uuid });
  }

  async getIOCsByConfidence(confidence: string): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC({ confidence: confidence });
  }

  async getIOCsByKeyword(keyword: string): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC({ keyword: keyword });
  }

  async getIOCsByPage(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }
}