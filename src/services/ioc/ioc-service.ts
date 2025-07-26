import type { IApiClient } from "../api-client.js";
import type { 
  IOCResponse, 
  IOCQueryParams
} from "../../types/index.js";

export interface IIOCService {
  searchIOCs(params?: IOCQueryParams): Promise<IOCResponse>;
  getIOCsByCountry(country: string): Promise<IOCResponse>;
  getIOCsByThreatType(threatType: string): Promise<IOCResponse>;
  getIOCsPage(params: IOCQueryParams): Promise<IOCResponse>;
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
} 