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
  getIOCs(params:FalconIOCQueryParams):Promise<FalconIOCResponse>;
  getIOCsThreatActors(params: IOCsThreatActorQueryParams): Promise<FalconIOCResponse>;
  getIOCsMalwares(params: IOCsMalwaresQueryParams):Promise<FalconIOCResponse>;
}

export class IOCService implements IIOCService {
  constructor(private readonly apiClient: IApiClient) {}

  async getIOCs(params: FalconIOCQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOC(params);
  }

  async getIOCsThreatActors(params: IOCsThreatActorQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOCsThreatActors(params);
  }

  async getIOCsMalwares(params: IOCsMalwaresQueryParams): Promise<FalconIOCResponse> {
    return this.apiClient.getIOCsMalwares(params);
  }
}