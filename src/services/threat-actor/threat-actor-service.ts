import type { IApiClient } from "../api-client.js";
import type { 
  ThreatActorResponse, 
  ThreatActorQueryParams
} from "../../types/index.js";

export interface IThreatActorService {
  searchThreatActors(params?: ThreatActorQueryParams): Promise<ThreatActorResponse>;
  getThreatActorById(uuid: string): Promise<ThreatActorResponse>;
  searchThreatActorsByName(name: string): Promise<ThreatActorResponse>;
  getNextPage(nextToken: string): Promise<ThreatActorResponse>;
}

export class ThreatActorService implements IThreatActorService {
  constructor(private readonly apiClient: IApiClient) {}

  async searchThreatActors(params?: ThreatActorQueryParams): Promise<ThreatActorResponse> {
    return this.apiClient.getThreatActors(params);
  }

  async getThreatActorById(uuid: string): Promise<ThreatActorResponse> {
    return this.apiClient.getThreatActors({ uuid });
  }

  async searchThreatActorsByName(name: string): Promise<ThreatActorResponse> {
    return this.apiClient.getThreatActors({ name });
  }

  async getNextPage(nextToken: string): Promise<ThreatActorResponse> {
    return this.apiClient.getThreatActors({ next: nextToken });
  }
} 