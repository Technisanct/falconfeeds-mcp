import type { IApiClient } from "../api-client.js";
import type { 
  ThreatFeedResponse, 
  ThreatFeedQueryParams,
  ThreatCategory,
  VictimKey,
  ThreatImageResponse
} from "../../types/index.js";

export interface IThreatFeedService {
  searchThreatFeeds(params?: ThreatFeedQueryParams): Promise<ThreatFeedResponse>;
  getThreatFeedById(uuid: string): Promise<ThreatFeedResponse>;
  getThreatFeedsByActor(threatActorUUID: string): Promise<ThreatFeedResponse>;
  getThreatFeedsByCategory(category: ThreatCategory): Promise<ThreatFeedResponse>;
  searchThreatFeedsByKeyword(keyword: string): Promise<ThreatFeedResponse>;
  getThreatFeedsByVictim(victimKey: VictimKey, victimValue: string): Promise<ThreatFeedResponse>;
  getNextPage(nextToken: string): Promise<ThreatFeedResponse>;
  getThreatImage(imageUuid: string): Promise<ThreatImageResponse>;
}

export class ThreatFeedService implements IThreatFeedService {
  constructor(private readonly apiClient: IApiClient) {}

  async searchThreatFeeds(params?: ThreatFeedQueryParams): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds(params);
  }

  async getThreatFeedById(uuid: string): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ uuid });
  }

  async getThreatFeedsByActor(threatActorUUID: string): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ threatActorUUID });
  }

  async getThreatFeedsByCategory(category: ThreatCategory): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ category });
  }

  async searchThreatFeedsByKeyword(keyword: string): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ keyword });
  }

  async getThreatFeedsByVictim(victimKey: VictimKey, victimValue: string): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ victimKey, victimValue });
  }

  async getNextPage(nextToken: string): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ next: nextToken });
  }

  async getThreatImage(imageUuid: string): Promise<ThreatImageResponse> {
    return this.apiClient.getThreatImage(imageUuid);
  }
} 