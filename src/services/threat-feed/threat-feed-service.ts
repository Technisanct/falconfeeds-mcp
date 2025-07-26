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
  getThreatFeedsByActor(threatActorUUID: string, publishedSince?: number, publishedTill?: number): Promise<ThreatFeedResponse>;
  getThreatFeedsByCategory(category: ThreatCategory, publishedSince?: number, publishedTill?: number, victimKey?: VictimKey, victimValue?: string): Promise<ThreatFeedResponse>;
  searchThreatFeedsByKeyword(keyword: string, publishedSince?: number, publishedTill?: number): Promise<ThreatFeedResponse>;
  getThreatFeedsByVictim(victimKey: VictimKey, victimValue: string, publishedSince?: number, publishedTill?: number, category?: ThreatCategory): Promise<ThreatFeedResponse>;
  getNextPage(params: ThreatFeedQueryParams): Promise<ThreatFeedResponse>;
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

  async getThreatFeedsByActor(threatActorUUID: string, publishedSince?: number, publishedTill?: number): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ 
      threatActorUUID,
      publishedSince,
      publishedTill
    });
  }

  async getThreatFeedsByCategory(category: ThreatCategory, publishedSince?: number, publishedTill?: number, victimKey?: VictimKey, victimValue?: string): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ 
      category,
      publishedSince,
      publishedTill,
      victimKey,
      victimValue
    });
  }

  async searchThreatFeedsByKeyword(keyword: string, publishedSince?: number, publishedTill?: number): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ 
      keyword,
      publishedSince,
      publishedTill
    });
  }

  async getThreatFeedsByVictim(victimKey: VictimKey, victimValue: string, publishedSince?: number, publishedTill?: number, category?: ThreatCategory): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds({ 
      victimKey, 
      victimValue,
      publishedSince,
      publishedTill,
      category
    });
  }

  async getNextPage(params: ThreatFeedQueryParams): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds(params);
  }

  async getThreatImage(imageUuid: string): Promise<ThreatImageResponse> {
    return this.apiClient.getThreatImage(imageUuid);
  }
} 