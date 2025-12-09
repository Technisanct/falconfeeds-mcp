import type { IApiClient } from "../api-client.js";
import type { 
  ThreatFeedResponse, 
  ThreatFeedQueryParams,
  ThreatCategory,
  VictimKey,
  ThreatImageResponse
} from "../../types/index.js";

export interface IThreatFeedService {
  getThreatFeeds(params: ThreatFeedQueryParams): Promise<ThreatFeedResponse>;
}

export class ThreatFeedService implements IThreatFeedService {
  constructor(private readonly apiClient: IApiClient) {}

  async getThreatFeeds(params: ThreatFeedQueryParams): Promise<ThreatFeedResponse> {
    return this.apiClient.getThreatFeeds(params);
  }
} 