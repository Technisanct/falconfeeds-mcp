import type { IApiClient } from "../api-client.js";
import type { 
  ImageResponse, 
  ImageQueryParams,
  ImageType
} from "../../types/index.js";

export interface IThreatImageService {
  getThreatImage(uuid: string, type?: ImageType): Promise<ImageResponse>;
  getThreatImageAsBase64(uuid: string): Promise<ImageResponse>;
  getThreatImageAsBlob(uuid: string): Promise<ImageResponse>;
}

export class ThreatImageService implements IThreatImageService {
  constructor(private readonly apiClient: IApiClient) {}

  async getThreatImage(uuid: string, type: ImageType = "base64"): Promise<ImageResponse> {
    return this.apiClient.getThreatImage({ uuid, type });
  }

  async getThreatImageAsBase64(uuid: string): Promise<ImageResponse> {
    return this.apiClient.getThreatImage({ uuid, type: "base64" });
  }

  async getThreatImageAsBlob(uuid: string): Promise<ImageResponse> {
    return this.apiClient.getThreatImage({ uuid, type: "blob" });
  }
} 