export interface ImageResponse {
  image: string;
}

export type ImageType = "base64" | "blob";

export interface ImageQueryParams {
  uuid: string;
  type?: ImageType;
} 