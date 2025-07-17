export interface IOC {
  id: string;
  iocValue: string;
  iocType: string;
  threat: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
  tags: string[];
  confidence: string;
  country: string[];
  source: string;
  threatType: string[];
}

export interface IOCResponse {
  message: string;
  data: IOC[];
  next?: string;
}

export type ThreatType = 
  | "botnet_cc"
  | "malware_download"
  | "Malware"
  | "Clean"
  | "general"
  | "Suspicious"
  | "payload";

export interface IOCQueryParams {
  country?: string;
  page?: number;
  threatType?: string;
} 