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

export interface FalconIOCQueryParams {
  type?: string;
  next?: string;
  malwareUUID?: string;
  threatActorUUID?: string;
  confidence?: string;
  keyword?: string;
  uuid?: string;
}

export interface IOCsThreatActorQueryParams {
  uuid: string;
  after?: string;
  name?: string;
  country?: string;
  SortBy?: string;
  SortOrder?: string;
}

export interface FalconIOCResponse {
  message: string;
  data: FalconIOC[];
  next?: string;
}

export interface FalconIOC {
  uuid: string;
  type: string;
  threatType: ThreatType[];
  ttp: string[];
  indicator: string;
  threatActors: IOCThreatActor[];
  malware: IOCMalware[];
  victims: IOCVictim[];
  createdAt: string;
  updatedAt: string;
  tags: string[];
  confidence: string;
}

export interface IOCThreatActor {
  uuid: string;
  name: string;
}

export interface IOCMalware {
  uuid: string;
  name: string;
}

export interface IOCVictim {
  uuid: string;
  name: string;
}