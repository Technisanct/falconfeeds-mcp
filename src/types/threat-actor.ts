export interface Alias {
  uuid: string;
  name: string;
}

export interface ActiveChannel {
  network: string;
  link: string;
}

export interface Target {
  type: string;
  values: string[];
}

export interface GroupMember {
  uuid: string;
  name: string;
}

export interface ThreatActorMeta {
  type: string;
  groupLeaders: GroupMember[];
  groupMembers: GroupMember[];
}

export interface ThreatActorDetails {
  uuid: string;
  name: string;
  description: string;
  category: string;
  alias: Alias[];
  suspectedAlias: Alias[];
  activeChannels: ActiveChannel[];
  targets: Target[];
  lastActivityReportedAt: string;
  firstActivityReportedAt: string;
  meta: ThreatActorMeta;
}

export interface ThreatActorResponse {
  data: ThreatActorDetails[];
  next?: string;
}

export interface ThreatActorQueryParams {
  next?: string;
  uuid?: string;
  name?: string;
} 