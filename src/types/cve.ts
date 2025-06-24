export interface CVEMetadata {
  cveId: string;
  state: string;
  assignerOrgId: string;
  assignerShortName: string;
  dateReservedInMilliseconds: number;
  datePublishedInMilliseconds: number;
  dateUpdatedInMilliseconds: number;
  dateRejectedInMilliseconds: number;
  yearDiscovered: number;
}

export interface Version {
  lessThan?: string;
  lessThanOrEqual?: string;
  greaterThan?: string;
  greaterThanOrEqual?: string;
  status: string;
  version: string;
  versionType: string;
}

export interface Affected {
  collectionURL: string;
  packageName: string;
  product: string;
  vendor: string;
  versions: Version[];
  defaultStatus: string;
  modules: string[];
}

export interface Description {
  lang: string;
  description: string;
}

export interface CNA {
  affected: Affected[];
  descriptions: Description[];
  metrics: any[];
  references: any[];
  providerMetadata: any;
  problemType: any[];
  replacedBy: any[];
  rejectedReasons: any[];
}

export interface CVE {
  cveMetadata: CVEMetadata;
  cna: CNA;
}

export interface CVEResponse {
  data: CVE[];
  next?: string;
}

export interface CVEQueryParams {
  cveID?: string;
  keyword?: string;
  publishedSince?: number;
  publishedTill?: number;
  resultCount: number;
  next?: string;
} 