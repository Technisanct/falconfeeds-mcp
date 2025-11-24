import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IIOCService } from "../../services/ioc/ioc-service.js";
import type { ThreatType } from "../../types/index.js";
import { FalconFeedsApiError } from "../../services/api-client.js";

export function registerIOCTools(
  server: McpServer, 
  iocService: IIOCService
): void {
  server.registerTool(
    "search_iocs",
    {
      description: "Search Indicators of Compromise (IOCs) with optional filters. This API may have higher response times (~4 seconds) as it aggregates data from multiple sources. To get the next page of results, call 'get_iocs_page' with the next page number and the same country and threatType parameters.",
      inputSchema: {
        country: z.string().optional().describe("Country name for filtering IOCs. **DO NOT USE ABBREVIATIONS LIKE USA, UK, UAE etc. Instead use full country names like United States, United Kingdom, United Arab Emirates etc.**"),
        page: z.number().optional().describe("Optional page number for pagination (starts from 1)"),
        threatType: z.enum(["botnet_cc", "malware_download", "Malware", "Clean", "general", "Suspicious", "payload"]).optional().describe("Optional filter by threat type")
        }
      },
    async ({ country, page, threatType }) => {
      try {
        const params: any = {};
        
        if (country) params.country = country;
        if (page) params.page = page;
        if (threatType) params.threatType = threatType;

        const response = await iocService.searchIOCs(params);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(response, null, 2)
            }
          ]
        };
      } catch (error) {
        if (error instanceof FalconFeedsApiError) {
          return {
            content: [
              {
                type: "text",
                text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
              }
            ],
            isError: true
          };
        }
        throw error;
      }
    }
  );

  server.registerTool(
    "get_iocs_by_country",
    {
      description: "**PREFERRED for country-specific IOC analysis**: Get IOCs filtered by a specific country. This tool is optimized for analyzing threats targeting or originating from particular countries. Use FULL country names, not abbreviations. To get the next page of results, call 'get_iocs_page' with the next page number and the same country parameter.",
      inputSchema: {
        country: z.string().describe("Country name for filtering IOCs. **DO NOT USE ABBREVIATIONS LIKE USA, UK, UAE etc. Instead use full country names like United States, United Kingdom, United Arab Emirates etc.**")
      }
    },
    async ({ country }) => {
      try {
        const response = await iocService.getIOCsByCountry(country);

        return {
          content: [
            {
              type: "text", 
              text: JSON.stringify(response, null, 2)
            }
          ]
        };
      } catch (error) {
        if (error instanceof FalconFeedsApiError) {
          return {
            content: [
              {
                type: "text",
                text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
              }
            ],
            isError: true
          };
        }
        throw error;
      }
    }
  );

  server.registerTool(
    "get_iocs_by_threat_type",
    {
      description: "Get IOCs filtered by a specific threat type. Use this tool to focus on particular types of threats from the available categories. To get the next page of results, call 'get_iocs_page' with the next page number and the same threatType parameter.",
      inputSchema: {
        threatType: z.enum(["botnet_cc", "malware_download", "Malware", "Clean", "general", "Suspicious", "payload"]).describe("Threat type to filter by from available options")
      }
    },
    async ({ threatType }) => {
      try {
        const response = await iocService.getIOCsByThreatType(threatType);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(response, null, 2)
            }
          ]
        };
      } catch (error) {
        if (error instanceof FalconFeedsApiError) {
          return {
            content: [
              {
                type: "text",
                text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
              }
            ],
            isError: true
          };
        }
        throw error;
      }
    }
  );

  server.registerTool(
    "get_iocs_page",
    {
      description: "Get a specific page of IOC results. To get the next page for a previous query, call this tool with the next page number and the same filtering parameters (country, threatType) as the original query. Each request returns up to 100 IOCs.",
      inputSchema: {
        page: z.number().min(1).describe("Page number to retrieve (starts from 1)"),
        country: z.string().optional().describe("Optional: Country name for filtering IOCs. **DO NOT USE ABBREVIATIONS LIKE USA, UK, UAE etc. Instead use full country names like United States, United Kingdom, United Arab Emirates etc.**"),
        threatType: z.enum(["botnet_cc", "malware_download", "Malware", "Clean", "general", "Suspicious", "payload"]).optional().describe("Optional: Filter by threat type")
      }
    },
    async ({ page, country, threatType }) => {
      try {
        const response = await iocService.getIOCsPage({
          page,
          country,
          threatType
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(response, null, 2)
            }
          ]
        };
      } catch (error) {
        if (error instanceof FalconFeedsApiError) {
          return {
            content: [
              {
                type: "text",
                text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
              }
            ],
            isError: true
          };
        }
        throw error;
      }
    }
  );

  server.registerTool(
    "get_IOCs_by_type",
    {
      description: "Get IOCs filtered by a specific type. Use this tool to focus on particular types from the available categories. To get the next page of results, call 'get_iocs_page' with the next page number and the same type parameter.",
      inputSchema: {
        type: z.enum(["ipv4", "ipv6", "ip:port", "domain", "url", "md5", "sha1", "sha256","sha3"]).describe("Type of IOC to retrieve")
      }
    },
    async ({ type }) => {
      try {
        const response = await iocService.getIOCByType({ type: type });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(response, null, 2)
            }
          ]
        };
      } catch (error) {
        if (error instanceof FalconFeedsApiError) {
          return {
            content: [
              {
                type: "text",
                text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
              }
            ],
            isError: true
          };
        }
        throw error;
      }
    }
  );

server.registerTool(
  "get_iocs_by_malware_uuid",
  {
          description: `Get all IOCs associated with a specific malware by providing the malware's UUID.`,
          inputSchema: {
              uuid: z.string().describe("The UUID of the malware to find associated IOCs for (e.g., 'MAL-Z70YOEPG7OP80T7Q')")
          }
  },
  async ({ uuid }) => {
      try {
          const response = await iocService.getIOCsByMalwareUUID(uuid);

          return {
              content: [
                  {
                      type: "text",
                      text: JSON.stringify(response, null, 2)
                  }
              ]
          };
      } catch (error) {
          if (error instanceof FalconFeedsApiError) {
              return {
                  content: [
                      {
                          type: "text",
                          text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
                      }
                  ],
                  isError: true
              };
          }
          throw error;
      }
  }
);

server.registerTool(
  "get_ioc_by_threatactor_uuid",
  {
          description: `Get all IOCs associated with a specific threat actor by providing the threat actor's UUID.`,
          inputSchema: {
              uuid: z.string().describe("The UUID of the threat actor to find associated IOCs for (e.g., 'XTA-ALHBXKLRWMTB54VB')")
          }
  },
  async ({ uuid }) => {
      try {
          const response = await iocService.getIOCsByThreatActorUUID(uuid);

          return {
              content: [
                  {
                      type: "text",
                      text: JSON.stringify(response, null, 2)
                  }
              ]
          };
      } catch (error) {
          if (error instanceof FalconFeedsApiError) {
              return {
                  content: [
                      {
                          type: "text",
                          text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
                      }
                  ],
                  isError: true
              };
          }
          throw error;
      }
  }
);

server.registerTool(
  "get_iocs_by_confidence",
  {
          description: `Get IOCs filtered by confidence level.`,
          inputSchema: {
              confidence: z.enum(["limited", "moderate", "elevated", "high", "other"]).describe("Confidence level to filter IOCs by (options: limited, moderate, elevated, high, other)")
          }
  },
  async ({ confidence }) => {
      try {
          const response = await iocService.getIOCsByConfidence(confidence as ThreatType);

          return {
              content: [
                  {
                      type: "text",
                      text: JSON.stringify(response, null, 2)
                  }
              ]
          };
      } catch (error) {
          if (error instanceof FalconFeedsApiError) {
              return {
                  content: [
                      {
                          type: "text",
                          text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
                      }
                  ],
                  isError: true
              };
          }
          throw error;
      }
  }
);

server.registerTool(
  "get_iocs_by_keyword",
  {
          description: `Get IOCs filtered by a specific keyword. The keyword will be searched for in the IOC's tags, threat actor names, and malware display names.`,
          inputSchema: {
                    keyword: z.string().describe("Search IoCs by keyword present in tags, threat actor names, or malware display names."),
          }
  },
  async ({ keyword }) => {
      try {
          const response = await iocService.getIOCsByKeyword(keyword);

          return {
              content: [
                  {
                      type: "text",
                      text: JSON.stringify(response, null, 2)
                  }
              ]
          };
      } catch (error) {
          if (error instanceof FalconFeedsApiError) {
              return {
                  content: [
                      {
                          type: "text",
                          text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
                      }
                  ],
                  isError: true
              };
          }
          throw error;
      }
  }
);

server.registerTool(
"get_next_ioc_page",
{
  description: "Get the next page of IOC results for a previous query. To get the next page for a previous query, call this tool with the next page number and the same filtering parameters (country, threatType) as the original query. Each request returns up to 100 IOCs.",
  inputSchema:{
    page: z.number().min(1).describe("Page number to retrieve (starts from 1)"),
    country: z.string().optional().describe("Optional: Country name for filtering IOCs. **DO NOT USE ABBREVIATIONS LIKE USA, UK, UAE etc. Instead use full country names like United States, United Kingdom, United Arab Emirates etc.**"),
    threatType: z.enum(["botnet_cc", "malware_download", "Malware", "Clean", "general", "Suspicious", "payload"]).optional().describe("Optional: Filter by threat type")
  }
},
async ({ page, country, threatType }) => {
  try {
    const response = await iocService.getIOCsPage({
      page,
      country,
      threatType
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(response, null, 2)
        }
      ]
    };
  } catch (error) {
    if (error instanceof FalconFeedsApiError) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error.message} (Status: ${error.status}, Code: ${error.code})`
          }
        ],
        isError: true
      };
    }
    throw error;
  }
}
);

}