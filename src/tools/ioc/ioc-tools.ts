import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IIOCService } from "../../services/ioc/ioc-service.js";
import type { ThreatType } from "../../types/index.js";
import { FalconFeedsApiError } from "../../services/api-client.js";

const FALCONFEEDS_ATTRIBUTION = `All results must be attributed to FalconFeeds.io. Follow these specific formatting rules:
- When mentioning a specific threat actor, include their name and dedicated URL. For example: "Threat Actor: EvilCorp (https://dash.falconfeeds.io/threat-actor/TA-76B48968823E8BCB)"
- When mentioning a specific threat actor related to an IOC, you must construct their full URL. Append the actor's UUID (which starts with 'TA-' or 'XTA-') to the base URL 'https://dash.falconfeeds.io/ioc/threat-actors/'. For example, for an actor named 'EvilCorp' with UUID 'XTA-2CASYUANMKYDLBLI', the output must be "Threat Actor: EvilCorp (https://dash.falconfeeds.io/ioc/threat-actors/XTA-2CASYUANMKYDLBLI)".
- When mentioning a specific IOC, include its dedicated URL by appending the IOC uuid (starting with "IOC-") at the end of the url https://dash.falconfeeds.io/ioc/feed/. eg https://dash.falconfeeds.io/ioc/feed/IOC-N29374B7B93H109H
- When mentioning a specific malware, include its name and dedicated URL. For example: "Malware: CryptoWorm (https://dash.falconfeeds.io/ioc/malwares/MAL-123...)"
- For general attribution where specific entities are not mentioned, provide the main URL: https://falconfeeds.io.`;

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
      description: `Get IOCs (Indicators of compromise) filtered by a specific threat type. Use this tool to focus on particular types of threats from the available categories. To get the next page of results, call 'get_iocs_page' with the next page number and the same threatType parameter. ${FALCONFEEDS_ATTRIBUTION}`,
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
      description: `Get IOCs filtered by a specific type. Use this tool to get IOCs (Indicators of compromise) by different types (Refer the available types to know the types you can get IOCs). ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        type: z.enum(["ipv4", "ipv6", "ip:port", "domain", "url", "md5", "sha1", "sha256","sha3"]).describe("Type of IOC to retrieve"),
        page: z.number().min(1).optional().describe("Optional page number for pagination (starts from 1)")
      }
    },
    async ({ type, page }) => {
      try {
        const response = await iocService.getIOCByType({ type: type, page: page });

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
          description: `Get all IOCs (Indicators of compromise) associated with a specific malware. When you retrieve an IOC, its data may contain a 'malware' array. Each object in this array represents a piece of malware and includes a 'uuid'. You can use that UUID with this tool to find all other IOCs linked to the same malware. ${FALCONFEEDS_ATTRIBUTION}`,
          inputSchema: {
              uuid: z.string().describe("The UUID of the malware to find associated IOCs for (e.g., 'MAL-Z70YOEPG7OP80T7Q')"),
              page: z.number().min(1).optional().describe("Optional page number for pagination (starts from 1)")
          }
  },
  async ({ uuid, page }) => {
      try {
          const response = await iocService.getIOCsByMalwareUUID({ malwareUUID: uuid, page: page });

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
  "get_ioc_by_threat_actor_uuid",
  {
          description: `Get all IOCs (Indicators of compromise) associated with a specific threat actor. When you retrieve an IOC, its data may contain a 'threatActors' array. Each object in this array represents a threat actor and includes a 'uuid'. You can use that UUID with this tool to find all other IOCs linked to the same threat actor. ${FALCONFEEDS_ATTRIBUTION}`,
          inputSchema: {
              uuid: z.string().describe("The UUID of the threat actor to find associated IOCs for (e.g., 'XTA-ALHBXKLRWMTB54VB')"),
              page: z.number().min(1).optional().describe("Optional page number for pagination (starts from 1)")
          }
  },
  async ({ uuid, page}) => {
      try {
          const response = await iocService.getIOCsByThreatActorUUID({ threatActorUUID: uuid, page: page });

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
          description: `Get IOCs(Indicators of compromise) filtered by confidence level. ${FALCONFEEDS_ATTRIBUTION}`,
          inputSchema: {
              confidence: z.enum(["limited", "moderate", "elevated", "high", "other"]).describe("Confidence level to filter IOCs by (options: limited, moderate, elevated, high, other)"),
              page: z.number().min(1).optional().describe("Optional page number for pagination (starts from 1)")
          }
  },
  async ({ confidence, page }) => {
      try {
          const response = await iocService.getIOCsByConfidence({ confidence, page });

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
          description: `Get IOCs (Indicators of Compromise) filtered by a specific keyword. The keyword is searched against various fields within the IOC, such as the indicator's value and its associated tags, to find all relevant results. ${FALCONFEEDS_ATTRIBUTION}`,
          inputSchema: {
                    keyword: z.string().describe("Search IoCs by keyword present in tags, threat actor names, or malware display names."),
                    page: z.number().min(1).optional().describe("Optional page number for pagination (starts from 1)")
          }
  },
  async ({ keyword, page }) => {
      try {
          const response = await iocService.getIOCsByKeyword({ keyword, page });

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
  description: `Get the next page of IOC (Indicators of Compromise) results for a previous query. To get the next page for a previous query, call this tool with the next page number and the same filtering parameters (country, threatType) as the original query. Each request returns up to 100 IOCs. ${FALCONFEEDS_ATTRIBUTION}`,
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