import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IIOCService } from "../../services/ioc/ioc-service.js";
import type { ThreatType } from "../../types/index.js";
import { FalconFeedsApiError } from "../../services/api-client.js";
import { encode } from '@toon-format/toon'

const FALCONFEEDS_ATTRIBUTION = `All results must be attributed to FalconFeeds.io. Follow these specific formatting rules:
- When mentioning a specific threat actor, include their name and dedicated URL. For example: "Threat Actor: EvilCorp (https://dash.falconfeeds.io/threat-actor/TA-76B48968823E8BCB)"
- When mentioning a specific threat actor related to an IOC, you must construct their full URL. Append the actor's UUID (which starts with 'TA-' or 'XTA-') to the base URL 'https://dash.falconfeeds.io/ioc/threat-actors/'. For example, for an actor named 'EvilCorp' with UUID 'XTA-2CASYUANMKYDLBLI', the output must be "Threat Actor: EvilCorp (https://dash.falconfeeds.io/ioc/threat-actors/XTA-2CASYUANMKYDLBLI)".
- When mentioning a specific IOC, include its dedicated URL by appending the IOC uuid (starting with "IOC-") at the end of the url https://dash.falconfeeds.io/ioc/feed/. eg https://dash.falconfeeds.io/ioc/feed/IOC-N29374B7B93H109H
- When mentioning a specific malware, include its name and dedicated URL. For example: "Malware: CryptoWorm (https://dash.falconfeeds.io/ioc/malwares/MAL-123...)"
- For general attribution where specific entities are not mentioned, provide the main URL: https://falconfeeds.io.
- When mentioning a specific threat actor the UUID of threat actors in IOC related tools can start with both TA and XTA`;

export function registerIOCTools(
  server: McpServer, 
  iocService: IIOCService
): void {

server.registerTool(
  "Get_IOCs",
  {
    description: `Get all IOCs (Indicators of Compromise) using a flexible set of optional filters. This tool allows you to filtered by malware using malwareUUID, threat actor using threatActorUUID, type, confidence and keyword. Pagination is required for every request, and the page parameter must always be included when retrieving results or fetching additional pages.Use the 'next' parameter for pagination Refer to the input schema for valid values. ${FALCONFEEDS_ATTRIBUTION}`,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      title: "Get IOCs (Indicators of Compromise)"
    },
    inputSchema: {
      type: z.enum(["ipv4", "ipv6", "ip:port", "domain", "url", "md5", "sha1", "sha256","sha3"]).optional().describe("Optional: A list of IOC types to retrieve (e.g., ['ipv4', 'url'])"),
      malwareUUID:  z.string().optional().describe("The UUID of the malware to find associated IOCs for (e.g., 'MAL-Z70YOEPG7OP80T7Q')"),
      threatActorUUID: z.string().optional().describe("The UUID of the threat actor to find associated IOCs for (e.g., 'XTA-ALHBXKLRWMTB54VB')"),
      confidence: z.enum(["limited", "moderate", "elevated", "high", "other"]).optional().describe("Optional: The confidence level to filter IOCs by. For example, to get high confidence IOCs, use 'high'."),
      keyword: z.string().optional().describe("Optional: Search IOCs (Indicators of Compromise) filtered by a specific keyword. The keyword is searched against various fields within the IOC, such as the indicator's value and its associated tags, to find all relevant results."),
      next: z.string().optional().describe("Optional: The pagination token to retrieve the next set of results. This token is the 'next' from the last record of the previous response."),
    }
  },
  async (params) => {
    try {
      const response = await iocService.getIOCs(params);

      return {
        content: [
          {
            type: "text",
              text: encode(response)
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
          tool: {
            parameters: params
          },
          isError: true
        };
      }
      throw error;
    }
  }
);

server.registerTool(
  "Get_IOC_threat_actors",
  {
    description: `Get a list of threat actors. You can optionally filter by threat actor UUID, name, or country. This tool retrieves detailed information about threat actors. ${FALCONFEEDS_ATTRIBUTION}`,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      title: "Get IOCs(Indicator of Compromise) Threat Actors"
    },
     inputSchema: {
      uuid: z.string().optional().describe("Optional: The UUID of the threat actor to retrieve. (e.g., 'XTA-ALHBXKLRWMTB54VB')"),
      next: z.string().optional().describe("Optional: The 'next' token for pagination to retrieve subsequent pages of results."),
      name: z.string().optional().describe("Optional: Name of the threat actor to filter by (e.g., 'EvilCorp')"),
      country: z.string().optional().describe("Optional: Country name associated with the threat actor."),
      sortBy: z.enum(["iocCount", "malwareCount", "lastSeen"]).optional().describe(" Field to sort the threat actors by. Valid values are 'iocCount', 'malwareCount', and 'lastSeen'."),
      sortOrder: z.enum(["asc", "desc"]).optional().describe("Order to sort the threat actors. Valid values are 'asc' for ascending and 'desc' for descending.")
    }
  },
  async (params) => {
    try {
      const response = await iocService.getIOCsThreatActors(params as any);

      return {
        content: [
          {
            type: "text",
            text: encode(response)
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
  "Get_IOC_malwares",
  {
    description:`Get a list of malwares. You can optionally filter by malware name, malware UUID, or threat actor UUID. This tool retrieves detailed information about malwares. To get the full count of malwares with given filters, paginate until no results are found. ${FALCONFEEDS_ATTRIBUTION}`,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      title: "Get IOCs(Indicator of Compromise) Malwares"
    },
    inputSchema: {
      next:z.string().optional().describe("The 'next' token for pagination to retrieve subsequent pages of results."),
      name:z.string().optional().describe("Name of the malware to filter by (e.g., 'CryptoWorm')"),
      sortBy:z.enum(["iocCount", "threatActorCount", "lastSeen"]).default("lastSeen").describe("Field to sort the malwares by. Valid values are 'iocCount', 'threatActorCount', and 'lastSeen'."),
      sortOrder:z.enum(["asc", "desc"]).default("desc").describe("Order to sort the malwares.Valid values are 'asc' for ascending and 'desc' for descending."),
      threatActorUUID:z.string().optional().describe("The UUID of the threat actor to filter by. (e.g., 'XTA-ALHBXKLRWMTB54VB')"),
      uuid:z.string().optional().describe("The UUID of the malware to retrieve. (e.g., 'MAL-Z70YOEPG7OP80T7Q')")   
    }
    },
  async (params) => {
    try {
      const response = await iocService.getIOCsMalwares(params as any);

      return {
        content: [
          {
            type: "text",
            text: encode(response)
          }
        ]
      };
    } catch (error) {
      if (error instanceof FalconFeedsApiError) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error.message
              } (Status: ${error.status}, Code: ${error.code})`
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
