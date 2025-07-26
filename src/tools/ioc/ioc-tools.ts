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
} 