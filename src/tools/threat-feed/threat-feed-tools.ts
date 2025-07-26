import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IThreatFeedService } from "../../services/threat-feed/threat-feed-service.js";
import type { IThreatActorService } from "../../services/threat-actor/threat-actor-service.js";
import type { Country, Industry } from "../../types/index.js";
import { FalconFeedsApiError } from "../../services/api-client.js";
import { SUPPORTED_COUNTRIES, SUPPORTED_INDUSTRIES, isValidCountry, getCountryValidationMessage, isValidIndustry, getIndustryValidationMessage } from "../../utils/validation.js";

export function registerThreatFeedTools(
  server: McpServer,
  threatFeedService: IThreatFeedService,
  threatActorService: IThreatActorService
): void {

  server.registerTool(
    "get_threat_feed_by_id",
    {
      description: "Get a specific threat feed by UUID.If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        uuid: z.string().describe("Threat feed UUID")
      }
    },
    async ({ uuid }) => {
      try {
        const response = await threatFeedService.getThreatFeedById(uuid);

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
    "get_threat_feeds_by_actor",
    {
      description: "Get threat feeds for a threat actor when you already have their UUID. If you only have the actor's name, use 'get_threat_actor_profile' instead. Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the threat feed results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        threatActorUUID: z.string().describe("Threat actor UUID (if you only have the name, use get_threat_actor_profile tool)")
      }
    },
    async ({ threatActorUUID }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByActor(threatActorUUID);

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
    "get_threat_feeds_by_category",
    {
      description: "Get threat feeds filtered by category. Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).describe("Threat category to filter by")
      }
    },
    async ({ category }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByCategory(category as any);

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
    "search_threat_feeds_by_keyword",
    {
      description: "Perform full-text search on threat feed content and titles using keywords. Use this for general content searches, NOT for country names, industry names, or threat actor names (use their dedicated tools instead). Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        keyword: z.string().describe("Search keyword for full-text search in feed content (NOT for country/industry/actor names)")
      }
    },
    async ({ keyword }) => {
      try {
        const response = await threatFeedService.searchThreatFeedsByKeyword(keyword);

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
    "get_threat_feeds_by_organization",
    {
      description: "Get threat feeds filtered by organization name. Use this tool to find threats targeting specific companies or organizations. Use lowercase for organization names. Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        organization: z.string().describe("Organization name to search for (use lowercase)")
      }
    },
    async ({ organization }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Organization", organization);

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
    "get_threat_feeds_by_domain",
    {
      description: "Get threat feeds filtered by website or domain name. Use this tool to find threats targeting specific websites or domains. Use lowercase for domain names. Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        domain: z.string().describe("domain name to search for (use lowercase. e.g. google.com, azure.com, etc.)")
      }
    },
    async ({ domain }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Site", domain);

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
    "get_threat_feeds_by_country",
    {
      description: "**PREFERRED for country-based threat landscape**: Get threat feeds where victims are from a specific country. Use this tool when searching for threats by country (e.g., 'UAE', 'USA', 'Germany'). The country name must match exactly from the supported list. Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        country: z.enum(SUPPORTED_COUNTRIES as [Country, ...Country[]]).describe("Exact country name from the supported list (e.g., 'UAE', 'USA', 'Germany')")
      }
    },
    async ({ country }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Country", country);

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
    "get_threat_feeds_by_industry",
    {
      description: "Get threat feeds for a specific industry or sector. Use this tool when analyzing threats by industry (e.g., 'Healthcare & Pharmaceuticals', 'Financial Services', 'Government & Public Sector'). The industry name must match exactly from the supported list. Use 'get_next_threat_feed_page' tool to get more results when pagination is needed. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        industry: z.enum(SUPPORTED_INDUSTRIES as any).describe("Exact industry name from the supported list (e.g., 'Healthcare & Pharmaceuticals', 'Financial Services')")
      }
    },
    async ({ industry }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Industry", industry);

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
    "get_next_threat_feed_page",
    {
      description: "Get the next page of threat feed results.If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images",
      inputSchema: {
        nextToken: z.string().describe("Pagination token from previous response")
      }
    },
    async ({ nextToken }) => {
      try {
        const response = await threatFeedService.getNextPage(nextToken);

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
    "get_threat_image",
    {
      description: "Get a base64-encoded image from a threat feed by its UUID. Use this tool when you need to retrieve and display images referenced in threat feeds. The response includes the full base64 string with MIME type prefix that can be directly used in HTML img tags or for other visualization purposes. This tool is designed to work with image UUIDs returned from other threat feed tools.",
      inputSchema: {
        imageUuid: z.string().describe("UUID of the image to retrieve")
      }
    },
    async ({ imageUuid }) => {
      try {
        const response = await threatFeedService.getThreatImage(imageUuid);
        
        const imageData = response?.data?.image;
        
        if (!imageData) {
          return {
            content: [
              {
                type: "text",
                text: "Error: No image data received from API"
              }
            ],
            isError: true
          };
        }
        
        const mimeTypeMatch = imageData.match(/^data:([^;]+);base64,(.+)$/);
        
        if (!mimeTypeMatch) {
          return {
            content: [
              {
                type: "text",
                text: "Error: Invalid image data format received from API"
              }
            ],
            isError: true
          };
        }
        
        const [, mimeType, base64Data] = mimeTypeMatch;
        
        return {
          content: [
            {
              type: "image",
              data: base64Data,
              mimeType: mimeType
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