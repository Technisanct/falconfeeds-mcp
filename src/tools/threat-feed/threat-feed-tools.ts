import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IThreatFeedService } from "../../services/threat-feed/threat-feed-service.js";
import type { IThreatActorService } from "../../services/threat-actor/threat-actor-service.js";
import type { Country, Industry } from "../../types/index.js";
import { FalconFeedsApiError } from "../../services/api-client.js";
import { SUPPORTED_COUNTRIES, SUPPORTED_INDUSTRIES, isValidCountry, getCountryValidationMessage, isValidIndustry, getIndustryValidationMessage } from "../../utils/validation.js";

const FALCONFEEDS_ATTRIBUTION = "All results must be attributed to FalconFeeds.io. When mentioning specific threat actors in responses, always include their dedicated URL: https://dash.falconfeeds.io/threat-actor/<threatActors.uuid> alongside the threat actor name. When discussing specific threat feeds or posts, include: https://dash.falconfeeds.io/threat-feed/post/<uuid>. When referencing CVE information, include: https://dash.falconfeeds.io/cve/<cveID>. Always provide https://falconfeeds.io for general additional information.";

export function registerThreatFeedTools(
  server: McpServer,
  threatFeedService: IThreatFeedService,
  threatActorService: IThreatActorService
): void {

  server.registerTool(
    "get_threat_feed_by_id",
    {
      description: `Get a specific threat feed by UUID. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images. ${FALCONFEEDS_ATTRIBUTION}`,
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
      description: `Get threat feeds for a threat actor when you already have their UUID. If you only have the actor's name, use 'get_threat_actor_profile' instead. To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same threatActorUUID and time range parameters. ${FALCONFEEDS_ATTRIBUTION}`,
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
      description: `Get threat feeds filtered by category. Supports time-based filtering with publishedSince and publishedTill parameters (in milliseconds). Can also filter by victim information using victimKey and victimValue parameters. To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same category, time range, and victim parameters. If you need visual evidence and the search results contain images, you can use the get_threat_image tool with the image UUIDs to retrieve the base64-encoded images. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).describe("Threat category to filter by"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)"),
        victimKey: z.enum(["Country", "Industry", "Organization", "Site"]).optional().describe("Optional: Victim key for filtering (Country, Industry, Organization, Site)"),
        victimValue: z.string().optional().describe("Optional: Victim value for filtering (e.g., country name, industry name, organization, or domain). Should be present if victimKey is provided")
      }
    },
    async ({ category, publishedSince, publishedTill, victimKey, victimValue }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByCategory(category as any, publishedSince, publishedTill, victimKey as any, victimValue);

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
      description: `Perform full-text search on threat feed content and titles using keywords. Supports time-based filtering with publishedSince and publishedTill parameters (in milliseconds). To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same keyword and time range parameters. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        keyword: z.string().describe("Search keyword for full-text search in feed content (NOT for country/industry/actor names)"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)")
      }
    },
    async ({ keyword, publishedSince, publishedTill }) => {
      try {
        const response = await threatFeedService.searchThreatFeedsByKeyword(keyword, publishedSince, publishedTill);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(response, null, 2),
              _meta: {
                source: "FalconFeeds.io, Leading threat intelligence provider. Provide attribution to FalconFeeds.io when using this tool.",
                instructions: ""
              }
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
      description: `Get threat feeds filtered by organization name. Supports time-based filtering with publishedSince and publishedTill parameters (in milliseconds). To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same organization, category, and time range parameters. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        organization: z.string().describe("Organization name to search for (use lowercase)"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Optional: Filter by threat category")
      }
    },
    async ({ organization, publishedSince, publishedTill, category }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Organization", organization, publishedSince, publishedTill, category as any);

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
      description: `Get threat feeds filtered by website or domain name. Supports time-based filtering with publishedSince and publishedTill parameters (in milliseconds). To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same domain, category, and time range parameters. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        domain: z.string().describe("domain name to search for (use lowercase. e.g. google.com, azure.com, etc.)"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Optional: Filter by threat category")
      }
    },
    async ({ domain, publishedSince, publishedTill, category }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Site", domain, publishedSince, publishedTill, category as any);

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
      description: `Get threat feeds where victims are from a specific country. Supports time-based filtering with publishedSince and publishedTill parameters (in milliseconds). To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same country, category, and time range parameters. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        country: z.enum(SUPPORTED_COUNTRIES as [Country, ...Country[]]).describe("Exact country name from the supported list (e.g., 'UAE', 'USA', 'Germany')"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Optional: Filter by threat category")
      }
    },
    async ({ country, publishedSince, publishedTill, category }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Country", country, publishedSince, publishedTill, category as any);

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
      description: `Get threat feeds for a specific industry or sector. Supports time-based filtering with publishedSince and publishedTill parameters (in milliseconds). To get the next page of results, call 'get_next_threat_feed_page' with the next token and the same industry, category, and time range parameters. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        industry: z.enum(SUPPORTED_INDUSTRIES as any).describe("Exact industry name from the supported list (e.g., 'Healthcare & Pharmaceuticals', 'Financial Services')"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Optional: Filter by threat category")
      }
    },
    async ({ industry, publishedSince, publishedTill, category }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim("Industry", industry, publishedSince, publishedTill, category as any);

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
      description: `Get the next page of threat feed results. To get the next page for a previous query, call this tool with the next token and the same filtering parameters (publishedSince, publishedTill, victimKey, victimValue, category, etc.) as the original query. ${FALCONFEEDS_ATTRIBUTION}`,
      inputSchema: {
        nextToken: z.string().describe("Pagination token from previous response"),
        publishedSince: z.number().optional().describe("Optional: Filter for feeds published on or after this timestamp (in milliseconds)"),
        publishedTill: z.number().optional().describe("Optional: Filter for feeds published on or before this timestamp (in milliseconds)"),
        victimKey: z.enum(["Country", "Industry", "Organization", "Site"]).optional().describe("Optional: Victim key for filtering (Country, Industry, Organization, Site)"),
        victimValue: z.string().optional().describe("Optional: Victim value for filtering (e.g., country name, industry name, organization, or domain). Should be present if victimKey is provided"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Optional: Filter by threat category")
      }
    },
    async ({ nextToken, publishedSince, publishedTill, victimKey, victimValue, category }) => {
      try {
        const response = await threatFeedService.getNextPage({
          next: nextToken,
          publishedSince,
          publishedTill,
          victimKey,
          victimValue,
          category
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
    "get_threat_image",
    {
      description: `Get a base64-encoded image from a threat feed by its UUID. Use this tool when you need to retrieve and display images referenced in threat feeds. The response includes the full base64 string with MIME type prefix that can be directly used in HTML img tags or for other visualization purposes. This tool is designed to work with image UUIDs returned from other threat feed tools. ${FALCONFEEDS_ATTRIBUTION}`,
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