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
  // Smart tool that implements the better flow automatically
  server.registerTool(
    "get_threat_actor_profile",
    {
      description: "**PREFERRED for threat actor searches by name**: Get comprehensive threat actor profile including attributed threat feeds. Use this tool when you have a threat actor NAME (like 'LockBit', 'LEAKBASE', 'APT29') and want to find their profile and associated threat feeds. This automatically searches for the actor by name first, then retrieves their feeds.",
      inputSchema: {
        actorName: z.string().describe("Name of the threat actor (e.g., 'LockBit', 'APT29', 'Lazarus Group', 'LEAKBASE')"),
        includeFeeds: z.boolean().optional().default(true).describe("Whether to include associated threat feeds (default: true)")
      }
    },
    async ({ actorName, includeFeeds = true }) => {
      try {
        // Step 1: Search for the threat actor by name
        const actorSearchResponse = await threatActorService.searchThreatActorsByName(actorName);
        
        if (!actorSearchResponse.data || actorSearchResponse.data.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No threat actor found with name: "${actorName}". Please check the spelling or try a different name.`
              }
            ]
          };
        }

        // Get the first matching actor (most relevant)
        const threatActor = actorSearchResponse.data[0];
        
        let result: any = {
          threatActor: threatActor,
          searchQuery: actorName,
          matchedActors: actorSearchResponse.data.length
        };

        // Step 2: If requested, get threat feeds attributed to this actor
        if (includeFeeds) {
          try {
            const feedsResponse = await threatFeedService.getThreatFeedsByActor(threatActor.uuid);
            result.attributedFeeds = {
              count: feedsResponse.data?.length || 0,
              feeds: feedsResponse.data || [],
              hasMore: !!feedsResponse.next,
              nextToken: feedsResponse.next
            };
          } catch (feedError) {
            result.attributedFeeds = {
              error: "Failed to retrieve attributed threat feeds",
              details: feedError instanceof FalconFeedsApiError ? feedError.message : "Unknown error"
            };
          }
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2)
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
    "get_threat_feed_by_id",
    {
      description: "Get a specific threat feed by UUID",
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
      description: "Get threat feeds for a threat actor when you already have their UUID. If you only have the actor's name, use 'get_threat_actor_profile' instead.",
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
      description: "Get threat feeds filtered by category",
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
      description: "Perform full-text search on threat feed content and titles using keywords. Use this for general content searches, NOT for country names, industry names, or threat actor names (use their dedicated tools instead).",
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
    "get_threat_feeds_by_victim",
    {
      description: "Get threat feeds filtered by organization name or website/domain. Use this ONLY for specific organization names or websites. For countries, use 'get_threat_feeds_by_country'. For industries, use 'get_threat_feeds_by_industry'.",
      inputSchema: {
        victimKey: z.enum(["Organization", "Site"]).describe("Type of victim filter: 'Organization' for company names, 'Site' for websites/domains"),
        victimValue: z.string().describe("Specific organization name or website/domain to search for")
      }
    },
    async ({ victimKey, victimValue }) => {
      try {
        const response = await threatFeedService.getThreatFeedsByVictim(victimKey as any, victimValue);

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
      description: "**PREFERRED for country-based threat landscape**: Get threat feeds where victims are from a specific country. Use this tool when searching for threats by country (e.g., 'UAE', 'USA', 'Germany'). The country name must match exactly from the supported list.",
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
      description: "**PREFERRED for industry-based threat analysis**: Get threat feeds where victims are from a specific industry sector. Use this tool when analyzing threats by industry (e.g., 'Healthcare & Pharmaceuticals', 'Financial Services', 'Government & Public Sector'). The industry name must match exactly from the supported list.",
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
      description: "Get the next page of threat feed results",
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
    "search_threat_feeds_with_images",
    {
      description: "**PREFERRED for comprehensive threat feed searches that need direct image urls**: Search threat feeds with direct image URLs included. This tool automatically includes image URLs in the response, providing direct access to screenshots and visual evidence from threat feeds. Use this for general threat intelligence gathering when you need complete information including visual assets.",
      inputSchema: {
        keyword: z.string().optional().describe("Optional keyword for full-text search in feed content"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Optional threat category filter"),
        threatActorUUID: z.string().optional().describe("Optional threat actor UUID filter"),
        victimKey: z.enum(["Country", "Industry", "Organization", "Site"]).optional().describe("Optional victim filter type"),
        victimValue: z.string().optional().describe("Optional victim filter value (required if victimKey is specified)"),
        next: z.string().optional().describe("Optional pagination token for next page")
      }
    },
    async ({ keyword, category, threatActorUUID, victimKey, victimValue, next }) => {
      try {
        // Validate that victimValue is provided if victimKey is specified
        if (victimKey && !victimValue) {
          return {
            content: [
              {
                type: "text",
                text: "Error: victimValue is required when victimKey is specified"
              }
            ],
            isError: true
          };
        }

        const params: any = { includeImages: true };
        
        if (keyword) params.keyword = keyword;
        if (category) params.category = category;
        if (threatActorUUID) params.threatActorUUID = threatActorUUID;
        if (victimKey) params.victimKey = victimKey;
        if (victimValue) params.victimValue = victimValue;
        if (next) params.next = next;

        const response = await threatFeedService.searchThreatFeeds(params);

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