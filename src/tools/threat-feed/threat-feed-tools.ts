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
      description: "Get comprehensive threat actor profile including attributed threat feeds. This tool automatically finds the threat actor by name and retrieves their associated threat feeds.",
      inputSchema: {
        actorName: z.string().describe("Name of the threat actor (e.g., 'LockBit', 'APT29', 'Lazarus Group')"),
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
    "search_threat_feeds",
    {
      description: "Search threat feeds with various filters",
      inputSchema: {
        next: z.string().optional().describe("Pagination token for next page"),
        threatActorUUID: z.string().optional().describe("Filter by specific threat actor UUID"),
        category: z.enum(["Ransomware", "Data Breach", "Data Leak", "Malware", "DDoS Attack", "Phishing", "Combo List", "Logs", "Defacement", "Alert", "Vulnerability"]).optional().describe("Filter by threat category"),
        keyword: z.string().optional().describe("Search keyword in threat feed content"),
        victimKey: z.enum(["Country", "Industry", "Organization", "Site"]).optional().describe("Type of victim filter"),
        victimValue: z.string().optional().describe("Value for victim filter")
      }
    },
    async ({ next, threatActorUUID, category, keyword, victimKey, victimValue }) => {
      try {
        let response;
        
        if (threatActorUUID) {
          response = await threatFeedService.getThreatFeedsByActor(threatActorUUID);
        } else if (category) {
          response = await threatFeedService.getThreatFeedsByCategory(category as any);
        } else if (keyword) {
          response = await threatFeedService.searchThreatFeedsByKeyword(keyword);
        } else if (victimKey && victimValue) {
          response = await threatFeedService.getThreatFeedsByVictim(victimKey as any, victimValue);
        } else if (next) {
          response = await threatFeedService.getNextPage(next);
        } else {
          response = await threatFeedService.searchThreatFeeds();
        }

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
      description: "Get threat feeds associated with a specific threat actor",
      inputSchema: {
        threatActorUUID: z.string().describe("Threat actor UUID")
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
      description: "Search threat feeds by keyword",
      inputSchema: {
        keyword: z.string().describe("Search keyword")
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
      description: "Get threat feeds filtered by victim criteria",
      inputSchema: {
        victimKey: z.enum(["Country", "Industry", "Organization", "Site"]).describe("Type of victim filter"),
        victimValue: z.string().describe("Value for the victim filter")
      }
    },
    async ({ victimKey, victimValue }) => {
      try {
        // Validate values based on victim key type
        if (victimKey === "Country" && !isValidCountry(victimValue)) {
          return {
            content: [
              {
                type: "text",
                text: getCountryValidationMessage(victimValue)
              }
            ],
            isError: true
          };
        }

        if (victimKey === "Industry" && !isValidIndustry(victimValue)) {
          return {
            content: [
              {
                type: "text",
                text: getIndustryValidationMessage(victimValue)
              }
            ],
            isError: true
          };
        }

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
      description: "Get threat feeds filtered by specific country (with validation)",
      inputSchema: {
        country: z.enum(SUPPORTED_COUNTRIES as [Country, ...Country[]]).describe("Country name from the supported list")
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
      description: "Get threat feeds filtered by specific industry (with validation)",
      inputSchema: {
        industry: z.enum(SUPPORTED_INDUSTRIES as any).describe("Industry name from the supported list")
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
} 