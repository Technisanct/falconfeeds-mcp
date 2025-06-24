import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IThreatActorService } from "../../services/threat-actor/threat-actor-service.js";
import { FalconFeedsApiError } from "../../services/api-client.js";

export function registerThreatActorTools(server: McpServer, threatActorService: IThreatActorService): void {
  server.registerTool(
    "search_threat_actors",
    {
      description: "Search threat actors with optional filters",
      inputSchema: {
        next: z.string().optional().describe("Pagination token for next page"),
        uuid: z.string().optional().describe("Get specific threat actor by UUID"),
        name: z.string().optional().describe("Search threat actors by name prefix")
      }
    },
    async ({ next, uuid, name }) => {
      try {
        let response;
        
        if (uuid) {
          response = await threatActorService.getThreatActorById(uuid);
        } else if (name) {
          response = await threatActorService.searchThreatActorsByName(name);
        } else if (next) {
          response = await threatActorService.getNextPage(next);
        } else {
          response = await threatActorService.searchThreatActors();
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
    "get_threat_actor_by_id",
    {
      description: "Get a specific threat actor by UUID",
      inputSchema: {
        uuid: z.string().describe("Threat actor UUID")
      }
    },
    async ({ uuid }) => {
      try {
        const response = await threatActorService.getThreatActorById(uuid);

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
    "search_threat_actors_by_name",
    {
      description: "Search threat actors by name prefix",
      inputSchema: {
        name: z.string().describe("Threat actor name prefix to search for")
      }
    },
    async ({ name }) => {
      try {
        const response = await threatActorService.searchThreatActorsByName(name);

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
    "get_next_threat_actor_page",
    {
      description: "Get the next page of threat actor results",
      inputSchema: {
        nextToken: z.string().describe("Pagination token from previous response")
      }
    },
    async ({ nextToken }) => {
      try {
        const response = await threatActorService.getNextPage(nextToken);

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