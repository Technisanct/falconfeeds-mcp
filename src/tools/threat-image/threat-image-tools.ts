import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { IThreatImageService } from "../../services/threat-image/threat-image-service.js";
import { FalconFeedsApiError } from "../../services/api-client.js";

export function registerThreatImageTools(server: McpServer, threatImageService: IThreatImageService): void {
  server.registerTool(
    "get_threat_image",
    {
      description: "Get a threat image by UUID in specified format",
      inputSchema: {
        uuid: z.string().describe("Image UUID"),
        type: z.enum(["base64", "blob"]).default("base64").describe("Image format type")
      }
    },
    async ({ uuid, type = "base64" }) => {
      try {
        const response = await threatImageService.getThreatImage(uuid, type as any);

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
    "get_threat_image_as_base64",
    {
      description: "Get a threat image as base64 encoded string",
      inputSchema: {
        uuid: z.string().describe("Image UUID")
      }
    },
    async ({ uuid }) => {
      try {
        const response = await threatImageService.getThreatImageAsBase64(uuid);

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
    "get_threat_image_as_blob",
    {
      description: "Get a threat image as blob data",
      inputSchema: {
        uuid: z.string().describe("Image UUID")
      }
    },
    async ({ uuid }) => {
      try {
        const response = await threatImageService.getThreatImageAsBlob(uuid);

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