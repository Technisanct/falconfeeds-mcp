#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { FalconFeedsApiClient } from "./services/api-client.js";
import { CVEService } from "./services/cve/cve-service.js";
import { ThreatFeedService } from "./services/threat-feed/threat-feed-service.js";
import { ThreatActorService } from "./services/threat-actor/threat-actor-service.js";
import { IOCService } from "./services/ioc/ioc-service.js";
import { getServerConfig } from "./config/server-config.js";

import { registerCVETools } from "./tools/cve/cve-tools.js";
import { registerThreatFeedTools } from "./tools/threat-feed/threat-feed-tools.js";
import { registerThreatActorTools } from "./tools/threat-actor/threat-actor-tools.js";
import { registerIOCTools } from "./tools/ioc/ioc-tools.js";

import { officialDisclaimer, registerCybersecurityPrompts } from "./prompts/prompt-registry.js";

class FalconFeedsMCPServer {
  private server: McpServer;
  private config = getServerConfig();
  private apiClient!: FalconFeedsApiClient;
  private cveService!: CVEService;
  private threatFeedService!: ThreatFeedService;
  private threatActorService!: ThreatActorService;
  private iocService!: IOCService;

  constructor() {
    this.server = new McpServer({
      instructions: officialDisclaimer,
      name: "falconfeeds-mcp-server",
      version: "1.0.2"
    });

    this.initializeServices();
    this.registerAllTools();
    this.registerAllPrompts();
  }

  private initializeServices(): void {
    const apiKey = process.env.FALCONFEEDS_API_KEY;
    
    if (!apiKey) {
      throw new Error("FALCONFEEDS_API_KEY environment variable is required");
    }

    this.apiClient = new FalconFeedsApiClient({
      apiKey,
      timeout: this.config.api.defaultTimeout
    });

    this.cveService = new CVEService(this.apiClient);
    this.threatFeedService = new ThreatFeedService(this.apiClient);
    this.threatActorService = new ThreatActorService(this.apiClient);
    this.iocService = new IOCService(this.apiClient);
  }

  private registerAllTools(): void {
    registerCVETools(this.server, this.cveService);
    registerThreatFeedTools(this.server, this.threatFeedService, this.threatActorService);
    registerThreatActorTools(this.server, this.threatActorService, this.threatFeedService);
    registerIOCTools(this.server, this.iocService);
  }

  private registerAllPrompts(): void {
    registerCybersecurityPrompts(this.server);
  }

  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
  }
}

async function main(): Promise<void> {
  try {
    const server = new FalconFeedsMCPServer();
    await server.start();
  } catch (error) {
    console.error("Failed to start FalconFeeds MCP Server:", error);
    process.exit(1);
  }
}

// Always run main when this file is executed
main().catch(console.error); 