# FalconFeeds MCP Server

A Model Context Protocol (MCP) server that provides access to FalconFeeds.io threat intelligence data, including CVEs, threat feeds, threat actor information, and threat-related images.

## Features

- **CVE Intelligence**: Search and retrieve Common Vulnerabilities and Exposures data
- **Threat Feeds**: Access real-time threat intelligence feeds
- **Threat Actors**: Get detailed information about threat actors and groups
- **Threat Images**: Retrieve screenshots and images from threat feeds
- **Cybersecurity Prompts**: Pre-built prompts for threat intelligence analysis

## Installation

### Prerequisites

- Node.js 18.0.0 or higher
- FalconFeeds API key

### Setup

1. Clone or download this repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the project:
   ```bash
   npm run build
   ```

4. Set up your environment variables:
   ```bash
   export FALCONFEEDS_API_KEY="your_api_key_here"
   export FALCONFEEDS_TIMEOUT="30000"  # Optional, defaults to 30 seconds
   ```

## Usage

### Running the Server

Start the server in development mode:
```bash
npm run dev
```

Or run the built version:
```bash
npm start
```

### Configuration

The server requires the following environment variables:

- `FALCONFEEDS_API_KEY` (required): Your FalconFeeds API key
- `FALCONFEEDS_TIMEOUT` (optional): Request timeout in milliseconds (default: 30000)

### Available Tools

#### CVE Tools
- `search_cves`: Search for CVEs with various filters
- `get_cve_by_id`: Get specific CVE by ID
- `search_cves_by_keyword`: Search CVEs by keyword
- `get_cves_by_date_range`: Get CVEs within a date range
- `get_next_cve_page`: Get next page of CVE results

#### Threat Feed Tools
- `search_threat_feeds`: Search threat feeds with filters
- `get_threat_feed_by_id`: Get specific threat feed by UUID
- `get_threat_feeds_by_actor`: Get feeds for specific threat actor
- `get_threat_feeds_by_category`: Get feeds by category
- `search_threat_feeds_by_keyword`: Search feeds by keyword
- `get_threat_feeds_by_victim`: Get feeds targeting specific victims
- `get_next_threat_feed_page`: Get next page of feed results

#### Threat Actor Tools
- `search_threat_actors`: Search threat actors
- `get_threat_actor_by_id`: Get specific threat actor by UUID
- `search_threat_actors_by_name`: Search actors by name
- `get_next_threat_actor_page`: Get next page of actor results

#### Threat Image Tools
- `get_threat_image`: Get threat image by UUID
- `get_threat_image_as_base64`: Get image in base64 format
- `get_threat_image_as_blob`: Get image as blob

### Available Prompts

The server includes specialized prompts for cybersecurity professionals:

1. **threat_intelligence_report**: Generate comprehensive threat intelligence reports
2. **cve_impact_assessment**: Assess CVE impact and urgency
3. **incident_threat_correlation**: Correlate incidents with threat actors
4. **vulnerability_trend_analysis**: Analyze vulnerability trends
5. **threat_hunting_playbook**: Create threat hunting procedures
6. **supply_chain_threat_analysis**: Analyze supply chain threats
7. **ioc_enrichment_analysis**: Enrich indicators of compromise
8. **sector_threat_briefing**: Generate sector-specific threat briefings
9. **malware_family_analysis**: Analyze malware families
10. **geopolitical_threat_assessment**: Assess geopolitical cyber threats

## API Endpoints

The server provides access to the following FalconFeeds API endpoints:

- `/cve` - CVE information
- `/threat/feed` - Threat intelligence feeds
- `/threat/actor` - Threat actor information
- `/threat/image` - Threat feed images

## Development

### Project Structure

```
src/
├── config/           # Configuration files
├── services/         # Service layer (organized by endpoint)
│   ├── cve/
│   ├── threat-feed/
│   ├── threat-actor/
│   └── threat-image/
├── tools/            # MCP tools (organized by endpoint)
│   ├── cve/
│   ├── threat-feed/
│   ├── threat-actor/
│   └── threat-image/
├── types/            # TypeScript type definitions
├── prompts/          # Cybersecurity prompts
└── index.ts          # Main server entry point
```

### Adding New Endpoints

To add a new FalconFeeds API endpoint:

1. Add the endpoint configuration to `src/config/api-endpoints.ts`
2. Create the TypeScript interfaces in `src/types/falconfeeds.ts`
3. Create a service class in `src/services/[endpoint-name]/`
4. Create MCP tools in `src/tools/[endpoint-name]/`
5. Register the tools in `src/index.ts`

### Adding New Prompts

To add new cybersecurity prompts:

1. Add the prompt configuration to `CYBERSECURITY_PROMPTS` in `src/prompts/prompt-registry.ts`
2. The prompt will be automatically registered when the server starts

## License

ISC

## Contributing

This project follows SOLID principles and clean architecture patterns. Please ensure:

- Each endpoint has its own service and tools directory
- All API responses are properly typed
- Error handling follows the established patterns
- New prompts are relevant to cybersecurity professionals 