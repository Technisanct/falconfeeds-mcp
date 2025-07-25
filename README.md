<div align="center">
  <img src="https://d1898qjf7hzy9p.cloudfront.net/icons/FFLogo-WhiteBorder.svg" alt="FalconFeeds Logo" width="200" height="auto">
  
  # FalconFeeds MCP Server
  
  [![npm version](https://badge.fury.io/js/@falconfeeds%2Fmcp.svg?icon=si%3Anpm)](https://badge.fury.io/js/@falconfeeds%2Fmcp)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
  
  **MCP server providing cybersecurity threat intelligence tools and resources**
  
  [Documentation](https://dash.falconfeeds.io/mcp/docs) • [API Reference](https://dash.falconfeeds.io/api/docs) • [Dashboard](https://dash.falconfeeds.io) • [Support](https://falconfeeds.io/contact)
</div>

---

Connect real-time cybersecurity threat intelligence to MCP clients through standardized tools and resources. Access comprehensive IOCs, CVEs, TTPs, and threat actor data from [FalconFeeds.io](https://falconfeeds.io) with seamless integration across Claude Desktop, VS Code, and other MCP-enabled applications.

## Features

- **CVE Intelligence**: Search and retrieve Common Vulnerabilities and Exposures data with detailed analysis
- **Threat Feeds**: Access real-time threat intelligence feeds from global sources  
- **Threat Actors**: Get detailed profiles of threat actors and cybercriminal groups
- **Threat Images**: Retrieve screenshots and visual evidence from threat feeds
- **IOC Management**: Handle Indicators of Compromise with enrichment capabilities
- **MCP Prompts**: Pre-built cybersecurity prompts optimized for threat analysis workflows

## Installation Options

### NPX Installation (Recommended)

Add the server to your MCP client configuration:

```json
{
  "mcpServers": {
    "falconfeeds": {
      "command": "npx",
      "args": [
        "-y",
        "@falconfeeds/mcp@latest"
      ],
      "env": {
        "FALCONFEEDS_API_KEY": "your_api_key_here",
        "FALCONFEEDS_TIMEOUT": "30000"
      }
    }
  }
}
```

### Local Development

Clone and build the repository for development or customization: 
```bash
git clone https://github.com/Technisanct/falconfeeds-mcp.git
cd falconfeeds-mcp
```
Install dependencies
```bash
npm install
```
Build the project
```bash
npm run build
```
Configure your MCP client:
```json
{
  "mcpServers": {
    "falconfeeds": {
      "command": "node",
      "args": [
        "/path/to/falconfeeds-mcp/dist/index.js"
      ],
      "env": {
        "FALCONFEEDS_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Getting Your API Key

1. Visit [FalconFeeds Dashboard](https://dash.falconfeeds.io)
2. Sign up or log in to your account
3. Navigate to **Settings**
4. Navigate to **API Access**
5. Generate your **API key**
6. Copy the key to your environment configuration

> [!NOTE]
> Make sure you have a valid plan and sufficient API credits

## Client Integration

## MCP Tools

### CVE Operations
- **`get_cve_by_id`**: Retrieve specific CVE details by identifier
- **`search_cves_by_keyword`**: Find CVEs matching specific terms
- **`get_cves_by_date_range`**: Get CVEs within specified time periods
- **`get_next_cve_page`**: Paginate through large CVE result sets

### Threat Feed Operations  
- **`get_threat_feed_by_id`**: Get specific threat feed by UUID
- **`get_threat_feeds_by_actor`**: Find feeds associated with threat actors
- **`get_threat_feeds_by_category`**: Filter feeds by threat categories
- **`search_threat_feeds_by_keyword`**: Search feeds using keywords
- **`get_threat_feeds_by_organization`**: Get feeds targeting specific organizations
- **`get_threat_feeds_by_domain`**: Get feeds targeting specific websites or domains
- **`get_next_threat_feed_page`**: Navigate through paginated results

### Threat Actor Operations
- **`get_threat_actor_profile`**: Get comprehensive threat actor profile with associated feeds
- **`search_threat_actors`**: Search and filter threat actor profiles
- **`get_threat_actor_by_id`**: Get detailed threat actor information
- **`search_threat_actors_by_name`**: Find actors by name or alias
- **`get_next_threat_actor_page`**: Paginate actor search results

### IOC Operations
- **`search_iocs`**: Search and analyze Indicators of Compromise
- **`get_ioc_by_id`**: Retrieve specific IOC details
- **`search_iocs_by_type`**: Filter IOCs by type (IP, domain, hash, etc.)
- **`get_next_ioc_page`**: Navigate IOC result pagination

### Threat Image Operations
- **`get_threat_image_as_base64`**: Get images in base64 encoding

## MCP Prompts

The server provides cybersecurity-focused prompts designed for threat intelligence workflows:

1. **Threat Intelligence Report**: Generate comprehensive threat reports
2. **CVE Impact Assessment**: Analyze vulnerability impact and prioritization  
3. **Incident Threat Correlation**: Correlate security incidents with known threats
4. **Vulnerability Trend Analysis**: Identify patterns in vulnerability disclosure
5. **Threat Hunting Playbook**: Create systematic threat hunting procedures
6. **Supply Chain Threat Analysis**: Analyze third-party and supply chain risks
7. **IOC Enrichment Analysis**: Enhance indicators with threat context
8. **Sector Threat Briefing**: Generate industry-specific threat briefings
9. **Malware Family Analysis**: Deep-dive into malware characteristics
10. **Geopolitical Threat Assessment**: Analyze nation-state and political threats

## Testing & Development

### Testing with MCP Inspector

Test server tools and prompts using the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector npx -y @falconfeeds/mcp@latest
```
### Usage Examples

**Threat Intelligence Query:**
```
"Search for recent CVEs affecting Apache products with CVSS score above 7.0"
```

**Threat Actor Investigation:**
```
"Get information about APT29 and their recent campaigns targeting government sectors"
```

**IOC Analysis:**
```
"Analyze this IP address for malicious activity: 192.168.1.100"
```

## Troubleshooting

### Common Issues

**API Key Not Working:**
- Verify your API key is correctly copied from the FalconFeeds dashboard
- Ensure the key has not expired or been revoked
- Check that the key is properly set in your environment configuration
- Ensure you have enough credits

**NPX Installation Issues:**
- Ensure you have Node.js 18.0.0 or higher installed
- Try clearing npm cache: `npm cache clean --force`
- Use the `-y` flag to auto-accept package installations

**MCP Client Connection Issues:**
- Restart your MCP client after server configuration changes
- Verify JSON configuration syntax is valid
- Check client logs for connection errors
- Ensure the server process starts correctly

### Getting Help

- **Documentation**: [https://dash.falconfeeds.io/mcp/docs](https://dash.falconfeeds.io/mcp/docs)
- **Falconfeeds API Documentation**: [https://dash.falconfeeds.io/api/docs](https://dash.falconfeeds.io/api/docs)
- **Bug Reports**: Create an issue on GitHub with detailed error information
- **Community Support**: Join our community discussions for help and tips
- **Enterprise Support**: Contact FalconFeeds support for enterprise assistance

## Contributing

We welcome contributions from the cybersecurity and development communities!

### Development Guidelines

- Follow existing code patterns and architecture
- Update documentation for any tools, prompt changes
- Ensure TypeScript strict mode compliance



## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with the [Model Context Protocol](https://modelcontextprotocol.io)
- Powered by [FalconFeeds.io](https://falconfeeds.io) threat intelligence platform
- TypeScript and Node.js ecosystem contributors
- Cybersecurity community for feedback and feature requests

---