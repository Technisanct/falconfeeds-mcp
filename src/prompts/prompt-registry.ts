import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export interface PromptConfig {
  name: string;
  description: string;
  arguments: Array<{
    name: string;
    description: string;
    required: boolean;
  }>;
  template: string;
}

export const CYBERSECURITY_PROMPTS: PromptConfig[] = [
  {
    name: "Threat Intelligence Report",
    description: "Generate a comprehensive threat intelligence report for a specific threat actor or campaign",
    arguments: [
      {
        name: "Threat Actor",
        description: "Name of the threat actor or group",
        required: true
      },
      {
        name: "Time Period",
        description: "Time period for analysis (e.g., 'last 30 days', 'Q1 2024')",
        required: false
      }
    ],
    template: `Generate a comprehensive threat intelligence report for {{Threat Actor}}{{#Time Period}} covering {{Time Period}}{{/Time Period}}.
      Include the following sections:
      1. Executive Summary
      2. Actor Profile and Attribution
      3. Tactics, Techniques, and Procedures (TTPs)
      4. Infrastructure Analysis
      5. Target Analysis
      6. Recent Activity Summary
      7. Indicators of Compromise (IOCs)
      8. Defensive Recommendations
      9. Risk Assessment
    
    IMPORTANT: Use the get_threat_actor_profile tool first to get comprehensive actor information and attributed threat feeds. This ensures accurate attribution and the most relevant intelligence. Supplement with additional CVE and threat feed searches as needed. Provide actionable intelligence for SOC teams and threat hunters.`
  },
  {
    name: "CVE Impact Assessment",
    description: "Assess the impact and urgency of CVEs for organizational risk management",
    arguments: [
      {
        name: "CVE ID",
        description: "CVE identifier (e.g., CVE-2024-1234)",
        required: true
      },
      {
        name: "Industry",
        description: "Industry sector (e.g., 'Financial Services', 'Healthcare', 'Government')",
        required: false
      }
    ],
    template: `Conduct a detailed impact assessment for {{CVE ID}}{{#Industry}} in the context of {{Industry}} organizations{{/Industry}}.
    Analyze:
      1. Vulnerability Details and Technical Impact
      2. CVSS Score Breakdown and Risk Rating
      3. Affected Products and Versions
      4. Exploitation Likelihood and Threat Landscape
      5. Business Impact Assessment
      6. Patch Availability and Mitigation Strategies
      7. Detection and Monitoring Recommendations
      8. Priority Level and Response Timeline
    Use FalconFeeds data to identify any active exploitation or threat actor interest in this vulnerability.`
  },
  {
    name: "Incident Threat Correlation",
    description: "Correlate security incidents with known threat actors and campaigns",
    arguments: [
      {
        name: "Indicators",
        description: "Comma-separated list of IOCs (IPs, domains, hashes, etc.)",
        required: true
      },
      {
        name: "Incident Type",
        description: "Type of security incident (e.g., 'ransomware', 'data breach', 'malware')",
        required: true
      }
    ],
    template: `Analyze and correlate the following indicators with known threat actors and campaigns:
      Indicators: {{Indicators}}
      Incident Type: {{Incident Type}}

      Provide analysis on:
      1. Threat Actor Attribution (high/medium/low confidence)
      2. Campaign Association and Timeline
      3. Similar Historical Incidents
      4. TTPs and Infrastructure Overlap
      5. Victimology Patterns
      6. Recommended Investigation Steps
      7. Additional IOCs to Hunt For
      8. Defensive Countermeasures
    Cross-reference with FalconFeeds threat intelligence to identify matching patterns and actor behaviors.`
  },
  {
    name: "Vulnerability Trend Analysis",
    description: "Analyze vulnerability trends and emerging threats in specific technology stacks",
    arguments: [
      {
        name: "Technology Stack",
        description: "Technology or vendor to analyze (e.g., 'Microsoft', 'Apache', 'VMware')",
        required: true
      },
      {
        name: "Time Range (Days)",
        description: "Number of days to look back (default: 90)",
        required: false
      }
    ],
    template: `Analyze vulnerability trends for {{Technology Stack}} over the past {{Time Range (Days)}}{{^Time Range (Days)}}90{{/Time Range (Days)}} days.
    Generate insights on:
    1. Vulnerability Volume and Severity Trends
    2. Most Critical CVEs and Exploitation Risk
    3. Common Vulnerability Types and Root Causes
    4. Patch Management Challenges
    5. Active Threat Actor Interest
    6. Zero-Day and N-Day Exploitation Patterns
    7. Defensive Recommendations
    8. Priority Patching Strategy
  Use FalconFeeds CVE data to identify patterns and correlate with threat actor activity.`
  },
  {
    name: "Threat Hunting Playbook",
    description: "Create threat hunting procedures for specific threat categories",
    arguments: [
      {
        name: "Threat Category",
        description: "Category of threat to hunt for (e.g., 'Ransomware', 'APT', 'Insider Threat')",
        required: true
      },
      {
        name: "Environment Type",
        description: "IT environment type (e.g., 'Windows AD', 'Cloud', 'OT/ICS')",
        required: false
      }
    ],
    template: `Develop a comprehensive threat hunting playbook for {{Threat Category}}{{#Environment Type}} in {{Environment Type}} environments{{/Environment Type}}.
    Include:
    1. Threat Overview and Context
    2. Common Attack Vectors and TTPs
    3. Key Indicators and Behavioral Patterns
    4. Hunting Hypotheses and Objectives
    5. Data Sources and Collection Requirements
    6. Hunting Queries and Detection Logic
    7. Analysis Techniques and Tools
    8. Response and Escalation Procedures
    9. Lessons Learned and Playbook Updates
  Incorporate recent FalconFeeds intelligence on {{Threat Category}} activities and actor behaviors.`
  },
  {
    name: "Supply Chain Threat Analysis",
    description: "Analyze supply chain threats and vendor risk assessments",
    arguments: [
      {
        name: "Vendor Name",
        description: "Vendor or software supplier name",
        required: true
      },
      {
        name: "Assessment Scope",
        description: "Scope of assessment (e.g., 'software products', 'infrastructure', 'services')",
        required: false
      }
    ],
    template: `Conduct a supply chain threat analysis for {{Vendor Name}}{{#Assessment Scope}} focusing on {{Assessment Scope}}{{/Assessment Scope}}.

Evaluate:
1. Vendor Security Posture and History
2. Known Vulnerabilities and Exposures
3. Threat Actor Targeting and Interest
4. Supply Chain Attack Vectors
5. Third-Party Risk Dependencies
6. Security Incident History
7. Compliance and Certification Status
8. Risk Mitigation Recommendations
9. Monitoring and Assessment Strategy

Leverage FalconFeeds data to identify any targeting of the vendor or related supply chain incidents.`
  },
  {
    name: "IOC Enrichment Analysis",
    description: "Enrich and analyze indicators of compromise for threat intelligence",
    arguments: [
      {
        name: "IOC Value",
        description: "Indicator value (IP, domain, hash, email, etc.)",
        required: true
      },
      {
        name: "IOC Type",
        description: "Type of indicator (ip, domain, hash, email, etc.)",
        required: true
      }
    ],
    template: `Perform comprehensive enrichment analysis for the indicator: {{IOC Value}} ({{IOC Type}})

Provide detailed analysis including:
1. Indicator Classification and Confidence Level
2. Threat Actor Attribution and Campaigns
3. Malware Family and Variant Analysis
4. Infrastructure Relationships and Pivots
5. Temporal Analysis and Activity Timeline
6. Victimology and Targeting Patterns
7. Detection Coverage and Gaps
8. Recommended Actions and IOCs to Monitor

Cross-reference with FalconFeeds threat intelligence to identify related activities and context.`
  },
  {
    name: "Sector Threat Briefing",
    description: "Generate sector-specific threat briefings for industry verticals",
    arguments: [
      {
        name: "Industry Sector",
        description: "Industry sector (e.g., 'healthcare', 'financial', 'government', 'energy')",
        required: true
      },
      {
        name: "Geographic Region",
        description: "Geographic focus (e.g., 'North America', 'EMEA', 'APAC')",
        required: false
      }
    ],
    template: `Generate a comprehensive threat briefing for the {{Industry Sector}} sector{{#Geographic Region}} in {{Geographic Region}}{{/Geographic Region}}.

Cover:
1. Current Threat Landscape Overview
2. Sector-Specific Targeting Trends
3. Major Threat Actors and Their Motivations
4. Common Attack Vectors and TTPs
5. Recent High-Impact Incidents
6. Regulatory and Compliance Implications
7. Industry-Specific Vulnerabilities
8. Defensive Best Practices
9. Threat Intelligence Recommendations

Utilize FalconFeeds data to provide current intelligence on threats targeting this sector.`
  },
  {
    name: "Malware Family Analysis",
    description: "Analyze malware families and their evolution patterns",
    arguments: [
      {
        name: "Malware Family",
        description: "Malware family name (e.g., 'Emotet', 'Ryuk', 'Cobalt Strike')",
        required: true
      },
      {
        name: "Analysis Depth",
        description: "Depth of analysis (basic, detailed, comprehensive)",
        required: false
      }
    ],
    template: `Conduct {{Analysis Depth}}{{^Analysis Depth}}detailed{{/Analysis Depth}} analysis of the {{Malware Family}} malware family.

Research and analyze:
1. Malware Family Overview and History
2. Technical Capabilities and Features
3. Infection and Propagation Methods
4. Command and Control Infrastructure
5. Payload and Post-Exploitation Activities
6. Evasion and Persistence Techniques
7. Attribution and Actor Usage Patterns
8. Variant Evolution and Updates
9. Detection and Mitigation Strategies
10. Related Families and Tool Overlap

Use FalconFeeds intelligence to identify recent campaigns and actor usage of this malware family.`
  },
  {
    name: "Geopolitical Threat Assessment",
    description: "Assess cyber threats in the context of geopolitical events and tensions",
    arguments: [
      {
        name: "Geopolitical Event",
        description: "Specific geopolitical event or tension area",
        required: true
      },
      {
        name: "Threat Actors",
        description: "Comma-separated list of relevant threat actors or nation-states",
        required: false
      }
    ],
    template: `Analyze cyber threat implications of: {{Geopolitical Event}}

Assess:
1. Geopolitical Context and Stakeholders
2. Cyber Threat Actor Motivations and Capabilities
3. Historical Precedents and Patterns
4. Likely Targets and Attack Scenarios
5. Threat Actor Collaboration and Proxy Activities
6. Information Operations and Influence Campaigns
7. Critical Infrastructure Risks
8. Economic and Supply Chain Implications
9. Defensive Posture Recommendations
10. Monitoring and Intelligence Requirements

{{#Threat Actors}}Focus analysis on: {{Threat Actors}}{{/Threat Actors}}

Correlate with current FalconFeeds intelligence on relevant threat actor activities and geopolitical cyber operations.`
  }
];

export function registerCybersecurityPrompts(server: McpServer): void {
  CYBERSECURITY_PROMPTS.forEach(prompt => {
    const schemaFields: Record<string, z.ZodString | z.ZodOptional<z.ZodString>> = {};
    
    prompt.arguments.forEach(arg => {
      schemaFields[arg.name] = arg.required 
        ? z.string().describe(arg.description)
        : z.string().optional().describe(arg.description);
    });

    const argsSchema = schemaFields;

    server.registerPrompt(
      prompt.name,
      {
        description: prompt.description,
        argsSchema
      },
      (args) => {
        let processedTemplate = prompt.template;
        
        // Simple Mustache-like template processing
        Object.entries(args).forEach(([key, value]) => {
          if (value) {
            // Replace {{#key}}...{{/key}} blocks
            const conditionalRegex = new RegExp(`{{#${key}}}(.*?){{/${key}}}`, 'gs');
            processedTemplate = processedTemplate.replace(conditionalRegex, '$1');
            
            // Replace {{key}} placeholders
            const placeholderRegex = new RegExp(`{{${key}}}`, 'g');
            processedTemplate = processedTemplate.replace(placeholderRegex, String(value));
          } else {
            // Remove conditional blocks for missing values
            const conditionalRegex = new RegExp(`{{#${key}}}(.*?){{/${key}}}`, 'gs');
            processedTemplate = processedTemplate.replace(conditionalRegex, '');
          }
        });
        
        // Handle {{^key}}...{{/key}} (inverted conditionals)
        Object.entries(args).forEach(([key, value]) => {
          if (!value) {
            const invertedRegex = new RegExp(`{{\\^${key}}}(.*?){{/${key}}}`, 'gs');
            processedTemplate = processedTemplate.replace(invertedRegex, '$1');
          } else {
            const invertedRegex = new RegExp(`{{\\^${key}}}(.*?){{/${key}}}`, 'gs');
            processedTemplate = processedTemplate.replace(invertedRegex, '');
          }
        });

        return {
          messages: [
            {
              role: "user" as const,
              content: {
                type: "text" as const,
                text: processedTemplate
              }
            }
          ]
        };
      }
    );
  });
} 