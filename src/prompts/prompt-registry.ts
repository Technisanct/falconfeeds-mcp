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
    name: "Cyber Security Threat Intelligence Report",
    description: "Generate a comprehensive threat intelligence report for a threat actor, country, industry, or organization",
    arguments: [
      {
        name: "Target",
        description: "Name of the threat actor, country, industry, or organization to analyze",
        required: true
      },
      {
        name: "Time Period",
        description: "Time period for analysis (e.g., 'last 30 days', 'Q1 2024')",
        required: false
      }
    ],
    template: `Generate a comprehensive threat intelligence report for {{Target}}{{#Time Period}} covering {{Time Period}}{{/Time Period}}.
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
    name: "Ransomware Analysis",
    description: "Analyze Ransomware activity and patterns",
    arguments: [
      {
        name: "Ransomware Name",
        description: "Name of the ransomware to analyze (e.g., 'Ransomware', 'Data Breach', 'Malware', 'Phishing')",
        required: true
      },
      {
        name: "Time Frame",
        description: "Analysis time frame (e.g., 'last 30 days', 'Q1 2024')",
        required: false
      }
    ],
    template: `Analyze threat activity patterns for {{Ransomware Name}}{{#Time Frame}} over {{Time Frame}}{{/Time Frame}}.
    Include:
    1. Ransomware Overview and Current Landscape
    2. Most Active Threat Actors in this Category
    3. Common Attack Vectors and Methods
    4. Target Industry and Geographic Analysis
    5. Recent Campaign Highlights
    6. Victim Impact Assessment
    7. Detection and Prevention Strategies
    8. Threat Intelligence Recommendations
  Use FalconFeeds threat feed data filtered by {{Threat Category}} category to provide current intelligence.`
  },
  {
    name: "Industry-Specific Threat Assessment",
    description: "Generate industry-specific threat briefings for industry verticals",
    arguments: [
      {
        name: "Industry",
        description: "Industry sector (e.g., 'Healthcare', 'Financial Services', 'Government', 'Energy')",
        required: true
      },
      {
        name: "Geographic Region",
        description: "Geographic focus (e.g., 'United States', 'United Kingdom', 'Germany')",
        required: false
      }
    ],
    template: `Generate a comprehensive threat briefing for the {{Industry}} sector{{#Geographic Region}} in {{Geographic Region}}{{/Geographic Region}}.

Cover:
1. Current Threat Landscape Overview
2. Sector-Specific Targeting Trends
3. Major Threat Actors and Their Motivations
4. Common Attack Categories and Methods
5. Recent High-Impact Incidents
6. Industry-Specific Vulnerabilities
7. Regional Threat Patterns
8. Defensive Best Practices
9. Threat Intelligence Recommendations

Utilize FalconFeeds threat feed data filtered by industry and geographic targeting to provide current intelligence.`
  },
  {
    name: "Threat Actor Comparison",
    description: "Perform detailed cyber threat intelligence analysis comparing multiple threat actors' TTPs, infrastructure, and operational patterns to identify overlaps and distinctions in their methodologies",
    arguments: [
      {
        name: "Threat Actors",
        description: "Comma-separated list of threat actor names to compare",
        required: true
      },
      {
        name: "Analysis Focus",
        description: "Specific aspect to focus on (e.g., 'TTPs', 'targeting', 'infrastructure')",
        required: false
      }
    ],
    template: `Conduct a comparative analysis of the following threat actors: {{Threat Actors}}{{#Analysis Focus}} with focus on {{Analysis Focus}}{{/Analysis Focus}}.

Analyze and compare:
1. Actor Profiles and Attribution
2. Operational Capabilities and Sophistication
3. Targeting Preferences and Victim Selection
4. Attack Methods and Techniques
5. Infrastructure and Tools Usage
6. Activity Timelines and Patterns
7. Potential Relationships or Collaborations
8. Threat Level Assessment
9. Detection and Mitigation Strategies

Use get_threat_actor_profile for each actor to gather comprehensive intelligence and compare their attributed activities from FalconFeeds.`
  },
  {
    name: "Geopolitical Threat Landscape Assessment",
    description: "Conduct comprehensive country-specific cyber threat landscape analysis for strategic threat intelligence and national security assessment",
    arguments: [
      {
        name: "Country",
        description: "Target country for threat landscape analysis (e.g., 'United States', 'Germany', 'Japan')",
        required: true
      },
      {
        name: "Assessment Period",
        description: "Temporal scope for analysis (e.g., 'Q4 2024', 'last 6 months', 'YTD 2024')",
        required: false
      },
      {
        name: "Focus Area",
        description: "Specific focus area for deeper analysis (e.g., 'critical infrastructure', 'financial sector', 'government entities')",
        required: false
      }
    ],
    template: `Conduct a comprehensive geopolitical cyber threat landscape assessment for {{Country}}{{#Assessment Period}} covering {{Assessment Period}}{{/Assessment Period}}{{#Focus Area}} with emphasis on {{Focus Area}}{{/Focus Area}}.

METHODOLOGY: Utilize FalconFeeds country-specific threat intelligence to provide evidence-based analysis. Cross-reference threat actor activities, attack patterns, and victim targeting data.

EXECUTIVE SUMMARY:
Provide a concise overview of the current threat landscape and key findings.

DETAILED ANALYSIS SECTIONS:

1. **Threat Actor Ecosystem**
   - State-sponsored Advanced Persistent Threats (APTs) targeting {{Country}}
   - Cybercriminal organizations operating against {{Country}} entities
   - Hacktivist groups and their motivations
   - Attribution confidence levels and intelligence gaps

2. **Attack Vector Analysis**
   - Primary attack methodologies observed
   - Sector-specific targeting patterns
   - Infrastructure compromise trends
   - Supply chain attack incidents

3. **Critical Infrastructure Threat Assessment**
   - Energy sector targeting and vulnerabilities
   - Financial services threat exposure
   - Healthcare and government entity risks
   - Telecommunications and technology sector threats

4. **Victim Impact Metrics**
   - Quantitative analysis of confirmed breaches
   - Economic impact assessment where available
   - Data exfiltration patterns and types
   - Service disruption incidents

5. **Threat Intelligence Gaps**
   - Areas requiring enhanced collection
   - Attribution challenges and uncertainties
   - Emerging threat vectors requiring monitoring

6. **Strategic Recommendations**
   - National cybersecurity posture improvements
   - Sector-specific defensive priorities
   - International cooperation opportunities
   - Threat hunting focus areas

7. **Indicators and Warning Signs**
   - Key indicators of compromise (IOCs)
   - Behavioral patterns for detection
   - Early warning signals for emerging threats

INTELLIGENCE SOURCES: Leverage get_threat_feeds_by_country tool for {{Country}}-specific threat intelligence. Supplement with threat actor profiling and cross-border attack pattern analysis from FalconFeeds database.

CLASSIFICATION: Provide appropriate handling and distribution guidance for the intelligence contained within this assessment.`
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