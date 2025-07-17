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
  },
  {
    name: "Darkweb Threat Intelligence Analysis",
    description: "Analyze darkweb activities, marketplaces, and threat intelligence for comprehensive underground cyber threat assessment",
    arguments: [
      {
        name: "Target Entity",
        description: "Organization, industry, or threat actor to investigate for darkweb presence (e.g., 'Financial Services', 'Healthcare', 'LockBit')",
        required: true
      },
      {
        name: "Analysis Type",
        description: "Type of darkweb analysis (e.g., 'data breach', 'credentials', 'malware', 'services')",
        required: false
      },
      {
        name: "Time Frame",
        description: "Analysis time period (e.g., 'last 30 days', 'Q4 2024', 'YTD 2024')",
        required: false
      }
    ],
    template: `Conduct comprehensive darkweb threat intelligence analysis for {{Target Entity}}{{#Analysis Type}} focusing on {{Analysis Type}} activities{{/Analysis Type}}{{#Time Frame}} covering {{Time Frame}}{{/Time Frame}}.

METHODOLOGY: Utilize FalconFeeds threat intelligence to analyze underground activities, data breaches, and darkweb marketplace intelligence. Focus on actionable intelligence for threat hunting and incident response teams.

EXECUTIVE SUMMARY:
Provide overview of darkweb threat landscape and key findings relevant to {{Target Entity}}.

DETAILED ANALYSIS SECTIONS:

1. **Darkweb Marketplace Intelligence**
   - Active marketplaces offering services or data related to {{Target Entity}}
   - Pricing and availability of stolen credentials or data
   - Vendor reputation and reliability analysis
   - Payment methods and transaction patterns

2. **Data Breach and Leak Analysis**
   - Confirmed data breaches involving {{Target Entity}} on darkweb forums
   - Types of compromised data available (credentials, PII, financial data)
   - Data freshness and verification status
   - Distribution channels and accessibility

3. **Threat Actor Underground Activities**
   - Known threat actors targeting {{Target Entity}} sector
   - Underground forum discussions and planning activities
   - Recruitment and collaboration patterns
   - Tools and services being advertised

4. **Credential and Identity Intelligence**
   - Compromised employee credentials availability
   - Corporate email domain presence in breach databases
   - Password patterns and security implications
   - Multi-factor authentication bypass services

5. **Cybercriminal Services and Tools**
   - Ransomware-as-a-Service (RaaS) targeting {{Target Entity}} sector
   - Custom malware development services
   - Access broker services and initial access offerings
   - Cryptocurrency laundering and payment services

6. **Threat Indicators and IOCs**
   - IP addresses and domains associated with darkweb activities
   - Bitcoin addresses and cryptocurrency wallets
   - Communication channels and contact methods
   - Infrastructure patterns and hosting providers

7. **Risk Assessment and Impact Analysis**
   - Immediate threats requiring urgent attention
   - Potential financial and reputational impact
   - Compliance and regulatory implications
   - Supply chain and third-party risks

8. **Defensive Recommendations**
   - Employee awareness and training priorities
   - Technical controls and monitoring enhancements
   - Incident response preparation guidelines
   - Threat hunting focus areas and IOCs for monitoring

INTELLIGENCE SOURCES: Leverage search_threat_feeds_with_images for visual evidence, get_threat_feeds_by_category for 'Data Breach' and 'Data Leak' categories, and get_threat_actor_profile for attribution analysis. Cross-reference with IOC data for infrastructure intelligence.

OPERATIONAL SECURITY: Ensure proper handling of sensitive intelligence and maintain appropriate classification levels for darkweb-derived information.`
  },
  {
    name: "Deep Web Telegram Channel Intelligence Analysis", 
    description: "Analyze Telegram channels and deep web communications for threat intelligence, data leaks, and cybercriminal activities",
    arguments: [
      {
        name: "Target Focus",
        description: "Primary focus for Telegram intelligence (e.g., 'ransomware groups', 'data leak channels', 'specific threat actor', 'industry sector')",
        required: true
      },
      {
        name: "Geographic Region",
        description: "Geographic focus area (e.g., 'Global', 'North America', 'Europe', 'Asia-Pacific')",
        required: false
      },
      {
        name: "Threat Category",
        description: "Specific threat category to focus on (e.g., 'Ransomware', 'Data Breach', 'Malware', 'Phishing')",
        required: false
      }
    ],
    template: `Conduct comprehensive Telegram channel and deep web communication analysis for {{Target Focus}}{{#Geographic Region}} in {{Geographic Region}}{{/Geographic Region}}{{#Threat Category}} focusing on {{Threat Category}} activities{{/Threat Category}}.

METHODOLOGY: Utilize FalconFeeds threat intelligence to analyze Telegram-based communications, announcements, and deep web activities. Focus on real-time threat intelligence and early warning indicators.

EXECUTIVE SUMMARY:
Provide overview of Telegram-based threat landscape and key intelligence findings for {{Target Focus}}.

DETAILED INTELLIGENCE ANALYSIS:

1. **Telegram Channel Ecosystem Mapping**
   - Active channels related to {{Target Focus}}
   - Channel membership statistics and growth patterns
   - Administrative hierarchies and key figures
   - Cross-channel relationships and collaborations

2. **Communication Pattern Analysis**
   - Message frequency and timing patterns
   - Communication languages and geographic indicators
   - Content types and media sharing patterns
   - Encryption and operational security practices

3. **Threat Actor Communications**
   - Leadership announcements and strategic communications
   - Recruitment and affiliate management activities
   - Technical discussions and tool sharing
   - Payment and financial coordination messages

4. **Data Leak and Breach Announcements**
   - Recent data leak announcements and victim claims
   - Proof-of-compromise evidence and screenshots
   - Data sale advertisements and pricing information
   - Victim notification and extortion communications

5. **Operational Intelligence**
   - Attack planning and coordination activities
   - Target selection and reconnaissance sharing
   - Tool distribution and technical support
   - Success metrics and impact reporting

6. **Technical Infrastructure Analysis**
   - Bot usage and automation patterns
   - File sharing and distribution methods
   - Payment system integration and cryptocurrency usage
   - Backup channels and contingency communications

7. **Geopolitical and Temporal Patterns**
   - Regional targeting preferences and motivations
   - Seasonal activity patterns and campaign timing
   - Response to law enforcement actions
   - Adaptation to platform restrictions and countermeasures

8. **Early Warning Indicators**
   - Pre-attack planning discussions
   - Target list sharing and reconnaissance activities
   - Tool testing and capability demonstrations
   - Escalation indicators and threat level changes

9. **Attribution and Network Analysis**
   - Identity patterns and persona management
   - Cross-platform presence and activity correlation
   - Financial relationships and profit-sharing arrangements
   - Technical fingerprints and operational patterns

10. **Countermeasure Effectiveness Assessment**
    - Response to disruption activities
    - Platform migration patterns
    - Operational security improvements
    - Resilience and adaptation capabilities

INTELLIGENCE COLLECTION STRATEGY: Utilize get_threat_actor_profile for known actors, search_threat_feeds_by_keyword for Telegram-related intelligence, and get_threat_feeds_by_category for relevant threat categories. Cross-reference with IOC data for infrastructure correlation.

ACTIONABLE INTELLIGENCE OUTPUTS:
- Priority threat actor identifiers and communication channels
- IOCs for network monitoring and threat hunting
- Early warning indicators for proactive defense
- Attribution confidence levels and intelligence gaps

OPERATIONAL CONSIDERATIONS: Maintain appropriate source protection and ensure compliance with platform terms of service and applicable regulations when utilizing Telegram-derived intelligence.`
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