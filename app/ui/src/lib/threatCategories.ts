// SPDX-License-Identifier: Apache-2.0
// threatCategories.ts — the names of the threat categories a classifier puts
// on recorded events. These are labels for triage, not settings: what gets
// refused is decided by the controls on the Policy screen.

export const THREAT_CATEGORY_LABELS: Record<string, string> = {
  credential_access: 'Credential access',
  data_exfiltration: 'Data exfiltration',
  privilege_escalation: 'Privilege escalation',
  prompt_injection: 'Prompt injection',
  supply_chain: 'Supply chain',
  excessive_agency: 'Excessive agency',
  output_handling: 'Output handling',
  memory_poisoning: 'Memory poisoning',
  tool_misuse: 'Tool misuse',
  rogue_agent: 'Rogue agent',
  system_prompt_leakage: 'System prompt leakage',
  mcp_tool_poisoning: 'MCP tool poisoning',
  harmful_content: 'Harmful content',
};

export const threatCategoryLabel = (id: string) =>
  THREAT_CATEGORY_LABELS[id] ?? id.replace(/_/g, ' ');
