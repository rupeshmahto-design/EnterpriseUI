export interface ProjectDocument {
  id: string;
  name: string;
  type: string;
  size: string;
  content: string;
  category: string;
}

export interface AssuranceReport {
  overallScore: number;
  summary: string;
  gapAnalysis: GapAnalysisItem[];
  benefitsRealisation: BenefitItem[];
  benefitsSummary?: BenefitsSummary;
  frameworkAlignment: FrameworkAlignment;
  financialAssurance: FinancialAssurance;
  riskAnalysis: RiskAnalysisItem[];
  governanceCompliance: GovernanceItem[];
  recommendations: string[];
  timelineHealth: TimelineHealth;
  resourceHealth: ResourceHealth;
  stakeholderAssurance: StakeholderItem[];
}

export interface GapAnalysisItem {
  area: string;
  gap: string;
  severity: 'Low' | 'Medium' | 'High';
  recommendation: string;
  documentReference?: string;
}

export interface BenefitItem {
  name: string;
  category: string;
  expectedValue: string;
  readinessScore: number;
  risks: string[];
  mitigation: string;
}

export interface BenefitsSummary {
  totalPlannedValue: string;
  projectedAnnualValue: string;
  benefitsCount: number;
  realizationOutlook: string;
}

export interface FrameworkAlignment {
  framework: string;
  alignmentScore: number;
  strengths: string[];
  gaps: string[];
}

export interface FinancialAssurance {
  budgetStatus: string;
  riskScore: number;
  findings: string[];
  recommendations: string[];
}

export interface RiskAnalysisItem {
  risk: string;
  impact: string;
  likelihood: string;
  mitigation: string;
  owner?: string;
}

export interface GovernanceItem {
  area: string;
  status: 'Compliant' | 'Partial' | 'Non-Compliant';
  findings: string[];
  actions: string[];
}

export interface TimelineHealth {
  status: string;
  keyDates: Array<{
    milestone: string;
    date: string;
    confidence: string;
  }>;
  delays: string[];
}

export interface ResourceHealth {
  adequacy: string;
  concerns: string[];
  recommendations: string[];
}

export interface StakeholderItem {
  stakeholder: string;
  engagementLevel: string;
  concerns: string[];
  actions: string[];
}

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface SavedReport {
  id: number;
  project_name: string;
  project_number: string;
  project_stage: string;
  overall_score: number;
  created_at: string;
  user_id: number;
}
