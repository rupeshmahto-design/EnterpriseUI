export const PROJECT_STAGES = [
  'Planning',
  'Development',
  'Testing',
  'Production',
  'Maintenance'
];

export const FRAMEWORKS = [
  'MITRE ATT&CK',
  'STRIDE',
  'PASTA',
  'OCTAVE',
  'VAST',
  'Custom Client Framework'
];

export const BUSINESS_CRITICALITY = [
  'Critical',
  'High',
  'Medium',
  'Low'
];

export const APPLICATION_TYPES = [
  'Web Application',
  'Mobile Application',
  'Desktop Application',
  'API/Microservices',
  'AI/ML Project',
  'Cloud Infrastructure',
  'IoT Device',
  'Database System',
  'Other'
];

export const DEPLOYMENT_MODELS = [
  'Cloud (AWS)',
  'Cloud (Azure)',
  'Cloud (GCP)',
  'On-Premises',
  'Hybrid',
  'Multi-Cloud'
];

export const ENVIRONMENTS = [
  'Production',
  'Staging',
  'Development',
  'Testing',
  'DR/Backup'
];

export const RISK_FOCUS_AREAS = [
  'Agentic AI Risk',
  'Model Risk',
  'Data Security Risk',
  'Infrastructure Risk',
  'Compliance Risk',
  'Privacy Risk',
  'Supply Chain Risk',
  'Identity & Access Risk'
];

export const COMPLIANCE_REQUIREMENTS = [
  'SOC 2',
  'ISO 27001',
  'GDPR',
  'HIPAA',
  'PCI DSS',
  'NIST',
  'CIS Controls',
  'CCPA',
  'None'
];

export const DOCUMENT_CATEGORIES = [
  'Architecture Diagram',
  'Data Flow Diagram',
  'System Design',
  'API Documentation',
  'Security Requirements',
  'Compliance Documentation',
  'Risk Assessment',
  'Incident Response Plan',
  'Other'
];

export const SEVERITY_LEVELS = {
  High: 'bg-red-100 text-red-800 border-red-300',
  Medium: 'bg-amber-100 text-amber-800 border-amber-300',
  Low: 'bg-green-100 text-green-800 border-green-300'
};

export const GOVERNANCE_STATUS = {
  Compliant: 'text-green-600',
  Partial: 'text-amber-600',
  'Non-Compliant': 'text-red-600'
};

export const USER_ROLES = [
  'user',
  'admin'
];

export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
