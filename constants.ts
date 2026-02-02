export const PROJECT_STAGES = [
  'Initiation',
  'Planning',
  'Execution',
  'Monitoring & Control',
  'Closure'
];

export const FRAMEWORKS = [
  'PRINCE2',
  'PMBOK',
  'Agile/Scrum',
  'MSP (Managing Successful Programmes)',
  'P3M3',
  'SAFe',
  'Custom Framework'
];

export const DOCUMENT_CATEGORIES = [
  'Business Case',
  'Project Charter',
  'Requirement',
  'Architecture',
  'Design',
  'Budget',
  'Plan',
  'Risk Register',
  'Status Report',
  'Stakeholder Register',
  'Quality Plan',
  'Communication Plan',
  'Change Log',
  'Issue Log',
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
